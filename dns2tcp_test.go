package main

import (
	"bytes"
	"net"
	"testing"
)

func TestParseDNSMsgWithCompression(t *testing.T) {
	// DNS Message:
	// Header
	//   ID: 0x1234
	//   Flags: 0x8180 (Response, No error, AA=0, TC=0, RD=1, RA=1)
	//   QDCOUNT: 1
	//   ANCOUNT: 2
	//   NSCOUNT: 0
	//   ARCOUNT: 0
	// Question: test.example.com A IN
	// Answer 1: sub1.test.example.com A IN 192.0.2.1 (TTL 225)
	// Answer 2: sub2.test.example.com A IN 192.0.2.2 (TTL 225) (using compression for "test.example.com")

	dnsMessageBytes := []byte{
		// Header
		0x12, 0x34, // Transaction ID
		0x81, 0x80, // Flags: Response, Opcode: Query, AA:0, TC:0, RD:1, RA:1, RCODE: No error
		0x00, 0x01, // Questions: 1
		0x00, 0x02, // Answer RRs: 2
		0x00, 0x00, // Authority RRs: 0
		0x00, 0x00, // Additional RRs: 0

		// Question Section (test.example.com)
		0x04, 't', 'e', 's', 't',
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm',
		0x00,       // Null terminator for domain name
		0x00, 0x01, // QTYPE: A
		0x00, 0x01, // QCLASS: IN

		// Answer Section - RR 1 (sub1.test.example.com)
		// Name: sub1.test.example.com (offset 28)
		0x04, 's', 'u', 'b', '1',
		0x04, 't', 'e', 's', 't', // This is where "test.example.com" starts for RR1 (offset 33)
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm',
		0x00,       // Null terminator
		0x00, 0x01, // TYPE: A
		0x00, 0x01, // CLASS: IN
		0x00, 0x00, 0x00, 0xE1, // TTL: 225 seconds
		0x00, 0x04, // RDLENGTH: 4
		192, 0, 2, 1, // RDATA: 192.0.2.1

		// Answer Section - RR 2 (sub2.test.example.com, with "test.example.com" compressed)
		// Name: sub2 (points to "test.example.com" at offset 12)
		0x04, 's', 'u', 'b', '2',
		0xc0, 0x0c, // Pointer to offset 12 (start of "test.example.com" in Question section)
		0x00, 0x01, // TYPE: A
		0x00, 0x01, // CLASS: IN
		0x00, 0x00, 0x00, 0xE1, // TTL: 225 seconds
		0x00, 0x04, // RDLENGTH: 4
		192, 0, 2, 2, // RDATA: 192.0.2.2
	}

	msg, err := parseDNSMsg(dnsMessageBytes)
	if err != nil {
		t.Fatalf("parseDNSMsg returned an error: %v", err)
	}

	// Assertions for Header
	if msg.id != 0x1234 {
		t.Errorf("Expected ID 0x1234, got %x", msg.id)
	}
	if !msg.response {
		t.Errorf("Expected 'response' flag to be true")
	}
	if msg.opcode != 0 { // Standard query
		t.Errorf("Expected opcode 0 (standard query), got %d", msg.opcode)
	}
	if msg.recursion_available == false { // RA was set to 1 in flags
		t.Errorf("Expected recursion_available to be true, got false")
	}
	if msg.rcode != 0 { // No error
		t.Errorf("Expected rcode 0 (no error), got %d", msg.rcode)
	}
	if msg.question_num != 1 {
		t.Errorf("Expected question_num 1, got %d", msg.question_num)
	}
	if msg.answer_num != 2 {
		t.Errorf("Expected answer_num 2, got %d", msg.answer_num)
	}

	// Assertions for Question Section
	if len(msg.question) != 1 {
		t.Fatalf("Expected 1 question, got %d", len(msg.question))
	}
	expectedQuestionName := "test.example.com"
	if msg.question[0].Name != expectedQuestionName {
		t.Errorf("Expected question name '%s', got '%s'", expectedQuestionName, msg.question[0].Name)
	}
	if msg.question[0].Qtype != 1 { // A record
		t.Errorf("Expected question qtype 1 (A), got %d", msg.question[0].Qtype)
	}
	if msg.question[0].Qclass != 1 { // IN class
		t.Errorf("Expected question qclass 1 (IN), got %d", msg.question[0].Qclass)
	}

	// Assertions for Answer Section
	if len(msg.answer) != 2 {
		t.Fatalf("Expected 2 answers, got %d", len(msg.answer))
	}

	// Answer RR 1
	expectedAnswerName1 := "sub1.test.example.com"
	if msg.answer[0].Name != expectedAnswerName1 {
		t.Errorf("Answer 1: Expected name '%s', got '%s'", expectedAnswerName1, msg.answer[0].Name)
	}
	if msg.answer[0].Rrtype != 1 { // A record
		t.Errorf("Answer 1: Expected rtype 1 (A), got %d", msg.answer[0].Rrtype)
	}
	if msg.answer[0].Class != 1 { // IN class
		t.Errorf("Answer 1: Expected class 1 (IN), got %d", msg.answer[0].Class)
	}
	if msg.answer[0].Ttl != 225 {
		t.Errorf("Answer 1: Expected TTL 225, got %d", msg.answer[0].Ttl)
	}
	if msg.answer[0].Rdlength != 4 {
		t.Errorf("Answer 1: Expected rdlength 4, got %d", msg.answer[0].Rdlength)
	}
	expectedRdata1 := net.IPv4(192, 0, 2, 1).To4() // Use To4() to get the 4-byte representation
	if !bytes.Equal(msg.answer[0].Data, expectedRdata1) {
		t.Errorf("Answer 1: Expected rdata %v, got %v", expectedRdata1, msg.answer[0].Data)
	}

	// Answer RR 2 (Compressed)
	expectedAnswerName2 := "sub2.test.example.com"
	if msg.answer[1].Name != expectedAnswerName2 {
		t.Errorf("Answer 2: Expected name '%s' (compression), got '%s'", expectedAnswerName2, msg.answer[1].Name)
	}
	if msg.answer[1].Rrtype != 1 { // A record
		t.Errorf("Answer 2: Expected rtype 1 (A), got %d", msg.answer[1].Rrtype)
	}
	if msg.answer[1].Class != 1 { // IN class
		t.Errorf("Answer 2: Expected class 1 (IN), got %d", msg.answer[1].Class)
	}
	if msg.answer[1].Ttl != 225 {
		t.Errorf("Answer 2: Expected TTL 225, got %d", msg.answer[1].Ttl)
	}
	if msg.answer[1].Rdlength != 4 {
		t.Errorf("Answer 2: Expected rdlength 4, got %d", msg.answer[1].Rdlength)
	}
	expectedRdata2 := net.IPv4(192, 0, 2, 2).To4() // Use To4() to get the 4-byte representation
	if !bytes.Equal(msg.answer[1].Data, expectedRdata2) {
		t.Errorf("Answer 2: Expected rdata %v, got %v", expectedRdata2, msg.answer[1].Data)
	}
}
