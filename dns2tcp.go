package main

import (
	"bytes"
	"encoding/binary"
	"log"
	"net"
	"strings"
)

const DNSSERVER = "8.8.8.8:53"

type dnsMsgHdr struct {
	id                  uint16
	response            bool
	opcode              uint
	authoritative       bool
	truncated           bool
	recursion_desired   bool
	recursion_available bool
	rcode               uint
	question_num        uint16
	answer_num          uint16
	authority_num       uint16
	additional_num      uint16
}

type dnsQuestion struct {
	Name   string `net:"domain-name"` // `net:"domain-name"` specifies encoding; see packers below
	Qtype  uint16
	Qclass uint16
}

type dnsRR struct {
	Name     string `net:"domain-name"`
	Rrtype   uint16
	Class    uint16
	Ttl      uint32
	Rdlength uint16 // length of data after header
	Data     []byte
}

type dnsMsg struct {
	dnsMsgHdr
	question []dnsQuestion
	answer   []dnsRR
	ns       []dnsRR
	extra    []dnsRR
}

func Itob(x uint16) bool {
	if x == 0 {
		return false
	}
	return true
}

func getQueryName(buf *bytes.Buffer) string {
	over := false
	n := 0
	labels := make([]string, 63)
	log.Printf("input buf: %x", buf)
	for ; !over; n++ {
		labelsize, err := buf.ReadByte()
		// detect message compression and ignore it in this version.
		if labelsize == 0xc0 {
			log.Printf("message compression")
			var position uint8
			err = binary.Read(buf, binary.BigEndian, &position)
			if err != nil {
				log.Fatal(err)
			}
			// if size != 1 {
			// 	log.Print("Read postion error %d", size)
			// }
			return string(position)

		}
		if err != nil {
			log.Fatal(err)
		}
		if labelsize == 0 {
			over = true
			break
		}
		label := make([]byte, labelsize)
		size, err := buf.Read(label)
		if err != nil {
			log.Fatal(err)
		}
		if size != int(labelsize) {
			log.Printf("Error in read %d, bytes of %x", size, label)
			log.Fatal()
		}
		labels[n] = string(label)
		log.Print(label)
	}

	labels = labels[0:n]
	name := strings.Join(labels, ".")
	return name
}

func parseDNSMsg(buf *bytes.Buffer) dnsMsg {
	var msg dnsMsg
	err := binary.Read(buf, binary.BigEndian, &msg.id)
	if err != nil {
		log.Fatal(err)
	}
	var dnsmisc uint16
	err = binary.Read(buf, binary.BigEndian, &dnsmisc)
	msg.response = true
	msg.opcode = uint((dnsmisc >> 11) & 0x000F)
	msg.authoritative = Itob((dnsmisc & 0x0400) >> 10)
	msg.truncated = Itob((dnsmisc & 0x0200) >> 9)
	msg.recursion_desired = Itob((dnsmisc & 0x0100) >> 8)
	msg.recursion_available = Itob((dnsmisc & 0x00F0) >> 7)
	msg.rcode = uint(dnsmisc & 0x000F)

	// var question_num uint16
	err = binary.Read(buf, binary.BigEndian, &msg.question_num)
	err = binary.Read(buf, binary.BigEndian, &msg.answer_num)
	err = binary.Read(buf, binary.BigEndian, &msg.authority_num)
	err = binary.Read(buf, binary.BigEndian, &msg.additional_num)

	question := make([]dnsQuestion, msg.question_num)
	for i := 0; i < int(msg.question_num); i++ {
		question[i].Name = getQueryName(buf)
		err = binary.Read(buf, binary.BigEndian, &question[i].Qtype)
		err = binary.Read(buf, binary.BigEndian, &question[i].Qclass)
	}
	msg.question = question
	if msg.answer_num > 0 {
		answer := make([]dnsRR, msg.answer_num)
		for i := 0; i < int(msg.answer_num); i++ {
			answer[i].Name = getQueryName(buf)
			err = binary.Read(buf, binary.BigEndian, &answer[i].Rrtype)
			err = binary.Read(buf, binary.BigEndian, &answer[i].Class)
			err = binary.Read(buf, binary.BigEndian, &answer[i].Ttl)
			err = binary.Read(buf, binary.BigEndian, &answer[i].Rdlength)
			Data := make([]byte, answer[i].Rdlength)
			err = binary.Read(buf, binary.BigEndian, &Data)
			answer[i].Data = Data
		}
		msg.answer = answer
	}
	return msg
}

func dnsRequest(data []byte) []byte {
	conn, err := net.Dial("tcp", DNSSERVER)
	if err != nil {
		log.Fatal(err)
	}

	// buf := new(bytes.Buffer)
	// err = binary.Write(buf, binary.BigEndian, uint16(len(data)))
	query := parseDNSMsg(bytes.NewBuffer(data))
	log.Printf("query: %v", query)
	req := make([]byte, 2)
	binary.BigEndian.PutUint16(req, uint16(len(data)))
	req = append(req, data...)
	_, err = conn.Write(req)
	if err != nil {
		log.Fatal(err)
	}

	reply := make([]byte, 1024)
	_, err = conn.Read(reply)
	if err != nil {
		log.Fatal(err)
	}

	var length uint16
	s := bytes.NewBuffer(reply[:2])
	err = binary.Read(s, binary.BigEndian, &length)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	msg := parseDNSMsg(bytes.NewBuffer(reply[2 : length+2]))
	log.Printf("reply: %v", msg)
	return reply[2 : length+2]
}

func dnsListen(conn net.UDPConn) {
	buf := make([]byte, 1024)
	n, addr, err := conn.ReadFrom(buf)
	log.Print("Addr", addr)

	if err != nil {
		log.Fatal(err)
	}
	log.Print("Data come in from", addr)

	reply := dnsRequest(buf[0:n])
	_, err = conn.WriteTo(reply, addr)
	if err != nil {
		log.Fatal(err)
	} else {
		log.Print("Reply sent")
	}
}

func main() {                
	udpAddr, err := net.ResolveUDPAddr("up4", ":53")
	conn, err := net.ListenUDP("udp",udpAddr)
	if err != nil {
		log.Fatal(err)
	}
	for {
		dnsListen(*conn)
	}
}