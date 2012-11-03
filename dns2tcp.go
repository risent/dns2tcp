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

func getDomainName(data []byte, cursor int) (name string, offset int) {
	over := false
	n := 0
	ptr := 0
	length := len(data[cursor:])
	labels := make([]string, 63)

Loop:
	for ; !over; n++ {
		if cursor >= len(data) {
			return "", len(data)
		}
		labelsize := data[cursor]
		cursor++
		if labelsize == 0 {
			break Loop
		}

		switch labelsize & 0xC0 {
		case 0x00:
			if labelsize == 0x00 {
				break Loop
			}
			label := make([]byte, labelsize)
			size, err := bytes.NewBuffer(data[cursor:]).Read(label)
			// cursor++
			if err != nil {
				log.Fatal(err)
			}
			if size != int(labelsize) {
				log.Printf("Error in read %d, bytes of %x", size, label)
			}
			labels[n] = string(label)
			cursor += size
		case 0xC0:
			n--
			if ptr == 0 {
				offset = cursor
			}
			if ptr > 10 {
				return "Too many compression pointers", offset
			}
			ptr++

			c1 := int(data[cursor])
			cursor = (int(labelsize)^0xC0)<<8 | int(c1)
		default:
			return "", length
		}
	}

	name = strings.Join(labels[0:n], ".")
	log.Printf("name=%s", name)
	if ptr != 0 {
		return name, offset + 1
	}
	return name, cursor
}

func parseDNSMsg(data []byte) dnsMsg {
	var msg dnsMsg
	msg.id = binary.BigEndian.Uint16(data)
	// var dnsmisc uint16
	dnsmisc := binary.BigEndian.Uint16(data[2:])
	msg.response = true
	msg.opcode = uint((dnsmisc >> 11) & 0x000F)
	msg.authoritative = Itob((dnsmisc & 0x0400) >> 10)
	msg.truncated = Itob((dnsmisc & 0x0200) >> 9)
	msg.recursion_desired = Itob((dnsmisc & 0x0100) >> 8)
	msg.recursion_available = Itob((dnsmisc & 0x00F0) >> 7)
	msg.rcode = uint(dnsmisc & 0x000F)

	msg.question_num = binary.BigEndian.Uint16(data[4:])
	msg.answer_num = binary.BigEndian.Uint16(data[6:])
	msg.authority_num = binary.BigEndian.Uint16(data[8:])
	msg.additional_num = binary.BigEndian.Uint16(data[10:])

	question := make([]dnsQuestion, msg.question_num)
	cursor := 12
	for i := 0; i < int(msg.question_num); i++ {
		// var nameLength int
		question[i].Name, cursor = getDomainName(data, cursor)
		// cursor += offset
		question[i].Qtype = binary.BigEndian.Uint16(data[cursor:])
		cursor += 2
		question[i].Qclass = binary.BigEndian.Uint16(data[cursor:])
		cursor += 2
	}
	msg.question = question

	if msg.answer_num > 0 {
		log.Printf("answer number: %d cursor: %d", msg.answer_num, cursor)
		answer := make([]dnsRR, msg.answer_num)
		for i := 0; i < int(msg.answer_num); i++ {
			answer[i].Name, cursor = getDomainName(data, cursor)
			answer[i].Rrtype = binary.BigEndian.Uint16(data[cursor:])
			cursor += 2
			answer[i].Class = binary.BigEndian.Uint16(data[cursor:])
			cursor += 2
			answer[i].Ttl = binary.BigEndian.Uint32(data[cursor:])
			cursor += 4
			answer[i].Rdlength = binary.BigEndian.Uint16(data[cursor:])
			cursor += 2
			Data := make([]byte, answer[i].Rdlength)
			err := binary.Read(bytes.NewBuffer(data[cursor:]), binary.BigEndian, &Data)
			if err != nil {
				log.Fatal(err)
			}
			answer[i].Data = Data
			cursor += int(answer[i].Rdlength)
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

	query := parseDNSMsg(data)
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

	msg := parseDNSMsg(reply[2 : length+2])
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
	log.Printf("Data come in from: %s", addr)

	reply := dnsRequest(buf[0:n])
	_, err = conn.WriteTo(reply, addr)
	if err != nil {
		log.Fatal(err)
	} else {
		log.Print("=====EOF=====")
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