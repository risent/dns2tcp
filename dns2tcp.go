package main

import (
	"encoding/binary"
	"log"
	"net"
	"strings"
	"errors"
	"time"
	"flag" // Added flag package

	"github.com/ameshkov/dnscrypt/v2"
	"github.com/miekg/dns"
)

// const DNSSERVER = "8.8.8.8:53" // No longer used for TCP forwarding

// Global variables for DNSCrypt client and resolver info
var cryptClient *dnscrypt.Client
var cryptResolverInfo *dnscrypt.ResolverInfo
var stampToUse string // To store the stamp selected via flag or default
const defaultDnsCryptStamp = "sdns://AQMAAAAAAAAAETk0LjE0MC4xNC4xNDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20" // AdGuard DNS

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

// getDomainName parses a domain name from DNS message data.
// It returns the parsed domain name and the next cursor position in the original data buffer.
// If parsing fails, it returns an empty string, the original cursor, and an error.
func getDomainName(data []byte, initialCursor int) (string, int, error) {
	var labels []string
	currentReadPos := initialCursor
	pointerFollowCount := 0
	posAfterFirstPointer := 0 // Stores the cursor position immediately after the first pointer sequence.

	for {
		if currentReadPos >= len(data) {
			log.Printf("Error: Reached end of data buffer while parsing domain name.")
			return "", initialCursor, errors.New("reached end of data buffer")
		}

		labelSize := data[currentReadPos]
		currentReadPos++

		if labelSize == 0 { // End of domain name
			break
		}

		switch labelSize & 0xC0 {
		case 0x00: // It's a label
			if currentReadPos+int(labelSize) > len(data) {
				log.Printf("Error: Label length exceeds data buffer boundaries.")
				return "", initialCursor, errors.New("label length exceeds data buffer")
			}
			label := string(data[currentReadPos : currentReadPos+int(labelSize)])
			labels = append(labels, label)
			currentReadPos += int(labelSize)
		case 0xC0: // It's a pointer
			if pointerFollowCount == 0 {
				// Store the position *after* this 2-byte pointer sequence.
				// The first byte (labelSize) is already read, currentReadPos is at the second byte.
				// So, after reading the second byte, the position will be currentReadPos + 1.
				posAfterFirstPointer = currentReadPos + 1
			}
			pointerFollowCount++

			if pointerFollowCount > 10 { // Arbitrary limit to prevent pointer loops
				log.Printf("Error: Too many compression pointers.")
				retCursor := initialCursor // Default to initialCursor if no pointer was even successfully started
				if posAfterFirstPointer != 0 { // If at least one pointer sequence was started
					retCursor = posAfterFirstPointer
				}
				// The problem states "return ("Too many compression pointers", offset)" is acceptable.
				// We adapt this to the new signature by returning the specific string in the name field.
				return "Too many compression pointers", retCursor, errors.New("too many compression pointers")
			}

			if currentReadPos >= len(data) { // Boundary check for the second byte of the pointer
				log.Printf("Error: Reached end of data buffer while reading pointer offset.")
				return "", initialCursor, errors.New("incomplete pointer offset")
			}
			secondByte := data[currentReadPos]
			// currentReadPos is already incremented for labelSize, so for the second byte of the pointer,
			// it's effectively currentReadPos (which is initialCursor + 1 + pointerFollowCount*0 -1 +1 = initialCursor+1 if first element is pointer)
			// No, currentReadPos was incremented *after* reading labelSize. So it points to the second byte.
			// We need to increment it *after* using it for pointerDestination.

			pointerDestination := ((int(labelSize) & 0x3F) << 8) | int(secondByte)

			if pointerDestination < 0 || pointerDestination >= len(data) {
				log.Printf("Error: Invalid pointer destination: %d.", pointerDestination)
				return "", initialCursor, errors.New("invalid pointer destination")
			}
			// After successfully reading the second byte of the pointer, the main loop's currentReadPos
			// for the *next* iteration should be the pointerDestination.
			// However, if this is the *first* pointer encountered, the function should eventually return
			// the position *after* this first pointer. This is already stored in posAfterFirstPointer.
			currentReadPos = pointerDestination // Jump to the pointer destination for further label parsing
			// We don't increment currentReadPos here for the main loop because the destination
			// is an absolute offset. The next iteration will read labelSize from there.

		default: // Invalid label type
			log.Printf("Error: Invalid label type encountered: %x", labelSize)
			return "", initialCursor, errors.New("invalid label type")
		}
	}

	name := strings.Join(labels, ".")
	// log.Printf("name=%s", name) // Kept for debugging if necessary, but can be removed for production

	if pointerFollowCount > 0 {
		// If pointers were followed, return the name and the position after the *first* pointer.
		return name, posAfterFirstPointer, nil
	}
	// If no pointers were followed, return the name and the position after the null terminator.
	return name, currentReadPos, nil
}


func parseRR(data []byte, cursor int) (dnsRR, int, error) {
	var rr dnsRR
	var err error

	rr.Name, cursor, err = getDomainName(data, cursor)
	if err != nil {
		log.Printf("Error parsing domain name in RR: %v", err)
		return rr, cursor, err // Propagate error
	}

	// Ensure there's enough data for RR header fields
	if cursor+10 > len(data) { // Rrtype(2) + Class(2) + Ttl(4) + Rdlength(2) = 10 bytes
		log.Printf("Error: Insufficient data for RR header at cursor %d", cursor)
		return rr, cursor, errors.New("insufficient data for RR header")
	}

	rr.Rrtype = binary.BigEndian.Uint16(data[cursor:])
	cursor += 2
	rr.Class = binary.BigEndian.Uint16(data[cursor:])
	cursor += 2
	rr.Ttl = binary.BigEndian.Uint32(data[cursor:])
	cursor += 4
	rr.Rdlength = binary.BigEndian.Uint16(data[cursor:])
	cursor += 2

	// Check for RDATA boundary
	if cursor+int(rr.Rdlength) > len(data) {
		log.Printf("Error: RDATA length %d exceeds data buffer boundaries at cursor %d", rr.Rdlength, cursor)
		return rr, cursor, errors.New("rdata length exceeds data buffer")
	}

	Data := make([]byte, rr.Rdlength)
	copy(Data, data[cursor:cursor+int(rr.Rdlength)])
	// Removed: err := binary.Read(bytes.NewBuffer(data[cursor:]), binary.BigEndian, &Data)
	// Removed: log.Fatal(err) for binary.Read

	rr.Data = Data
	cursor += int(rr.Rdlength)
	return rr, cursor, nil
}

func parseDNSMsg(data []byte) (dnsMsg, error) {
	var msg dnsMsg
	var err error // To hold errors from called functions

	// Basic check for minimum DNS header size
	if len(data) < 12 {
		log.Printf("Error: Data too short for DNS header (%d bytes)", len(data))
		return msg, errors.New("data too short for DNS header")
	}

	msg.id = binary.BigEndian.Uint16(data)
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

	cursor := 12
	question := make([]dnsQuestion, msg.question_num)
	for i := 0; i < int(msg.question_num); i++ {
		if cursor >= len(data) {
			log.Printf("Error: Reached end of data parsing questions (num: %d, index: %d)", msg.question_num, i)
			return msg, errors.New("EOF parsing questions")
		}
		question[i].Name, cursor, err = getDomainName(data, cursor)
		if err != nil {
			log.Printf("Error parsing domain name in Question %d: %v", i, err)
			return msg, err // Propagate error
		}
		if cursor+4 > len(data) { // Qtype(2) + Qclass(2) = 4 bytes
			log.Printf("Error: Insufficient data for Qtype/Qclass in Question %d at cursor %d", i, cursor)
			return msg, errors.New("insufficient data for Qtype/Qclass")
		}
		question[i].Qtype = binary.BigEndian.Uint16(data[cursor:])
		cursor += 2
		question[i].Qclass = binary.BigEndian.Uint16(data[cursor:])
		cursor += 2
	}
	msg.question = question

	if msg.answer_num > 0 {
		// log.Printf("answer number: %d cursor: %d", msg.answer_num, cursor)
		answer := make([]dnsRR, msg.answer_num)
		for i := 0; i < int(msg.answer_num); i++ {
			if cursor >= len(data) {
				log.Printf("Error: Reached end of data parsing answers (num: %d, index: %d)", msg.answer_num, i)
				return msg, errors.New("EOF parsing answers")
			}
			answer[i], cursor, err = parseRR(data, cursor)
			if err != nil {
				log.Printf("Error parsing Answer RR %d: %v", i, err)
				return msg, err // Propagate error
			}
		}
		msg.answer = answer
	}

	if msg.authority_num > 0 {
		// log.Printf("authority number: %d cursor: %d", msg.authority_num, cursor)
		ns := make([]dnsRR, msg.authority_num)
		for i := 0; i < int(msg.authority_num); i++ {
			if cursor >= len(data) {
				log.Printf("Error: Reached end of data parsing authority RRs (num: %d, index: %d)", msg.authority_num, i)
				return msg, errors.New("EOF parsing authority RRs")
			}
			ns[i], cursor, err = parseRR(data, cursor)
			if err != nil {
				log.Printf("Error parsing Authority RR %d: %v", i, err)
				return msg, err // Propagate error
			}
		}
		msg.ns = ns
	}

	if msg.additional_num > 0 {
		// log.Printf("additional  number: %d cursor: %d", msg.additional_num, cursor)
		extra := make([]dnsRR, msg.additional_num)
		for i := 0; i < int(msg.additional_num); i++ { // Corrected loop to use msg.additional_num
			if cursor >= len(data) {
				log.Printf("Error: Reached end of data parsing additional RRs (num: %d, index: %d)", msg.additional_num, i)
				return msg, errors.New("EOF parsing additional RRs")
			}
			extra[i], cursor, err = parseRR(data, cursor)
			if err != nil {
				log.Printf("Error parsing Additional RR %d: %v", i, err)
				return msg, err // Propagate error
			}
		}
		msg.extra = extra
	}
	return msg, nil
}

func dnsRequest(queryBytes []byte) ([]byte, error) {
	// cryptClient and cryptResolverInfo are now global and initialized in main()

	reqMsg := new(dns.Msg)
	err := reqMsg.Unpack(queryBytes)
	if err != nil {
		log.Printf("DNSCrypt: failed to unpack query: %v", err)
		return nil, err
	}

	// Optional: Log the query details after unpacking
	// log.Printf("DNSCrypt: Sending query to %s: %s", cryptResolverInfo.ProviderName, reqMsg.Question[0].String())

	replyMsg, err := cryptClient.Exchange(reqMsg, cryptResolverInfo)
	if err != nil {
		// Use ProviderName from global cryptResolverInfo for better logging
		providerName := "unknown resolver"
		if cryptResolverInfo != nil && cryptResolverInfo.ProviderName != "" {
			providerName = cryptResolverInfo.ProviderName
		}
		log.Printf("DNSCrypt: exchange with resolver '%s' failed: %v", providerName, err)
		return nil, err
	}

	// Optional: Log the reply details
	// if replyMsg != nil && len(replyMsg.Answer) > 0 {
	// 	log.Printf("DNSCrypt: Received reply with answers. First answer: %s", replyMsg.Answer[0].String())
	// } else if replyMsg != nil {
	// 	log.Printf("DNSCrypt: Received reply with RCODE: %s", dns.RcodeToString[replyMsg.Rcode])
	// }


	replyBytes, err := replyMsg.Pack()
	if err != nil {
		log.Printf("DNSCrypt: failed to pack reply: %v", err)
		return nil, err
	}

	return replyBytes, nil
}

func dnsListen(conn net.UDPConn) {
	buf := make([]byte, 1024)
	n, addr, err := conn.ReadFrom(buf)
	if err != nil {
		log.Printf("Error reading from UDP: %v. Client address: %s", err, addr)
		return // Return to avoid further processing on read error
	}
	log.Printf("Data come in from: %s, size: %d bytes", addr, n)

	reply, err := dnsRequest(buf[0:n])
	if err != nil {
		log.Printf("Failed to get DNS response via DNSCrypt for client %s: %v", addr, err)
		// Do not send a reply or send a SERVFAIL (out of scope for this PoC)
		return
	}

	// If successful, send the reply:
	_, err = conn.WriteTo(reply, addr)
	if err != nil {
		log.Printf("Error writing reply to client %s: %v", addr, err)
	} else {
		providerName := "configured resolver"
		if cryptResolverInfo != nil && cryptResolverInfo.ProviderName != "" {
			providerName = cryptResolverInfo.ProviderName
		}
		log.Printf("Successfully sent DNSCrypt reply to %s (via %s)", addr, providerName)
	}
}

func main() {
	// Define command-line flag for the DNSCrypt stamp
	flag.StringVar(&stampToUse, "stamp", defaultDnsCryptStamp, "DNSCrypt v2 resolver stamp string.")
	flag.Parse()

	if stampToUse == defaultDnsCryptStamp {
		log.Printf("Using default DNSCrypt resolver stamp (AdGuard DNS): %s", defaultDnsCryptStamp)
	} else {
		log.Printf("Using user-provided DNSCrypt resolver stamp: %s", stampToUse)
	}

	// Initialize the global DNSCrypt client
	// Note: The Net field in dnscrypt.Client ("udp" or "tcp") specifies the transport for DNSCrypt itself,
	// not the transport for the incoming plain DNS queries (which is UDP in our dnsListen function).
	cryptClient = &dnscrypt.Client{Net: "udp", Timeout: 10 * time.Second}

	var err error // Declare err here so it's accessible for multiple calls if needed
	cryptResolverInfo, err = cryptClient.Dial(stampToUse)
	if err != nil {
		log.Fatalf("DNSCrypt: failed to dial resolver with stamp '%s': %v", stampToUse, err)
	}
	log.Printf("Successfully initialized DNSCrypt client with resolver: %s", cryptResolverInfo.ProviderName)

	// Setup UDP listener for incoming plain DNS queries
	udpAddr, err := net.ResolveUDPAddr("udp4", ":53") // Using "udp4" for IPv4 UDP
	if err != nil {
		log.Fatalf("Failed to resolve UDP address :53: %v", err)
	}

	conn, err := net.ListenUDP("udp4", udpAddr) // Using "udp4"
	if err != nil {
		log.Fatalf("Failed to listen on UDP port 53: %v. Ensure the program has necessary permissions (e.g., run with sudo).", err)
	}
	defer conn.Close()

	log.Printf("DNS-to-DNSCrypt proxy started. Listening for plain DNS on UDP :53. Forwarding to DNSCrypt resolver: %s.", cryptResolverInfo.ProviderName)

	// Removed the incorrect 'if conn == nil' check here, as ListenUDP would have already returned an error.
	for {
		dnsListen(*conn)
	}
}