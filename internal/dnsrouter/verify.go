package dnsrouter

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"log"
	"math/rand/v2"
	"net"
	"strings"
	"sync"
)

// verifyRoute holds the pubkey and MTU for a domain's HMAC verification.
type verifyRoute struct {
	domainLabels []string // tunnel domain split into lowercase labels
	pubkey       []byte   // server public key used as HMAC key
	mtu          int      // default response size (0 = no padding)
}

// verifyEncoding is the lowercase base32 alphabet used for verify queries,
// matching dnstt's subdomain encoding so probes are visually identical to
// real tunnel traffic.
var verifyEncoding = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// paddingPool reuses random padding buffers to avoid allocations.
var paddingPool = sync.Pool{
	New: func() any {
		b := make([]byte, 4096)
		return &b
	},
}

// handleVerify detects and responds to HMAC verify probes.
//
// Query format:  <base32(nonce[16] || HMAC(key,nonce)[:16])>.<tunnel-domain>
// Response:      TXT containing HMAC(key, nonce||0x01) padded to MTU.
//
// The subdomain looks like any other base32-encoded dnstt/noizdns label.
// The server only responds when the embedded HMAC proof is correct; all
// other queries (real tunnel traffic, random probes) are forwarded normally.
func (r *Router) handleVerify(packet []byte, clientAddr *net.UDPAddr) bool {
	if len(packet) < 12 {
		return false
	}
	// Must be a query (QR=0)
	if packet[2]&0x80 != 0 {
		return false
	}
	// QDCOUNT must be 1
	if binary.BigEndian.Uint16(packet[4:6]) != 1 {
		return false
	}

	// Parse the question name into labels
	offset := 12
	var labels []string
	for offset < len(packet) {
		length := int(packet[offset])
		if length == 0 {
			offset++
			break
		}
		if length >= 0xC0 {
			return false
		}
		offset++
		if offset+length > len(packet) {
			return false
		}
		labels = append(labels, strings.ToLower(string(packet[offset:offset+length])))
		offset += length
	}

	if offset+4 > len(packet) {
		return false
	}
	qtype := binary.BigEndian.Uint16(packet[offset : offset+2])
	if qtype != 16 { // must be TXT
		return false
	}
	qEnd := offset + 4

	// Find a registered verify route matching the domain suffix
	vr := r.findVerifyRoute(labels)
	if vr == nil {
		return false
	}

	dl := len(vr.domainLabels)
	if len(labels) <= dl {
		return false
	}

	// Concatenate all subdomain labels.
	// nonce[16] || clientProof[16] = 32 bytes → exactly 52 base32 chars.
	// Quick length check before expensive decode to skip real tunnel traffic fast.
	encoded := strings.Join(labels[:len(labels)-dl], "")
	if len(encoded) != 52 {
		return false
	}

	decoded, err := verifyEncoding.DecodeString(encoded)
	if err != nil || len(decoded) != 32 {
		return false
	}

	nonce := decoded[:16]
	clientProof := decoded[16:32]

	// Verify client proof: HMAC-SHA256(key, nonce)[:16]
	mac := hmac.New(sha256.New, vr.pubkey)
	mac.Write(nonce)
	expected := mac.Sum(nil)[:16]
	if !hmac.Equal(clientProof, expected) {
		return false
	}

	log.Printf("verify: valid probe from %s, responding", clientAddr)

	// Valid probe. Compute response: HMAC-SHA256(key, nonce || 0x01)
	mac2 := hmac.New(sha256.New, vr.pubkey)
	mac2.Write(nonce)
	mac2.Write([]byte{0x01})
	respHMAC := mac2.Sum(nil) // 32 bytes

	// Determine response padding target.
	// The desired response size is encoded in nonce[14:16] (big-endian uint16)
	// by the client, so it survives resolver EDNS0 rewriting.
	mtu := vr.mtu
	if mtu == 0 {
		mtu = 1232
	}
	if desiredSize := int(binary.BigEndian.Uint16(nonce[14:16])); desiredSize >= 200 && desiredSize <= 4096 {
		mtu = desiredSize
	} else if clientEDNS := parseEDNS0PayloadSize(packet, qEnd); clientEDNS > 0 && clientEDNS != 1232 {
		mtu = clientEDNS
	}

	// Randomize around the target to match natural dnstt variation
	targetTotal := mtu - rand.IntN(mtu/4) // 75%-100% of target
	if targetTotal < 200 {
		targetTotal = 200
	}
	overhead := qEnd + 14 + 11 // header+question + answer fixed + EDNS0 OPT
	targetPayload := targetTotal - overhead
	// Account for TXT length prefixes: 1 byte per 255 bytes of data
	targetData := targetPayload - (targetPayload / 256) - 1
	if targetData < 32 {
		targetData = 32
	}

	// Build payload: HMAC response + fast random padding from pool
	bufPtr := paddingPool.Get().(*[]byte)
	payload := (*bufPtr)[:targetData]
	copy(payload, respHMAC)
	if targetData > 32 {
		fillFastRandom(payload[32:])
	}

	resp := buildBinaryTXTResponseWithEDNS(packet, qEnd, payload, 4096)
	paddingPool.Put(bufPtr)

	if _, err := r.conn.WriteToUDP(resp, clientAddr); err != nil {
		log.Printf("verify: write: %v", err)
	}
	return true
}

// fillFastRandom fills buf with pseudo-random bytes using math/rand.
// This is for padding only — not security-critical.
func fillFastRandom(buf []byte) {
	for i := 0; i+8 <= len(buf); i += 8 {
		binary.LittleEndian.PutUint64(buf[i:], rand.Uint64())
	}
	// Fill remaining bytes
	for i := len(buf) &^ 7; i < len(buf); i++ {
		buf[i] = byte(rand.UintN(256))
	}
}

// findVerifyRoute returns the verify route whose domain suffix matches labels.
func (r *Router) findVerifyRoute(labels []string) *verifyRoute {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for i := range r.verifyRoutes {
		vr := &r.verifyRoutes[i]
		dl := len(vr.domainLabels)
		if len(labels) < 1+dl {
			continue
		}
		off := len(labels) - dl
		match := true
		for j, want := range vr.domainLabels {
			if labels[off+j] != want {
				match = false
				break
			}
		}
		if match {
			return vr
		}
	}
	return nil
}

// buildBinaryTXTResponseWithEDNS constructs a DNS TXT response with raw binary
// payload and EDNS0 OPT record. Matches real dnstt-server response format.
func buildBinaryTXTResponseWithEDNS(query []byte, qEnd int, data []byte, ednsPayloadSize int) []byte {
	var resp []byte

	// Header — match dnstt-server exactly: QR=1, AA=1, RD=0, RA=0
	resp = append(resp, query[0], query[1]) // Transaction ID
	resp = append(resp, 0x84, 0x00)         // Flags: QR=1, AA=1 (0x8400)
	resp = append(resp, 0x00, 0x01)         // QDCOUNT = 1
	resp = append(resp, 0x00, 0x01)         // ANCOUNT = 1
	resp = append(resp, 0x00, 0x00)         // NSCOUNT = 0
	resp = append(resp, 0x00, 0x01)         // ARCOUNT = 1 (EDNS0 OPT)

	// Question section (copy from query)
	resp = append(resp, query[12:qEnd]...)

	// Answer: name pointer + TXT RR
	resp = append(resp, 0xC0, 0x0C)              // name pointer to offset 12
	resp = append(resp, 0x00, 0x10)              // TYPE = TXT
	resp = append(resp, 0x00, 0x01)              // CLASS = IN
	resp = append(resp, 0x00, 0x00, 0x00, 0x3C) // TTL = 60

	// Build RDATA with character-strings (max 255 bytes each)
	var rdata []byte
	remaining := data
	for len(remaining) > 0 {
		chunk := remaining
		if len(chunk) > 255 {
			chunk = chunk[:255]
		}
		rdata = append(rdata, byte(len(chunk)))
		rdata = append(rdata, chunk...)
		remaining = remaining[len(chunk):]
	}

	// RDLENGTH
	resp = append(resp, byte(len(rdata)>>8), byte(len(rdata)))
	resp = append(resp, rdata...)

	// EDNS0 OPT pseudo-RR (RFC 6891)
	resp = append(resp, 0x00)                                                 // Name: root
	resp = append(resp, 0x00, 0x29)                                           // TYPE: OPT (41)
	resp = append(resp, byte(ednsPayloadSize>>8), byte(ednsPayloadSize&0xFF)) // CLASS: UDP payload size
	resp = append(resp, 0x00, 0x00, 0x00, 0x00)                              // TTL: extended RCODE(0) + version(0) + flags(0)
	resp = append(resp, 0x00, 0x00)                                           // RDLENGTH: 0

	return resp
}

// parseEDNS0PayloadSize scans the additional section of a DNS query for an
// OPT (type 41) pseudo-RR and returns the advertised UDP payload size.
func parseEDNS0PayloadSize(packet []byte, qEnd int) int {
	if len(packet) < 12 {
		return 0
	}
	arCount := int(binary.BigEndian.Uint16(packet[10:12]))
	if arCount == 0 {
		return 0
	}
	anCount := int(binary.BigEndian.Uint16(packet[6:8]))
	nsCount := int(binary.BigEndian.Uint16(packet[8:10]))
	offset := qEnd
	for i := 0; i < anCount+nsCount; i++ {
		offset = skipName(packet, offset)
		if offset < 0 || offset+10 > len(packet) {
			return 0
		}
		rdLen := int(binary.BigEndian.Uint16(packet[offset+8 : offset+10]))
		offset += 10 + rdLen
		if offset > len(packet) {
			return 0
		}
	}
	for i := 0; i < arCount; i++ {
		offset = skipName(packet, offset)
		if offset < 0 || offset+10 > len(packet) {
			return 0
		}
		rrType := binary.BigEndian.Uint16(packet[offset : offset+2])
		if rrType == 41 {
			return int(binary.BigEndian.Uint16(packet[offset+2 : offset+4]))
		}
		rdLen := int(binary.BigEndian.Uint16(packet[offset+8 : offset+10]))
		offset += 10 + rdLen
		if offset > len(packet) {
			return 0
		}
	}
	return 0
}

// skipName advances past a DNS name (handles both labels and pointers).
func skipName(packet []byte, offset int) int {
	for offset < len(packet) {
		length := int(packet[offset])
		if length == 0 {
			return offset + 1
		}
		if length >= 0xC0 { // pointer
			return offset + 2
		}
		offset += 1 + length
	}
	return -1
}
