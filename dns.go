package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"strings"
	"time"
)

const (
	flagQR = 0x8000 // response bit
	flagTC = 0x0200 // truncated bit
	flagRD = 0x0100 // recursion desired
)

// question is the query we send to every resolver.
type question struct {
	name  string
	qtype uint16
}

// dnsResponse is what we could learn from a resolver.
type dnsResponse struct {
	rcode     int
	answers   int
	truncated bool
}

var rcodeNames = []string{
	"NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED",
	"YXDOMAIN", "YXRRSET", "NXRRSET", "NOTAUTH", "NOTZONE",
}

func rcodeName(c int) string {
	if c >= 0 && c < len(rcodeNames) {
		return rcodeNames[c]
	}
	return fmt.Sprintf("RCODE%d", c)
}

func appendU16(b []byte, v uint16) []byte { return append(b, byte(v>>8), byte(v)) }

// buildQuery encodes a DNS query message for the given question.
func buildQuery(id uint16, q question) ([]byte, error) {
	name := strings.TrimSuffix(strings.TrimSpace(q.name), ".")
	if name == "" {
		return nil, errors.New("empty domain name")
	}
	msg := []byte{}
	msg = appendU16(msg, id)
	msg = appendU16(msg, flagRD)
	msg = appendU16(msg, 1) // QDCOUNT
	msg = appendU16(msg, 0) // ANCOUNT
	msg = appendU16(msg, 0) // NSCOUNT
	msg = appendU16(msg, 0) // ARCOUNT

	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 {
			return nil, fmt.Errorf("invalid label %q in %q", label, name)
		}
		msg = append(msg, byte(len(label)))
		msg = append(msg, label...)
	}
	msg = append(msg, 0)          // root label
	msg = appendU16(msg, q.qtype) // QTYPE
	msg = appendU16(msg, 1)       // QCLASS = IN
	return msg, nil
}

// parseResponse validates a DNS response against the query we sent.
func parseResponse(msg []byte, id uint16, q question) (*dnsResponse, error) {
	if len(msg) < 12 {
		return nil, fmt.Errorf("malformed response: %d bytes", len(msg))
	}
	if got := binary.BigEndian.Uint16(msg[0:2]); got != id {
		return nil, fmt.Errorf("unexpected response id %d (want %d)", got, id)
	}
	flags := binary.BigEndian.Uint16(msg[2:4])
	if flags&flagQR == 0 {
		return nil, errors.New("malformed response: not a reply")
	}
	if binary.BigEndian.Uint16(msg[4:6]) < 1 {
		// Some resolvers reply without echoing the question. That is still a
		// response, so accept it instead of dropping the resolver.
		return &dnsResponse{
			rcode:   int(flags & 0xF),
			answers: int(binary.BigEndian.Uint16(msg[6:8])),
		}, nil
	}
	name, off, err := readName(msg, 12)
	if err == nil && off+4 <= len(msg) {
		qtype := binary.BigEndian.Uint16(msg[off : off+2])
		qclass := binary.BigEndian.Uint16(msg[off+2 : off+4])
		if !strings.EqualFold(strings.TrimSuffix(name, "."), strings.TrimSuffix(q.name, ".")) ||
			qtype != q.qtype || qclass != 1 {
			return nil, errors.New("malformed response: does not match query")
		}
	}
	return &dnsResponse{
		rcode:     int(flags & 0xF),
		answers:   int(binary.BigEndian.Uint16(msg[6:8])),
		truncated: flags&flagTC != 0,
	}, nil
}

// readName reads an uncompressed domain name and returns it plus the offset
// just after the name.
func readName(msg []byte, off int) (string, int, error) {
	var sb strings.Builder
	for {
		if off >= len(msg) {
			return "", 0, errors.New("malformed response: truncated name")
		}
		l := int(msg[off])
		if l == 0 {
			return sb.String(), off + 1, nil
		}
		if l&0xC0 != 0 {
			return "", 0, errors.New("malformed response: unexpected name compression")
		}
		off++
		if off+l > len(msg) {
			return "", 0, errors.New("malformed response: truncated label")
		}
		if sb.Len() > 0 {
			sb.WriteByte('.')
		}
		sb.Write(msg[off : off+l])
		off += l
		if sb.Len() > 255 {
			return "", 0, errors.New("malformed response: name too long")
		}
	}
}

// queryResolver asks a single resolver for the question over UDP, falling back
// to TCP when the answer is truncated.
func queryResolver(addr string, q question, timeout time.Duration) (*dnsResponse, time.Duration, error) {
	id := uint16(rand.Intn(1 << 16))
	msg, err := buildQuery(id, q)
	if err != nil {
		return nil, 0, err
	}

	start := time.Now()
	conn, err := net.DialTimeout("udp", addr, timeout)
	if err != nil {
		return nil, time.Since(start), fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, time.Since(start), err
	}
	if _, err := conn.Write(msg); err != nil {
		return nil, time.Since(start), fmt.Errorf("write: %w", err)
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, time.Since(start), timeoutErr(err, timeout)
	}
	resp, err := parseResponse(buf[:n], id, q)
	if err != nil {
		return nil, time.Since(start), err
	}
	if resp.truncated {
		tcpResp, err := queryOverTCP(addr, msg, id, q, timeout)
		if err != nil {
			return nil, time.Since(start), err
		}
		resp = tcpResp
	}
	return resp, time.Since(start), nil
}

// queryOverTCP re-sends the query over TCP and parses the reply.
func queryOverTCP(addr string, msg []byte, id uint16, q question, timeout time.Duration) (*dnsResponse, error) {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, fmt.Errorf("tcp dial: %w", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}
	framed := appendU16([]byte{}, uint16(len(msg)))
	framed = append(framed, msg...)
	if _, err := conn.Write(framed); err != nil {
		return nil, fmt.Errorf("tcp write: %w", err)
	}
	var lenBuf [2]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return nil, timeoutErr(err, timeout)
	}
	reply := make([]byte, binary.BigEndian.Uint16(lenBuf[:]))
	if _, err := io.ReadFull(conn, reply); err != nil {
		return nil, timeoutErr(err, timeout)
	}
	return parseResponse(reply, id, q)
}

func timeoutErr(err error, timeout time.Duration) error {
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return fmt.Errorf("timeout after %s", timeout)
	}
	return err
}
