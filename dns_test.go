package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// fakeDNS starts a UDP and a TCP listener on the same port. The handlers get
// the raw query and return the raw reply (nil means "stay silent").
func fakeDNS(t *testing.T, udpHandler, tcpHandler func(query []byte) []byte) string {
	t.Helper()
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	t.Cleanup(func() { udp.Close() })
	port := udp.LocalAddr().(*net.UDPAddr).Port

	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := udp.ReadFrom(buf)
			if err != nil {
				return
			}
			if reply := udpHandler(buf[:n]); reply != nil {
				udp.WriteTo(reply, addr)
			}
		}
	}()

	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				var lenBuf [2]byte
				if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
					return
				}
				query := make([]byte, binary.BigEndian.Uint16(lenBuf[:]))
				if _, err := io.ReadFull(conn, query); err != nil {
					return
				}
				reply := tcpHandler(query)
				if reply == nil {
					return
				}
				out := make([]byte, 2+len(reply))
				binary.BigEndian.PutUint16(out, uint16(len(reply)))
				copy(out[2:], reply)
				conn.Write(out)
			}(conn)
		}
	}()

	return fmt.Sprintf("127.0.0.1:%d", port)
}

// reply builds a response that echoes the query's id and question.
func reply(query []byte, flags uint16, answers int) []byte {
	resp := []byte{}
	resp = appendU16(resp, binary.BigEndian.Uint16(query[0:2]))
	resp = appendU16(resp, flagQR|flags)
	resp = appendU16(resp, 1) // QDCOUNT
	resp = appendU16(resp, uint16(answers))
	resp = appendU16(resp, 0)
	resp = appendU16(resp, 0)
	resp = append(resp, query[12:]...)
	return resp
}

func TestQueryResolverAnswers(t *testing.T) {
	addr := fakeDNS(t,
		func(q []byte) []byte { return reply(q, 0, 3) },
		func(q []byte) []byte { return reply(q, 0, 3) },
	)
	resp, elapsed, err := queryResolver(addr, question{name: "example.com", qtype: 1}, time.Second)
	if err != nil {
		t.Fatalf("queryResolver: %v", err)
	}
	if resp.rcode != 0 {
		t.Errorf("rcode = %d, want 0", resp.rcode)
	}
	if resp.answers != 3 {
		t.Errorf("answers = %d, want 3", resp.answers)
	}
	if elapsed <= 0 {
		t.Errorf("elapsed = %v, want > 0", elapsed)
	}
}

func TestQueryResolverTimeout(t *testing.T) {
	addr := fakeDNS(t, func(q []byte) []byte { return nil }, func(q []byte) []byte { return nil })
	_, _, err := queryResolver(addr, question{name: "example.com", qtype: 1}, 200*time.Millisecond)
	if err == nil {
		t.Fatal("expected an error, got none")
	}
	if !strings.Contains(err.Error(), "timeout") {
		t.Errorf("error = %v, want a timeout", err)
	}
}

func TestQueryResolverRefused(t *testing.T) {
	addr := fakeDNS(t,
		func(q []byte) []byte { return reply(q, 5, 0) }, // REFUSED
		func(q []byte) []byte { return reply(q, 5, 0) },
	)
	resp, _, err := queryResolver(addr, question{name: "example.com", qtype: 1}, time.Second)
	if err != nil {
		t.Fatalf("queryResolver: %v", err)
	}
	if resp.rcode != 5 {
		t.Errorf("rcode = %d, want 5 (REFUSED)", resp.rcode)
	}
}

func TestQueryResolverTruncatedFallsBackToTCP(t *testing.T) {
	addr := fakeDNS(t,
		func(q []byte) []byte { return reply(q, flagTC, 0) },
		func(q []byte) []byte { return reply(q, 0, 2) },
	)
	resp, _, err := queryResolver(addr, question{name: "example.com", qtype: 1}, time.Second)
	if err != nil {
		t.Fatalf("queryResolver: %v", err)
	}
	if resp.truncated {
		t.Error("response still marked truncated")
	}
	if resp.answers != 2 {
		t.Errorf("answers = %d, want 2", resp.answers)
	}
}

func TestQueryResolverRejectsWrongID(t *testing.T) {
	addr := fakeDNS(t,
		func(q []byte) []byte {
			r := reply(q, 0, 1)
			binary.BigEndian.PutUint16(r[0:2], binary.BigEndian.Uint16(q[0:2])+1)
			return r
		},
		func(q []byte) []byte { return reply(q, 0, 1) },
	)
	if _, _, err := queryResolver(addr, question{name: "example.com", qtype: 1}, time.Second); err == nil {
		t.Fatal("expected an error for mismatched response id, got none")
	}
}

func TestQueryResolverRejectsWrongQuestion(t *testing.T) {
	addr := fakeDNS(t,
		func(q []byte) []byte {
			r := reply(q, 0, 1)
			r[13] = 'x' // corrupt the echoed domain name
			return r
		},
		func(q []byte) []byte { return reply(q, 0, 1) },
	)
	if _, _, err := queryResolver(addr, question{name: "example.com", qtype: 1}, time.Second); err == nil {
		t.Fatal("expected an error for mismatched question, got none")
	}
}

func TestQueryResolverAcceptsResponseWithoutQuestion(t *testing.T) {
	// Some resolvers reply with QDCOUNT=0 and no echoed question. They did
	// answer, so they must not be reported as broken.
	addr := fakeDNS(t,
		func(q []byte) []byte {
			r := reply(q, 5, 0)
			binary.BigEndian.PutUint16(r[4:6], 0) // QDCOUNT = 0
			return r
		},
		func(q []byte) []byte { return reply(q, 5, 0) },
	)
	resp, _, err := queryResolver(addr, question{name: "example.com", qtype: 1}, time.Second)
	if err != nil {
		t.Fatalf("queryResolver: %v", err)
	}
	if resp.rcode != 5 {
		t.Errorf("rcode = %d, want 5 (REFUSED)", resp.rcode)
	}
}

func TestParseResolver(t *testing.T) {
	tests := []struct {
		in   string
		host string
		port int
		err  bool
	}{
		{in: "1.1.1.1", host: "1.1.1.1", port: 53},
		{in: " 8.8.8.8 ", host: "8.8.8.8", port: 53},
		{in: "1.1.1.1:5353", host: "1.1.1.1", port: 5353},
		{in: "2606:4700:4700::1111", host: "2606:4700:4700::1111", port: 53},
		{in: "[2606:4700:4700::1111]", host: "2606:4700:4700::1111", port: 53},
		{in: "[2606:4700:4700::1111]:5353", host: "2606:4700:4700::1111", port: 5353},
		{in: "dns.google", err: true},
		{in: "1.1.1.1:99999", err: true},
		{in: "", err: true},
	}
	for _, tt := range tests {
		host, port, err := parseResolver(tt.in)
		if tt.err {
			if err == nil {
				t.Errorf("parseResolver(%q) = %q,%d, want error", tt.in, host, port)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseResolver(%q): %v", tt.in, err)
			continue
		}
		if host != tt.host || port != tt.port {
			t.Errorf("parseResolver(%q) = %q,%d, want %q,%d", tt.in, host, port, tt.host, tt.port)
		}
	}
}

func TestSplitList(t *testing.T) {
	got := splitList("# comment\n1.1.1.1\n\n  8.8.8.8, 9.9.9.9  \n1.0.0.1 # trailing\n")
	want := []string{"1.1.1.1", "8.8.8.8", "9.9.9.9", "1.0.0.1"}
	if len(got) != len(want) {
		t.Fatalf("splitList = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("splitList = %v, want %v", got, want)
		}
	}
}

func TestBuildQuery(t *testing.T) {
	msg, err := buildQuery(0x1234, question{name: "example.com", qtype: 1})
	if err != nil {
		t.Fatalf("buildQuery: %v", err)
	}
	if len(msg) != 12+13+4 {
		t.Errorf("len = %d, want %d", len(msg), 12+13+4)
	}
	if got := binary.BigEndian.Uint16(msg[0:2]); got != 0x1234 {
		t.Errorf("id = %x, want 1234", got)
	}
	if got := binary.BigEndian.Uint16(msg[2:4]); got&flagRD == 0 {
		t.Errorf("recursion desired not set: %x", got)
	}
}
