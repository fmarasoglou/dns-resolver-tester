package main

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
	"time"
)

// queryType extracts the QTYPE from a raw query. buildQuery appends no EDNS
// records, so the question's type+class are the last four bytes.
func queryType(q []byte) uint16 {
	return binary.BigEndian.Uint16(q[len(q)-4 : len(q)-2])
}

func TestCanaryQuestionsAreMustFailNames(t *testing.T) {
	qs := canaryQuestions()
	if len(qs) != 4 {
		t.Fatalf("want 4 canary questions, got %d", len(qs))
	}
	suffixes := []string{".example.com", ".google.com", ".invalid", ".invalid"}
	types := []uint16{queryTypes["A"], queryTypes["A"], queryTypes["A"], queryTypes["AAAA"]}
	for i, q := range qs {
		if !strings.HasSuffix(q.name, suffixes[i]) {
			t.Errorf("question %d: %q does not end in %q", i, q.name, suffixes[i])
		}
		if q.qtype != types[i] {
			t.Errorf("question %d: type %d, want %d", i, q.qtype, types[i])
		}
	}
	if qs[0].name == qs[1].name {
		t.Error("canary names must be random per call, got a repeated name")
	}
}

func TestCanaryCleanResolver(t *testing.T) {
	// NXDOMAIN for everything → answered, not fabricated.
	addr := fakeDNS(t,
		func(q []byte) []byte { return reply(q, 3, 0) },
		func(q []byte) []byte { return reply(q, 3, 0) })
	res := checkCanaries([]string{addr}, 500*time.Millisecond, 8)
	if len(res) != 1 {
		t.Fatalf("want 1 result, got %d", len(res))
	}
	if !res[0].answered || res[0].fabricated {
		t.Errorf("clean resolver misclassified: %+v", res[0])
	}
}

func TestCanaryFabricatorIsFlagged(t *testing.T) {
	// Answers every lookup with records → fabricator.
	addr := fakeDNS(t,
		func(q []byte) []byte { return reply(q, 0, 1) },
		func(q []byte) []byte { return reply(q, 0, 1) })
	res := checkCanaries([]string{addr}, 500*time.Millisecond, 8)
	if !res[0].fabricated {
		t.Fatalf("fabricator not flagged: %+v", res[0])
	}
	if res[0].detail == "" {
		t.Error("fabricator detail should name the canary that got records")
	}
}

func TestCanaryFabricatorOnAAAAOnly(t *testing.T) {
	// NXDOMAIN on A, but answers the AAAA canary of the .invalid name.
	addr := fakeDNS(t,
		func(q []byte) []byte {
			if queryType(q) == queryTypes["AAAA"] {
				return reply(q, 0, 2)
			}
			return reply(q, 3, 0)
		}, nil)
	res := checkCanaries([]string{addr}, 500*time.Millisecond, 8)
	if !res[0].fabricated {
		t.Fatalf("AAAA fabricator not flagged: %+v", res[0])
	}
	if !strings.Contains(res[0].detail, "AAAA") {
		t.Errorf("detail should mention AAAA, got %q", res[0].detail)
	}
}

func TestCanarySilentResolverIsNotAFabricator(t *testing.T) {
	addr := fakeDNS(t, func(q []byte) []byte { return nil }, nil)
	res := checkCanaries([]string{addr}, 100*time.Millisecond, 8)
	if res[0].fabricated {
		t.Fatalf("silent resolver flagged as fabricator: %+v", res[0])
	}
	if res[0].answered {
		t.Fatalf("silent resolver marked as answered: %+v", res[0])
	}
	if res[0].errs == 0 {
		t.Fatalf("silent resolver should count errors, got 0")
	}
}

func TestRunCanaryFlagExitsOneOnFabricators(t *testing.T) {
	addr := fakeDNS(t,
		func(q []byte) []byte { return reply(q, 0, 1) },
		nil)
	var out, errOut bytes.Buffer
	code := run([]string{"-canary", "-timeout", "300ms", addr}, &out, &errOut)
	if code != 1 {
		t.Errorf("exit code %d, want 1 (fabricator found)", code)
	}
	if !strings.Contains(errOut.String(), "fabricator") {
		t.Errorf("stderr should carry the fabricator report, got %q", errOut.String())
	}
	if out.Len() != 0 {
		t.Errorf("stdout must stay empty when everything fabricated, got %q", out.String())
	}
}

func TestRunCanaryFlagExitsZeroAndPrintsCleanList(t *testing.T) {
	addr := fakeDNS(t,
		func(q []byte) []byte { return reply(q, 3, 0) },
		nil)
	var out, errOut bytes.Buffer
	code := run([]string{"-canary", "-timeout", "300ms", addr}, &out, &errOut)
	if code != 0 {
		t.Errorf("exit code %d, want 0", code)
	}
	if strings.TrimSpace(out.String()) != addr {
		t.Errorf("clean list = %q, want %q", out.String(), addr)
	}
	if !strings.Contains(errOut.String(), "1/1 clean") {
		t.Errorf("summary missing, got %q", errOut.String())
	}
}
