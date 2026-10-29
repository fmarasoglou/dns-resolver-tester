package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"sort"
	"strconv"
	"sync"
	"time"
)

// Stage 1 of the fabrication check (research doc §13: NXDOMAIN canaries, the
// fast kill). Every resolver is asked for names that MUST NOT exist: a random
// label under a verified non-wildcard anchor (example.com, google.com — both
// verified to return NXDOMAIN for garbage) plus an RFC 6761 reserved
// .invalid name. A resolver that returns records instead of NXDOMAIN/empty is
// fabricating answers and is dropped from the clean list.
//
// The measured defect this catches: 2/12 garbage names resolved to fake A
// records through the current public-dns.info working.txt pool.

// canaryQuestions builds the per-resolver set of must-fail lookups.
func canaryQuestions() []question {
	r1 := randLabel()
	r2 := randLabel()
	r3 := randLabel()
	return []question{
		{name: r1 + ".example.com", qtype: queryTypes["A"]},
		{name: r2 + ".google.com", qtype: queryTypes["A"]},
		{name: "zz" + r3 + ".invalid", qtype: queryTypes["A"]},
		{name: "zz" + r3 + ".invalid", qtype: queryTypes["AAAA"]},
	}
}

// randLabel returns 16 hex characters of cryptographic randomness.
func randLabel() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failing is not recoverable; fall back to time so a
		// canary name is still unique enough for the check.
		return hex.EncodeToString([]byte(strconv.FormatInt(time.Now().UnixNano(), 16)))
	}
	return hex.EncodeToString(b[:])
}

// qtypeName maps a numeric query type back to its mnemonic.
func qtypeName(t uint16) string {
	for name, code := range queryTypes {
		if code == t {
			return name
		}
	}
	return fmt.Sprintf("TYPE%d", t)
}

type canaryResult struct {
	addr       string
	answered   bool   // at least one canary got a DNS reply
	fabricated bool   // returned records for a name that cannot exist
	detail     string // first fabricating lookup, for the report
	errs       int    // canaries that timed out or failed to reply
}

// checkCanaries asks every resolver the must-fail questions. A fabricator is
// decided as soon as the first canary gets records; remaining questions for
// that resolver are skipped.
func checkCanaries(entries []string, timeout time.Duration, concurrency int) []canaryResult {
	results := make([]canaryResult, len(entries))
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for i, entry := range entries {
		wg.Add(1)
		go func(i int, entry string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			host, port, err := parseResolver(entry)
			if err != nil {
				results[i] = canaryResult{addr: entry}
				return
			}
			addr := net.JoinHostPort(host, strconv.Itoa(port))
			res := canaryResult{addr: addr}
			for _, q := range canaryQuestions() {
				resp, _, err := queryResolver(addr, q, timeout)
				if err != nil {
					res.errs++
					continue
				}
				res.answered = true
				if resp.rcode == 0 && resp.answers > 0 {
					res.fabricated = true
					res.detail = fmt.Sprintf("%s %s -> %d answer(s)", q.name, qtypeName(q.qtype), resp.answers)
					break // fast kill
				}
			}
			results[i] = res
		}(i, entry)
	}
	wg.Wait()
	return results
}

// printCanaries writes the clean list (answered at least one canary, never
// fabricated) to out, and the fabricator report + summary to summaryOut.
func printCanaries(out, summaryOut io.Writer, results []canaryResult) {
	seen := map[string]bool{}
	clean := []string{}
	fabricators := []canaryResult{}
	silent := 0
	for _, r := range results {
		if r.fabricated {
			fabricators = append(fabricators, r)
			continue
		}
		if !r.answered {
			silent++
			continue
		}
		addr := stripDefaultPort(r.addr)
		if seen[addr] {
			continue
		}
		seen[addr] = true
		clean = append(clean, addr)
	}
	sort.Slice(clean, func(i, j int) bool { return lessIP(clean[i], clean[j]) })
	for _, addr := range clean {
		fmt.Fprintln(out, addr)
	}
	sort.Slice(fabricators, func(i, j int) bool { return lessIP(fabricators[i].addr, fabricators[j].addr) })
	for _, r := range fabricators {
		fmt.Fprintf(summaryOut, "fabricator %s: %s\n", r.addr, r.detail)
	}
	fmt.Fprintf(summaryOut, "\ncanary check: %d/%d clean, %d fabricators dropped, %d silent\n",
		len(clean), len(results), len(fabricators), silent)
}
