package main

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestRunAgainstFakeResolver(t *testing.T) {
	addr := fakeDNS(t,
		func(q []byte) []byte { return reply(q, 0, 1) },
		func(q []byte) []byte { return reply(q, 0, 1) },
	)
	list := filepath.Join(t.TempDir(), "resolvers.txt")
	if err := os.WriteFile(list, []byte("# list\n"+addr+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	code := run([]string{"-file", list, "-timeout", "2s"}, &out, &bytes.Buffer{})
	if code != 0 {
		t.Errorf("exit code = %d, want 0 (output: %s)", code, out.String())
	}
	for _, want := range []string{"RESOLVER", "OK", "NOERROR", "1/1 resolvers responded"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output missing %q:\n%s", want, out.String())
		}
	}
}

func TestRunFailsWhenResolverIsSilent(t *testing.T) {
	addr := fakeDNS(t, func(q []byte) []byte { return nil }, func(q []byte) []byte { return nil })

	var out bytes.Buffer
	code := run([]string{"-timeout", "200ms", addr}, &out, &bytes.Buffer{})
	if code != 1 {
		t.Errorf("exit code = %d, want 1 (output: %s)", code, out.String())
	}
	if !strings.Contains(out.String(), "FAIL") {
		t.Errorf("output missing FAIL:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "0/1 resolvers responded") {
		t.Errorf("output missing summary:\n%s", out.String())
	}
}

func TestRunRejectsUnknownType(t *testing.T) {
	var out bytes.Buffer
	if code := run([]string{"-type", "NOPE", "1.1.1.1"}, &out, &bytes.Buffer{}); code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}
}

func TestRunWithoutResolvers(t *testing.T) {
	var out bytes.Buffer
	if code := run(nil, &out, &bytes.Buffer{}); code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}
}

func TestRunOnlyOKPrintsWorkingResolvers(t *testing.T) {
	good := fakeDNS(t,
		func(q []byte) []byte { return reply(q, 0, 1) },
		func(q []byte) []byte { return reply(q, 0, 1) },
	)
	dead := fakeDNS(t, func(q []byte) []byte { return nil }, func(q []byte) []byte { return nil })

	var out, errOut bytes.Buffer
	code := run([]string{"-only-ok", "-timeout", "200ms", good, dead}, &out, &errOut)
	if code != 1 {
		t.Errorf("exit code = %d, want 1 (one resolver did not respond)", code)
	}
	if got := strings.TrimSpace(out.String()); got != good {
		t.Errorf("stdout = %q, want %q", got, good)
	}
	if !strings.Contains(errOut.String(), "1/2 resolvers responded") {
		t.Errorf("summary missing from stderr: %q", errOut.String())
	}
}

func TestRunOnlyOKSortsAndDeduplicates(t *testing.T) {
	first := fakeDNS(t,
		func(q []byte) []byte { return reply(q, 0, 1) },
		func(q []byte) []byte { return reply(q, 0, 1) },
	)
	second := fakeDNS(t,
		func(q []byte) []byte { return reply(q, 0, 1) },
		func(q []byte) []byte { return reply(q, 0, 1) },
	)
	// first appears twice, second once
	var out, errOut bytes.Buffer
	run([]string{"-only-ok", "-timeout", "1s", second, first, first}, &out, &errOut)

	want := []string{first, second}
	sort.Strings(want)
	got := strings.Fields(out.String())
	if len(got) != len(want) {
		t.Fatalf("stdout = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("stdout = %v, want %v", got, want)
		}
	}
}

func TestStripDefaultPort(t *testing.T) {
	tests := map[string]string{
		"1.1.1.1:53":           "1.1.1.1",
		"1.1.1.1:5353":         "1.1.1.1:5353",
		"[2606:4700::1111]:53": "2606:4700::1111",
		"1.1.1.1":              "1.1.1.1",
		// an unbracketed IPv6 with a port is ambiguous, leave it alone
		"2606:4700::1111:53": "2606:4700::1111:53",
	}
	for in, want := range tests {
		if got := stripDefaultPort(in); got != want {
			t.Errorf("stripDefaultPort(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLessIPIsNumeric(t *testing.T) {
	if !lessIP("1.2.3.4", "1.10.0.1") {
		t.Error("1.2.3.4 should sort before 1.10.0.1")
	}
	if lessIP("1.10.0.1", "1.2.3.4") {
		t.Error("1.10.0.1 should not sort before 1.2.3.4")
	}
	if !lessIP("1.1.1.1", "2606:4700::1111") {
		t.Error("IPv4 should sort before IPv6")
	}
}

// listServer serves a fake plain text resolver list at /list.txt.
func listServer(t *testing.T, body string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/list.txt" {
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestFetchResolvers(t *testing.T) {
	url := listServer(t, "# comment\n1.1.1.1\n8.8.8.8\n")
	got, err := fetchResolvers(url + "/list.txt")
	if err != nil {
		t.Fatalf("fetchResolvers: %v", err)
	}
	want := []string{"1.1.1.1", "8.8.8.8"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("fetchResolvers = %v, want %v", got, want)
	}
}

func TestFetchResolversHTTPError(t *testing.T) {
	url := listServer(t, "")
	if _, err := fetchResolvers(url + "/missing"); err == nil {
		t.Fatal("expected an error for a 404 response")
	}
}

func TestKeepResolvers(t *testing.T) {
	got, skipped := keepResolvers([]string{"1.1.1.1", "dns.google", "8.8.8.8:53", ""})
	if skipped != 2 {
		t.Errorf("skipped = %d, want 2", skipped)
	}
	if len(got) != 2 || got[0] != "1.1.1.1" || got[1] != "8.8.8.8:53" {
		t.Errorf("keepResolvers = %v, want [1.1.1.1 8.8.8.8:53]", got)
	}
}

func TestDedupe(t *testing.T) {
	got := dedupe([]string{"1.1.1.1", "8.8.8.8", "1.1.1.1", "9.9.9.9", "8.8.8.8"})
	want := []string{"1.1.1.1", "8.8.8.8", "9.9.9.9"}
	if len(got) != len(want) {
		t.Fatalf("dedupe = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("dedupe = %v, want %v", got, want)
		}
	}
}

func TestFilterFamily(t *testing.T) {
	entries := []string{"1.1.1.1", "2606:4700:4700::1111", "[2606:4700:4700::1111]:53", "not-an-ip"}

	got, dropped := filterFamily(entries, "ipv4")
	if dropped != 2 {
		t.Errorf("dropped = %d, want 2", dropped)
	}
	if len(got) != 2 || got[0] != "1.1.1.1" || got[1] != "not-an-ip" {
		t.Errorf("filterFamily(ipv4) = %v, want [1.1.1.1 not-an-ip]", got)
	}

	got, dropped = filterFamily(entries, "ipv6")
	if dropped != 1 {
		t.Errorf("dropped = %d, want 1", dropped)
	}
	if len(got) != 3 {
		t.Errorf("filterFamily(ipv6) = %v, want 3 entries", got)
	}

	got, dropped = filterFamily(entries, "any")
	if dropped != 0 || len(got) != len(entries) {
		t.Errorf("filterFamily(any) = %v (%d dropped), want all entries", got, dropped)
	}
}

func TestRunFetchesList(t *testing.T) {
	good := fakeDNS(t,
		func(q []byte) []byte { return reply(q, 0, 1) },
		func(q []byte) []byte { return reply(q, 0, 1) },
	)
	// the second line is not an IP address and must be dropped
	url := listServer(t, good+"\nnot-an-ip\n")

	var out, errOut bytes.Buffer
	code := run([]string{"-fetch", url + "/list.txt", "-only-ok", "-timeout", "1s"}, &out, &errOut)
	if code != 0 {
		t.Errorf("exit code = %d, want 0 (output: %s, err: %s)", code, out.String(), errOut.String())
	}
	if got := strings.TrimSpace(out.String()); got != good {
		t.Errorf("stdout = %q, want %q", got, good)
	}
	if !strings.Contains(errOut.String(), "fetched 1 resolvers") {
		t.Errorf("fetch summary missing: %q", errOut.String())
	}
	if !strings.Contains(errOut.String(), "1 skipped") {
		t.Errorf("skipped count missing: %q", errOut.String())
	}
}

func TestRunWritesWorkingListToFile(t *testing.T) {
	good := fakeDNS(t,
		func(q []byte) []byte { return reply(q, 0, 1) },
		func(q []byte) []byte { return reply(q, 0, 1) },
	)
	dead := fakeDNS(t, func(q []byte) []byte { return nil }, func(q []byte) []byte { return nil })
	path := filepath.Join(t.TempDir(), "working.txt")

	var out, errOut bytes.Buffer
	code := run([]string{"-only-ok", "-out", path, "-timeout", "200ms", good, dead}, &out, &errOut)
	if code != 1 {
		t.Errorf("exit code = %d, want 1 (one resolver did not respond)", code)
	}
	if out.Len() != 0 {
		t.Errorf("stdout = %q, want empty", out.String())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(data)); got != good {
		t.Errorf("file = %q, want %q", got, good)
	}
}
