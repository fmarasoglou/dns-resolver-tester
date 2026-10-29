package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"text/tabwriter"
	"time"
	"unicode"
)

var queryTypes = map[string]uint16{
	"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15,
	"TXT": 16, "AAAA": 28, "SRV": 33, "SVCB": 64, "HTTPS": 65,
}

type options struct {
	file        string
	domain      string
	qtype       string
	timeout     time.Duration
	concurrency int
	onlyOK      bool
	outFile     string
	family      string
	canary      bool
	fetch       stringList
}

// stringList is a flag that can be given more than once.
type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }

func (s *stringList) Set(v string) error {
	*s = append(*s, v)
	return nil
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, out, errOut io.Writer) int {
	var o options
	fs := flag.NewFlagSet("dnsresolvertest", flag.ContinueOnError)
	fs.SetOutput(out)
	fs.StringVar(&o.file, "file", "", "file with resolvers, one per line ('-' for stdin)")
	fs.StringVar(&o.domain, "domain", "example.com", "domain name to query")
	fs.StringVar(&o.qtype, "type", "A", "query type (A, AAAA, MX, TXT, ...)")
	fs.DurationVar(&o.timeout, "timeout", 2*time.Second, "timeout per resolver")
	fs.IntVar(&o.concurrency, "concurrency", 256, "resolvers checked in parallel")
	fs.BoolVar(&o.onlyOK, "only-ok", false, "print only the resolvers that responded, one per line")
	fs.StringVar(&o.outFile, "out", "", "write the output to this file instead of stdout")
	fs.Var(&o.fetch, "fetch", "URL of a plain text resolver list to download (can be given more than once)")
	fs.StringVar(&o.family, "family", "ipv4", "IP family to check: ipv4, ipv6 or any")
	fs.BoolVar(&o.canary, "canary", false, "stage-1 fabrication check: ask each resolver only for names that cannot exist and drop it if it answers with records (clean list on stdout/-out, report on stderr; exit 1 when fabricators are found)")
	fs.Usage = func() {
		fmt.Fprintf(out, "usage: dnsresolvertest [flags] [resolver ...]\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}

	qtype, ok := queryTypes[strings.ToUpper(o.qtype)]
	if !ok {
		fmt.Fprintf(out, "unknown query type %q\n", o.qtype)
		return 2
	}
	if o.domain == "" {
		fmt.Fprintln(out, "domain must not be empty")
		return 2
	}
	if o.concurrency < 1 {
		fmt.Fprintln(out, "concurrency must be at least 1")
		return 2
	}
	switch o.family {
	case "ipv4", "ipv6", "any":
	default:
		fmt.Fprintf(out, "unknown IP family %q, use ipv4, ipv6 or any\n", o.family)
		return 2
	}

	entries, err := collectEntries(o.file, fs.Args())
	if err != nil {
		fmt.Fprintf(out, "error: %v\n", err)
		return 2
	}
	var dropped int
	for _, url := range o.fetch {
		fetched, err := fetchResolvers(url)
		if err != nil {
			fmt.Fprintf(errOut, "error: %v\n", err)
			return 2
		}
		kept, skipped := keepResolvers(fetched)
		fmt.Fprintf(errOut, "fetched %d resolvers from %s", len(kept), url)
		if skipped > 0 {
			fmt.Fprintf(errOut, " (%d skipped, not an IP address)", skipped)
		}
		fmt.Fprintln(errOut)
		entries = append(entries, kept...)
	}
	entries = dedupe(entries)
	entries, dropped = filterFamily(entries, o.family)
	if dropped > 0 {
		fmt.Fprintf(errOut, "skipped %d entries that are not %s\n", dropped, familyLabel(o.family))
	}
	if len(entries) == 0 {
		fs.Usage()
		return 2
	}

	if o.canary {
		// Clean list to -out or stdout, fabricator report + summary to stderr,
		// so the list keeps the same pipeable contract as -only-ok.
		canaryListOut := out
		if o.outFile != "" {
			f, err := os.Create(o.outFile)
			if err != nil {
				fmt.Fprintf(errOut, "error: %v\n", err)
				return 2
			}
			defer f.Close()
			canaryListOut = f
		}
		cres := checkCanaries(entries, o.timeout, o.concurrency)
		printCanaries(canaryListOut, errOut, cres)
		for _, r := range cres {
			if r.fabricated {
				return 1
			}
		}
		return 0
	}

	results := checkAll(entries, question{name: o.domain, qtype: qtype}, o.timeout, o.concurrency)
	listOut, summaryOut := out, out
	if o.onlyOK {
		// Keep stdout a clean list of resolvers.
		summaryOut = errOut
	}
	if o.outFile != "" {
		f, err := os.Create(o.outFile)
		if err != nil {
			fmt.Fprintf(errOut, "error: %v\n", err)
			return 2
		}
		defer f.Close()
		listOut, summaryOut = f, errOut
	}
	if o.onlyOK {
		printWorking(listOut, summaryOut, results)
	} else {
		printResults(listOut, summaryOut, results)
	}
	return exitCode(results)
}

// familyLabel turns the -family value into something readable.
func familyLabel(family string) string {
	switch family {
	case "ipv4":
		return "IPv4"
	case "ipv6":
		return "IPv6"
	}
	return "IPv4 or IPv6"
}

// collectEntries gathers resolvers from the file and/or the command line.
func collectEntries(file string, args []string) ([]string, error) {
	var entries []string
	if file != "" {
		var data []byte
		var err error
		if file == "-" {
			data, err = io.ReadAll(os.Stdin)
		} else {
			data, err = os.ReadFile(file)
		}
		if err != nil {
			return nil, err
		}
		entries = append(entries, splitList(string(data))...)
	}
	entries = append(entries, args...)
	return entries, nil
}

// fetchTimeout is the time budget for downloading a resolver list.
const fetchTimeout = 60 * time.Second

// maxFetchBytes caps how much of a downloaded list is read.
const maxFetchBytes = 64 << 20

// fetchResolvers downloads a plain text list of resolvers, one per line.
func fetchResolvers(url string) ([]string, error) {
	client := &http.Client{Timeout: fetchTimeout}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "dns-resolver-tester")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s returned %s", url, resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxFetchBytes))
	if err != nil {
		return nil, err
	}
	return splitList(string(body)), nil
}

// keepResolvers drops the entries that are not IP addresses and returns how
// many were dropped.
func keepResolvers(entries []string) ([]string, int) {
	out := make([]string, 0, len(entries))
	skipped := 0
	for _, e := range entries {
		if _, _, err := parseResolver(e); err != nil {
			skipped++
			continue
		}
		out = append(out, e)
	}
	return out, skipped
}

// filterFamily drops the resolvers that are not of the wanted IP family and
// returns how many were dropped. Entries that are not IP addresses at all are
// kept, so they still show up as failures.
func filterFamily(entries []string, family string) ([]string, int) {
	if family == "any" {
		return entries, 0
	}
	out := make([]string, 0, len(entries))
	dropped := 0
	for _, e := range entries {
		host, _, err := parseResolver(e)
		if err != nil {
			out = append(out, e)
			continue
		}
		ip := net.ParseIP(host)
		isV4 := ip != nil && ip.To4() != nil
		if (family == "ipv4") != isV4 {
			dropped++
			continue
		}
		out = append(out, e)
	}
	return out, dropped
}

// dedupe removes repeated entries, keeping the first occurrence.
func dedupe(entries []string) []string {
	seen := make(map[string]bool, len(entries))
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		if seen[e] {
			continue
		}
		seen[e] = true
		out = append(out, e)
	}
	return out
}

// splitList splits a resolver list into entries. Blank lines and everything
// after a '#' are ignored; entries may be separated by whitespace or commas.
func splitList(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		for _, f := range strings.FieldsFunc(line, func(r rune) bool {
			return r == ',' || unicode.IsSpace(r)
		}) {
			out = append(out, f)
		}
	}
	return out
}

// parseResolver turns "1.1.1.1", "1.1.1.1:53" or "[2606:4700::1111]:53"
// into a host/port pair. Hostnames are not accepted: they would need the
// system resolver, which is exactly what we are trying to avoid.
func parseResolver(s string) (string, int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", 0, fmt.Errorf("empty resolver")
	}
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		s = s[1 : len(s)-1]
	}
	if ip := net.ParseIP(s); ip != nil {
		return s, 53, nil
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return "", 0, fmt.Errorf("not an IP address: %q", s)
	}
	if net.ParseIP(host) == nil {
		return "", 0, fmt.Errorf("not an IP address: %q", host)
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return "", 0, fmt.Errorf("invalid port: %q", port)
	}
	return host, p, nil
}

type result struct {
	addr    string
	resp    *dnsResponse
	elapsed time.Duration
	err     error
}

// checkAll queries every resolver, at most concurrency at a time.
func checkAll(entries []string, q question, timeout time.Duration, concurrency int) []result {
	results := make([]result, len(entries))
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
				results[i] = result{addr: entry, err: err}
				return
			}
			addr := net.JoinHostPort(host, strconv.Itoa(port))
			resp, elapsed, err := queryResolver(addr, q, timeout)
			results[i] = result{addr: addr, resp: resp, elapsed: elapsed, err: err}
		}(i, entry)
	}
	wg.Wait()
	return results
}

func printResults(table, summary io.Writer, results []result) {
	w := tabwriter.NewWriter(table, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "RESOLVER\tSTATUS\tTIME\tRCODE\tANSWERS\tDETAIL")
	for _, r := range results {
		if r.err != nil {
			fmt.Fprintf(w, "%s\tFAIL\t%s\t-\t-\t%s\n", r.addr, r.elapsed.Round(100*time.Microsecond), r.err)
			continue
		}
		fmt.Fprintf(w, "%s\tOK\t%s\t%s\t%d\t-\n", r.addr, r.elapsed.Round(100*time.Microsecond),
			rcodeName(r.resp.rcode), r.resp.answers)
	}
	w.Flush()
	writeSummary(summary, results)
}

// printWorking prints only the resolvers that responded: bare IPs, sorted and
// without duplicates, so the output can be piped elsewhere or fed back into the
// tool. The summary goes to errOut to keep stdout a clean list.
func printWorking(out, errOut io.Writer, results []result) {
	seen := map[string]bool{}
	working := []string{}
	for _, r := range results {
		if r.err != nil {
			continue
		}
		addr := stripDefaultPort(r.addr)
		if seen[addr] {
			continue
		}
		seen[addr] = true
		working = append(working, addr)
	}
	sort.Slice(working, func(i, j int) bool { return lessIP(working[i], working[j]) })
	for _, addr := range working {
		fmt.Fprintln(out, addr)
	}
	writeSummary(errOut, results)
}

// stripDefaultPort drops the ":53" suffix but keeps any other port.
func stripDefaultPort(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || port != "53" {
		return addr
	}
	return host
}

// lessIP orders addresses numerically (1.2.3.4 before 1.10.0.1), not
// alphabetically.
func lessIP(a, b string) bool {
	ipA, ipB := net.ParseIP(a), net.ParseIP(b)
	if ipA == nil || ipB == nil {
		return a < b
	}
	if c := bytes.Compare(ipA.To16(), ipB.To16()); c != 0 {
		return c < 0
	}
	return a < b
}

// summarize counts the responders and their response codes.
func summarize(results []result) (int, map[string]int) {
	responded := 0
	rcodes := map[string]int{}
	for _, r := range results {
		if r.err != nil {
			continue
		}
		responded++
		rcodes[rcodeName(r.resp.rcode)]++
	}
	return responded, rcodes
}

// writeSummary reports how many resolvers responded, broken down by rcode.
func writeSummary(w io.Writer, results []result) {
	responded, rcodes := summarize(results)
	fmt.Fprintf(w, "\n%d/%d resolvers responded", responded, len(results))
	if len(rcodes) > 0 {
		fmt.Fprintf(w, " (%s)", breakdown(rcodes))
	}
	fmt.Fprintln(w)
}

// breakdown renders rcode counts, most frequent first.
func breakdown(rcodes map[string]int) string {
	type entry struct {
		name  string
		count int
	}
	entries := make([]entry, 0, len(rcodes))
	for name, count := range rcodes {
		entries = append(entries, entry{name, count})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].count != entries[j].count {
			return entries[i].count > entries[j].count
		}
		return entries[i].name < entries[j].name
	})
	parts := make([]string, 0, len(entries))
	for _, e := range entries {
		parts = append(parts, fmt.Sprintf("%d %s", e.count, e.name))
	}
	return strings.Join(parts, ", ")
}

// exitCode is non-zero when at least one resolver did not answer.
func exitCode(results []result) int {
	for _, r := range results {
		if r.err != nil {
			return 1
		}
	}
	return 0
}
