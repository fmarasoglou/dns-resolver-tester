# dns-resolver-tester

Checks whether a list of DNS resolvers actually answers.

For every resolver in the list it sends a real DNS query (UDP, falling back to
TCP when the answer is truncated) and reports whether the resolver responded,
how long it took, the DNS response code and how many answer records came back.

Go, standard library only, no dependencies.

---

## Running it (Docker)

Build the images first — `docker compose run` does **not** rebuild an existing
image, so rebuild after every code change:

```bash
docker compose build
```

### Check a list of resolvers

```bash
docker compose run --rm tester
```

This uses the compose default: it fetches the public resolver list of
[public-dns.info](https://public-dns.info/) (62,790 resolvers) and checks them
all, which takes a few minutes.

> Note: any argument you pass to `docker compose run` **replaces** the default
> command, so repeat the flags you need.

### Check your own list

Put the list anywhere in this directory (it is mounted at `/resolvers` inside
the container) and point the tool at it:

```bash
docker compose run --rm tester -file /resolvers/mylist.txt
```

Your own list is not tracked by git — `resolvers.txt` is in `.gitignore` — so
it never ends up in the repository.

### Fetch a resolver list from the web

`-fetch` downloads a plain text list of resolvers (one per line) and adds it to
the list to check. It can be combined with `-file` and with command line
arguments, and it can be given more than once.

```bash
# the public resolver list of public-dns.info (62,790 resolvers)
docker compose run --rm tester -fetch https://public-dns.info/nameservers.txt

# your own list plus the public one
docker compose run --rm tester -file /resolvers/mylist.txt \
  -fetch https://public-dns.info/nameservers.txt
```

The fetch is reported on stderr (`fetched 62790 resolvers from ...`), the
duplicates between the sources are removed, and entries that are not IP
addresses are skipped.

### Get only the working resolvers

```bash
# printed to stdout, one per line
docker compose run --rm tester -file /resolvers/mylist.txt -only-ok

# written to a new file in this directory
docker compose run --rm tester -file /resolvers/mylist.txt \
  -only-ok -out /resolvers/working.txt
```

The list contains bare IPs (the default `:53` is dropped, any other port is
kept), sorted numerically and without duplicates:

```
1.0.0.1
1.0.0.19
1.1.1.1
1.1.1.2
```

The summary line (`7855/62607 resolvers responded (...)`) always goes to stderr,
so stdout stays a clean list you can pipe or redirect.

The `tester` service runs as your host user (`UID`/`GID`, default `1000`) so
files written with `-out` belong to you and not to root. Override it with
`docker compose run --rm --user "$(id -u):$(id -g)" tester ...` if your uid is
not 1000.

### Other useful flags

```bash
docker compose run --rm tester -file /resolvers/mylist.txt -type AAAA -timeout 5s
docker compose run --rm tester -file /resolvers/mylist.txt -domain example.org -concurrency 512
```

## Timeout

`-timeout` sets how long a single resolver is given to answer. It is a Go
duration and **needs a unit**:

| Value | Meaning |
| --- | --- |
| `-timeout 1s` | one second |
| `-timeout 500ms` | half a second |
| `-timeout 2m` | two minutes |

`-timeout 1` is rejected with `parse error` — write `1s`.

The timeout is per resolver, and resolvers are checked `-concurrency` at a time
(default 256), so the worst case for a whole list is roughly
`timeout × ceil(resolvers / concurrency)`:

| List | Timeout | Concurrency | Worst case |
| --- | --- | --- | --- |
| 62,607 resolvers (the public list) | `2s` | 256 | ~8 min |
| 62,607 resolvers (the public list) | `1s` | 256 | ~4 min |
| 300 resolvers | `1s` | 256 | ~2 s |

A resolver that is merely slow counts as a failure, so an aggressive timeout
turns slow-but-alive resolvers into `FAIL / timeout after 1s` rows. Raise the
timeout before concluding that a resolver is dead.

## IP family

`-family` decides which addresses are checked:

| Value | Meaning |
| --- | --- |
| `-family ipv4` | only IPv4 resolvers (**default**) |
| `-family ipv6` | only IPv6 resolvers |
| `-family any` | both |

IPv6 addresses are dropped before anything is queried and the count is
reported on stderr (`skipped 183 entries that are not IPv4`). Entries that are
not IP addresses at all are kept, so they still show up as failures.

### Without compose

```bash
docker build --target runtime -t dnsresolvertest .
docker run --rm -v "$PWD":/resolvers dnsresolvertest -file /resolvers/mylist.txt
```

---

## Public resolver lists (public-dns.info)

[public-dns.info](https://public-dns.info/) keeps a database of public
nameservers and offers it for download. The endpoints that are useful here:

| URL | Content |
| --- | --- |
| `https://public-dns.info/nameservers.txt` | 62,790 valid nameservers, one IP per line |
| `https://public-dns.info/nameservers-all.txt` | 99,973 nameservers, including the ones that failed their last check |
| `https://public-dns.info/nameservers.csv` | the valid ones as CSV, with country, AS number, DNSSEC and reliability |
| `https://public-dns.info/nameservers-all.csv` | the same for all nameservers |
| `https://public-dns.info/nameservers.json` | the valid ones as JSON |
| `https://public-dns.info/nameservers-all.json` | the same for all nameservers |

There is no documented JSON API, but the `.json` and `.csv` endpoints work
without a key. The tool itself only reads the plain text lists
(`-fetch` expects one IP per line), which is exactly what `nameservers.txt`
gives you.

The list is a good starting point, but it is not the same thing as "works":
`public-dns.info` marks a resolver valid based on its own periodic checks,
while this tool measures whether the resolver answers *right now*, from your
network, for the domain and type you asked for.

The valid list contains 183 IPv6 addresses, which `-family ipv4` (the default)
skips.

---

## Weekly GitHub Action

`.github/workflows/weekly-resolvers.yml` runs every Monday at 04:17 UTC (and
can be triggered by hand from the Actions tab):

1. builds the image,
2. fetches `https://public-dns.info/nameservers.txt`,
3. checks every resolver with a 2s timeout and 256 in parallel,
4. writes the working list to `working.txt`,
5. commits `working.txt` back to the repository.

The run takes about 4 to 8 minutes. The action needs write permission, which
it requests itself with `permissions: contents: write`.

The workflow must be on the default branch to run. It fails the job if the
check produced an empty list, so a broken fetch never wipes the committed
list.

To run the same thing locally:

```bash
docker build --target runtime -t dnsresolvertest .
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD":/resolvers \
  dnsresolvertest -fetch https://public-dns.info/nameservers.txt \
  -timeout 2s -only-ok -out /resolvers/working.txt
```

---

## Running the tests

```bash
docker compose run --rm test
```

The suite starts a fake DNS server inside the container and exercises the
query, timeout, truncation, TCP fallback and response validation paths. No
internet access and no real resolvers are needed.

---

## Input format

One resolver per line. Blank lines and everything after a `#` are ignored, and
entries may be separated by whitespace or commas.

```
# public resolvers
1.1.1.1
8.8.8.8
9.9.9.9

# with an explicit port
1.1.1.1:5353
[2606:4700:4700::1111]:53
```

Accepted forms: `1.1.1.1`, `1.1.1.1:53`, `2606:4700:4700::1111`,
`[2606:4700:4700::1111]:53`. Hostnames are rejected on purpose: resolving them
would use the system resolver, which is exactly what we are testing.

Resolvers can also be passed as command line arguments, or read from stdin with
`-file -`.

The output of `-only-ok` is in the same format, so it can be fed straight back
into the tool.

---

## Output

Full report (default):

```
RESOLVER          STATUS  TIME     RCODE    ANSWERS  DETAIL
1.0.0.1:53        OK      5.5ms    NOERROR  2        -
1.0.130.68:53     FAIL    2.0018s  -        -        timeout after 2s

7855/62607 resolvers responded (6610 NOERROR, 1083 REFUSED, 144 SERVFAIL, 18 NXDOMAIN)
```

* `STATUS` — `OK` when the resolver answered, `FAIL` when it did not (timeout,
  unreachable, or a reply that was not a valid DNS response).
* `TIME` — round trip time.
* `RCODE` — DNS response code. `NOERROR` means the query was answered
  normally; `REFUSED`/`SERVFAIL`/`NXDOMAIN` mean the resolver is alive but did
  not give a usable answer.
* `ANSWERS` — number of records in the answer section.
* `DETAIL` — why the check failed.

`-only-ok` prints just the addresses that responded, one per line: bare IPs
(the default `:53` is dropped, any other port is kept), sorted numerically
(`1.2.3.4` before `1.10.0.1`) and without duplicates.

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | every resolver responded |
| `1` | at least one resolver did not respond |
| `2` | usage error (bad flags, unreadable file, no resolvers) |

---

## Flags

| Flag | Default | Meaning |
| --- | --- | --- |
| `-file` | – | file with resolvers (`-` for stdin) |
| `-fetch` | – | URL of a plain text resolver list to download (repeatable) |
| `-domain` | `example.com` | domain name to query |
| `-type` | `A` | query type (A, AAAA, MX, TXT, NS, PTR, SRV, CNAME, SOA, HTTPS, SVCB) |
| `-timeout` | `2s` | timeout per resolver (Go duration, unit required: `1s`, `500ms`, `2m`) |
| `-concurrency` | `256` | number of resolvers checked in parallel |
| `-family` | `ipv4` | IP family to check: `ipv4`, `ipv6` or `any` |
| `-only-ok` | `false` | print only the resolvers that responded: bare IPs, sorted, no duplicates |
| `-out` | – | write the output to this file instead of stdout |

The full public list of 62,607 IPv4 resolvers takes about four minutes with
the default settings.

---

## Local development

```bash
go test ./...
go build -o dnsresolvertest .
./dnsresolvertest -file mylist.txt
```

| File | Purpose |
| --- | --- |
| `main.go` | CLI, input parsing, output |
| `dns.go` | DNS wire format, query/response handling |
| `dns_test.go`, `main_test.go` | tests |
| `Dockerfile` | `build`, `runtime` and `test` targets |
| `docker-compose.yml` | `tester` and `test` services |
| `.github/workflows/weekly-resolvers.yml` | weekly check that publishes `working.txt` |

---

This is tooling used for [primitive.host](https://primitive.host).
