# Project guidance for coding agents

## Scope and structure

checkCRT is a Bash CLI for checking a TLS endpoint's certificate chain,
hostname/IP, expiry, and CRL/OCSP revocation status. Read `CONTRIBUTING.md` and
the relevant sections of `README.md` before changing behavior. `SECURITY.md`
describes the trust model and vulnerability-reporting policy.

- `checkCRT.sh`: CLI parsing, TLS/HTTP transport, shared cache, certificate
  verification, and single-host/batch text and JSON output.
- `tests/test_cli.sh`: offline option-parsing and CLI regressions.
- `tests/functional/run.sh`: local PKI integration suite; also invokes the
  standalone OCSP cache, recursive AIA chain, and Axel fallback suites.
- `tests/functional/setup_*.sh` and fixture/wrapper scripts: disposable PKI,
  local responders, request counters, and controlled failure scenarios.
- `README.md`, `CHANGELOG.md`, and `examples/`: user documentation, release
  history, and sample inputs.

## Implementation conventions

- Preserve Bash 4.3+ compatibility and existing Linux/GNU tool assumptions.
  Do not add required runtimes or dependencies without a clear need. Python
  and jq are not runtime dependencies; jq is used only by tests.
- Follow the surrounding Bash style: four-space indentation, local function
  variables, quoted expansions, and arrays for command arguments. Avoid
  `eval` and shell command strings built from hostnames or certificate data.
- Keep changes focused. Inspect the working tree first and preserve unrelated
  user edits, especially domain lists and example files.
- Treat certificate contents, URLs, host inputs, and cache files as untrusted.
  Generate test keys and certificates at test time; do not commit keys,
  credentials, private certificates, or downloaded cache contents.

## Trust and revocation invariants

- Final trust requires OpenSSL verification against configured local trust
  anchors, including hostname/IP and server purpose checks. AIA downloads
  supply untrusted chain material; never install or automatically trust them.
- Match an issuer by its subject and verify that its key signed the child.
  A matching name alone is insufficient. Bound chain traversal and cycles.
- Verify CRL/OCSP signatures and signed freshness before using them as
  evidence. A transport success or cached response alone proves nothing.
- Keep leaf and CA OCSP age policies distinct. Do not extend validity beyond
  signed `nextUpdate` just to improve cache hit rates.
- Missing issuers, failed downloads, and unknown revocation status must not
  become successful verification. Preserve the documented status precedence
  and exit codes.

## Cache and parallel behavior

- Revalidate cache entries for the current certificate/issuer and enforce
  download-age limits. Never cache whole-host verdicts.
- Keep one downloader per shared object. Recheck the cache after taking its
  lock. A five-second lock wait is a polling interval, not permission to
  start a duplicate download while another worker owns the lock.
- Publish cache entries atomically; preserve private directory/file modes.
  Waiting workers must reuse valid completed downloads.
- Keep curl and wget timeout/retry behavior aligned. Retry temporary failures
  only, with the configured exponential delay and six-second cap.
- Axel fallback is optional and GET-only. Keep it within the existing retry
  budget and cache lock, preserve proxy routing, and verify completed data
  before caching. Never treat partial download files as usable evidence.
- Shared failure cooldowns suppress repeated failed requests; they are not
  revocation evidence, never count as hits, and must not hide a valid entry.
- Preserve metrics: a reused verified object is a hit; one attempted object
  fetch is a miss, regardless of retries. Waiting alone is not a miss.
  `--no-cache` records neither. Per-host elapsed time includes lock waits and
  retries, excluding time queued before that host starts.

## Output and documentation

- Keep existing exit-code meanings and JSON field types compatible. In JSON
  mode, stdout contains only JSON/NDJSON and diagnostics go to stderr.
- Preserve sequential/parallel batch behavior and compact table formatting.
  Keep `FINAL STATUS`, batch output, JSON, and their examples consistent.
- For user-visible behavior changes, update `VERSION` in `checkCRT.sh`, the
  version assertion in `tests/test_cli.sh`, `CHANGELOG.md`, and relevant README
  sections together. Documentation-only changes do not need a version bump.

## Verification workflow

Respect explicit user instructions about running or stopping tests. If tests
are prohibited, review statically and report what was not run. Otherwise add
or update meaningful regressions for changes to trust, revocation, caching,
retry behavior, option parsing, or output contracts.

The project's complete check, matching CI, is:

```bash
bash -n checkCRT.sh
shellcheck -s bash checkCRT.sh tests/test_cli.sh tests/functional/*.sh
./tests/test_cli.sh
./tests/functional/run.sh
```

ShellCheck must report zero warnings. Functional tests require OpenSSL, jq,
curl, wget, Axel, and BusyBox with `httpd`, and bind local TCP ports. They generate disposable
certificates and do not need public Internet access. Request the appropriate
sandbox permission if local listeners are blocked; do not treat that as a
product failure. Prefer these reproducible fixtures over live domains.

Report what changed, checks actually run, and remaining limitations. Do not
claim a live site was verified based only on fixtures. Commit and push when
the user requests them; never include unrelated edits.
