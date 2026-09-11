# Contributing

Please keep changes focused and add or update a regression test when changing
status handling, option parsing, revocation/trust logic, or output format
(text, JSON, or the batch summary table).

## Before opening a pull request

Run the full check locally — this is exactly what CI (`.github/workflows/ci.yml`)
runs on every push and pull request:

```bash
bash -n checkCRT.sh
shellcheck -s bash checkCRT.sh tests/functional/run.sh tests/functional/setup_pki.sh tests/test_cli.sh
./tests/test_cli.sh
./tests/functional/run.sh
```

All four must pass cleanly (shellcheck must report zero warnings, not just no
errors — CI fails on warnings too).

- **`tests/test_cli.sh`** — fast, offline checks of argument parsing and
  validation (`--help`, `--version`, error messages). No network needed.
- **`tests/functional/run.sh`** — end-to-end checks against a local,
  disposable PKI (`tests/functional/setup_pki.sh` builds a throwaway root CA,
  two intermediates, and several leaves) served over `openssl s_server` and a
  local `http.server` on `127.0.0.1`. It exercises revocation (leaf and
  intermediate), the AIA chain-recovery path, the OCSP-stapling retry
  fallback, and `--hosts-file` batch mode (both sequential and parallel),
  asserting exit codes and specific output. It makes no real network
  requests, but it does bind local TCP ports, so in a sandboxed environment
  you may need to grant permission for that.

If you change how a certificate scenario should be handled (a new trust
nuance, a new revocation case, a new CLI option), prefer adding a case to
`tests/functional/setup_pki.sh` + `tests/functional/run.sh` over only
verifying by hand against a live site — live sites drift and aren't
reproducible in CI.

## Versioning and changelog

- Bump `VERSION` in `checkCRT.sh` for any user-visible change (new option,
  changed output format, changed default behavior, bug fix that changes
  results) — see `CHANGELOG.md` for the granularity this project has used so
  far (roughly: new capability or behavior change → minor version; small
  formatting/wording fix → patch version).
- Update the matching `grep -q '^checkCRT.sh X\.Y\.Z$'` assertion in
  `tests/test_cli.sh` in the same commit, or `./tests/test_cli.sh` will fail.
- Add a `CHANGELOG.md` entry under a new version heading describing the
  change from a user's perspective (what changed and why it matters), not a
  diff summary.

## Documentation

Update `README.md` alongside any behavior change — this project treats stale
docs as a bug. In particular keep these in sync:
- The exit-code table and the `FINAL STATUS` text block, if either changes.
- The `--hosts-file`/batch-mode section and the `BATCH SUMMARY` example, if
  the summary format or ordering changes.
- The `## Advisory checks` and `## Revocation checks` sections, if a new
  advisory warning or revocation nuance is added.
- `examples/README.md`, if you add or change a file under `examples/`.

## Compatibility

- Don't change the meaning of an existing exit code or JSON field without a
  strong reason — scripts and monitoring may depend on them. Prefer adding a
  new opt-in flag (see `--fail-on-expiry-warning` for the pattern) over
  silently changing default behavior.
- This project currently requires Bash 4.3+ (needed for `wait -n`, used by
  `--hosts-file`'s default parallel mode). Avoid introducing a dependency on
  a newer Bash feature without discussion; support for other Bash versions
  matters more than any convenience one feature might offer.
- Avoid adding new required external tools. Optional tools (`dig`/`host`/
  `nslookup` for CAA, `curl`/`wget` for HTTP fetches) must degrade gracefully
  and clearly when absent, not fail hard.

## Security-sensitive changes

Do not commit private certificates, private keys, or credentials. Test
certificates and keys must be generated at test time (see
`tests/functional/setup_pki.sh`) — never checked into the repository, not
even as "obviously fake" fixtures.

If a change affects how trust, revocation, or hostname verification is
decided, call that out explicitly in the PR description and explain the
security reasoning, not just the mechanics — see `SECURITY.md` for the
project's scope and trust-store assumptions.
