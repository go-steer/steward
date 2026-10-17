# AGENTS.md — steward

Instructions for AI agents working in this repository.

## Start here

[`README.md`](./README.md) for what steward is, and
[`docs/DESIGN.md`](./docs/DESIGN.md) for the design this module implements:
how it sits on purser, Path A (the client holds the user's Google token)
and Path B (the service is its own authorization server), and the phase
plan. Read the design before adding to the exported surface, and keep it
current in the same PR as the API change it describes.

## What this project is

A Go **library**, `github.com/go-steer/steward`, consumed as a module by
go-steer services that accept people's Google access tokens and act as
those people. It ships no binary and no image. Its product is the exported
API.

## Hard rules (violations are bugs)

- **Never accept a token issued to someone else's client.** Every accepted
  access token was issued to one of the service's configured OAuth clients
  (`aud` or `azp`). This is what stops a service from replaying a grant the
  user gave another app.
- **The token never leaves the request.** Not in a log line, not in an error
  string, not as a cache key (hash it), not in storage. Tests plant a token
  and assert it appears nowhere.
- **Google failing is not Google refusing.** No answer, 429 and 5xx are
  retryable errors and are never cached as refusals.
- **A domain needs Google's word.** `@domain` admission matches Google's
  `hd`, never the email suffix.
- **No service policy.** Roles, tool lists and resource scopes belong to the
  consuming service. steward supplies identity, admission and the token
  source, like purser, and stays out of the vocabulary.
- **No fallback identity.** A refused request is refused; steward never
  substitutes the service's own identity for a person's.
- **The caller contract is purser's.** Identity reaches the service as a
  `purser.Caller` through purser's middleware, not through a parallel
  steward type. If purser lacks something steward needs, add it to purser.

## Build & test

```bash
dev/tools/ci                # full local presubmit sweep, fast-fail order
dev/ci/presubmits/build     # go build ./...
dev/ci/presubmits/test-unit # go test -race ./...
dev/ci/presubmits/vet       # go vet ./...
dev/ci/presubmits/lint-go   # golangci-lint (auto-installs the pinned version)
dev/ci/presubmits/verify-go-format  # gofmt + goimports (fix: dev/tools/fix-go-format)
dev/ci/presubmits/verify-mod-tidy   # go.mod/go.sum are tidy
dev/ci/presubmits/verify-apidiff    # exported-API diff vs the last release tag
dev/ci/presubmits/verify-coverage   # per-package floors (dev/coverage-floors.txt)
dev/ci/presubmits/verify-vuln       # govulncheck
dev/ci/presubmits/verify-no-agent-attribution  # no assistant attribution
```

The default test run needs no network and no credentials. Google's
endpoints are `httptest` servers; never call real Google from a test.

## Conventions

- Mirror `purser` / `core-agent` conventions (package layout, `dev/`
  tooling); a maintainer of one repo should recognize the others. Fixes
  should be one-line ports. Code moved from supercargo keeps its tests;
  code taken from kode-gopher records the commit it came from.
- **License headers everywhere.** The Apache 2.0 boilerplate attributed to
  Google LLC sits atop every Go / shell / YAML source file. Markdown carries
  no header. `goheader` enforces it on `.go`; run
  `dev/tools/add-license-headers` for the rest.
- **Conventional Commits**, small self-contained commits, bodies explaining
  *why* + the verification done. **DCO sign-off** (`git commit -s`).
- **No `Co-Authored-By` trailer and no assistant attribution** — in commits,
  PR titles/bodies, or any committed/published artifact. Author under your
  own name. `verify-no-agent-attribution` and the `agent-attribution`
  workflow enforce it. See [`CONTRIBUTING.md`](./CONTRIBUTING.md).
- **Tests before merging.** Every new package ships unit tests; a bug fix
  ships a regression test. A new package also needs a floor in
  `dev/coverage-floors.txt` — `verify-coverage` fails on a package that has
  none. Lowering an existing floor belongs in the same PR as the code that
  made it necessary, with a comment saying why.

## How we develop

Single long-lived branch `main`; short-lived `feat/…` `fix/…` `chore/…`
`docs/…` branches → PR → merge once the required CI checks are green.
Rebase, don't merge; `--force-with-lease` on your own branch is fine, never
force-push `main`. Full contributor flow + DCO in
[`CONTRIBUTING.md`](./CONTRIBUTING.md).

- **Run presubmits before every push.** `dev/tools/ci` runs the same scripts
  CI runs (`dev/ci/presubmits/*`).
- **Adversarial-review gate before every PR touching Go code.** Run a skeptic
  subagent over the staged diff (correctness, races, API misuse — verified
  against real dependency source, not memory), fix or pin every finding, and
  record the outcome in the PR body under an `## Adversarial review` heading.
  For bug fixes, also verify the new regression test FAILS on the pre-fix
  code. Enforced by the `review-gate` required CI check (docs-only and bot
  PRs exempt). `dev/claude/settings-review-gate.json` is an opt-in local
  hook.
- **Admin merge protocol.** `gh pr merge <N> --admin --squash` once CI is
  green. Not a way to skip review: the adversarial gate plus green CI are
  the review on this single-maintainer repo.
- **The exported API is the product.** `dev/tools/verify-apidiff` reports
  every change since the last release tag and fails on incompatible ones
  `dev/api-breaks.txt` does not acknowledge.
- **`[Unreleased]` grows on every merged PR.** Any user-visible change adds a
  bullet under `## [Unreleased]` in `CHANGELOG.md`.
- **Harness settings are not committed.** `.claude/` and a personal
  `CLAUDE.md` are git-ignored; the only checked-in Claude Code config is the
  opt-in sample under `dev/claude/`.

## Current state

**v0.2.0: Path A and Path B.** v0.1.0 shipped Path A: `googletoken` (the
verifier and a purser authenticator, moved from supercargo), `allow`,
`httpauth` (the Protector: purser's enforced middleware, the token source,
RFC 9728 metadata) and `mcpauth` (SDK session binding and per-call
tokens), on purser v0.2.0. v0.2.0 adds Path B for k8s-lookout#702:
`allow` groups (`CloudIdentityGroups`, `Admitter`), `seal` (rotatable AEAD
envelopes; Secret Manager keys in `seal/secretmanager`), `authserver`
(the OAuth 2.1 authorization server: DCR, CIMD, static clients, PKCE,
resource indicators, client credentials, vault and sealed custody,
refresh-token families) and both token kinds in one `httpauth.Protector`
and `mcpauth`. `allow`'s group checker, `seal` and `authserver` are taken
from kode-gopher at `8b53617`, which will not import steward: port fixes
by hand in both directions (DESIGN.md lists the ones made here).
supercargo keeps its own `googletoken` copy for now. Later: `signin`. See
the phase table in [`docs/DESIGN.md`](./docs/DESIGN.md).
