# Changelog

All notable changes to this module are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the module
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html); before
1.0, a minor version may change the exported API (see "Changing the
exported API" in [`CONTRIBUTING.md`](./CONTRIBUTING.md)).

## [Unreleased]

### Added

- **`allow`: Google groups.** `Parse` accepts `group:<group email>`
  entries (`List.Groups`). `CloudIdentityGroups` is a `GroupChecker` that
  asks Cloud Identity as the service's own identity:
  `checkTransitiveMembership`, falling back on its 403 (editions below
  Workspace Enterprise) to a bounded walk of nested groups with
  `memberships.list`, cached for 5 minutes so one walk serves every
  account. An `Admitter` answers for emails, domains and groups, caching
  group verdicts per account for 5 minutes; a failed lookup is an error,
  never a refusal and never cached. Taken from kode-gopher
  `internal/oauth` at `8b53617` with its tests.
- **`googletoken.NewAdmittingAuthenticator`** admits through an
  `allow.Admitter`, so Path A can admit by group. A failed group lookup is
  `ErrUnavailable`, logged without the token.

### Changed

- `allow.Parse` reads an entry starting with `group:` as a group (it
  previously parsed as an odd email address), and `List.Empty` counts
  group entries. `List.Admits` never admits through a group.
- `googletoken.NewAuthenticator` refuses a list with group entries, which
  it has no way to look up; use `NewAdmittingAuthenticator`.

## [0.1.0] - 2026-10-15

Path A: a go-steer service can accept the per-user Google access tokens a
Gemini Enterprise app sends to a Custom MCP Server, decide who gets in, and
act as that person.

**What v0.1.0 is for.** k8s-lookout's per-user identity
(k8s-lookout#699) needs a tag to pin rather than a commit, and
`verify-apidiff` needs a baseline: before this tag it had nothing to compare
against and skipped every run. Built on purser v0.2.0. Browser sign-in,
group allow-lists and Path B (a service as its own authorization server)
come later.

### Added

- **`httpauth`: protect a resource and hand each request the caller's own
  token** (Path A, #1). A `Protector` wraps a handler in purser's
  `CallerMiddleware`, built with `Enforce` and no `Fallback` so a refused
  request can never run as anyone, around a `googletoken.Authenticator`.
  Behind it, `TokenSourceFromContext` gives the person's own Google token
  (with its expiry) and `IdentityFromContext` their verified identity, for
  calling Google APIs and GKE as them. It serves RFC 9728 Protected Resource
  Metadata naming Google as the authorization server, and every 401 names
  it. The resource URL must be https except on loopback, since clients send
  the user's token to it, and advertised scopes must be RFC 6749 scope
  tokens. A `Protector` is an `httpmw.Gate`, so purser's `CheckBind`
  accepts it for a non-loopback bind.
- **`mcpauth`: bind MCP sessions to the person who opened them, and give
  each call its own token.** For a server on the MCP Go SDK with stateful
  sessions, `Middleware` runs the `Protector` and then the SDK's
  `RequireBearerToken` with a `TokenInfo` built from the verified identity,
  so the SDK refuses (403) a session ID presented by another person. Tool
  handlers read the person's token and identity with `TokenSource(req)` and
  `Identity(req)`, which come from the HTTP request carrying that call: the
  SDK runs every call with the session's first context, so a context
  accessor would hand a tool the token from initialize, stale within the
  hour. The raw `Authorization` header is removed before the SDK sees the
  request. The only package that imports the SDK (v1.8.0, matching
  k8s-lookout).

- **`googletoken`: verify the Google access tokens a client sends for a
  person** (Path A, #1). `Verifier` accepts a token only if Google's
  tokeninfo says it is unexpired, was issued to one of the service's own
  OAuth clients (`aud` or `azp`), carries every required scope (always
  `userinfo.email`, plus whatever the service names, such as
  `cloud-platform`), and belongs to a verified email, and userinfo agrees on
  the email and supplies the Workspace domain. Verdicts are cached by the
  token's SHA-256 for at most 10 minutes or the token's own expiry, refusals
  for 30 s, with at most 8 lookups in flight and 1024 entries. Google
  refusing is `ErrInvalid` (which wraps `purser.ErrUnauthenticated`).
  Everything else is `ErrUnavailable`, never cached and never a credential
  error: Google not answering, 429, 5xx, an answer cut short or unparseable,
  and the lookup limit being hit. `Config.Logger` logs each one without the
  token, since behind purser's enforced middleware an outage is otherwise an
  unexplained 401 (purser#23). `Authenticator` wraps a `Verifier` and an
  allow-list as a purser `authn.Authenticator` reporting
  `AuthSourceGoogleAccessToken`, and passes purser's conformance suite; use
  it with `Enforce` and no `Fallback`.

  Moved from supercargo's `internal/googleauth` (supercargo#110,
  `910d638`), generalized to several clients and service-required scopes.
  It differs from supercargo in ways that fix latent bugs there: a
  half-read or unparseable answer from Google is no longer cached as a
  refusal (one disconnecting client could lock a valid token out for 30 s);
  `exp` and `email_verified` are accepted as numbers or booleans as well as
  strings; a panic during a lookup no longer keeps its slot; and
  load-shedding is reported as unavailable rather than as an invalid token.
- **`allow`: who is let in.** Exact email addresses, or `@domain`, which
  matches only when Google's `hd` names that domain, so a consumer account
  carrying a company address never matches by its suffix. An empty list
  admits no one, and `Parse` rejects entries that would silently match
  nothing (such as a domain without its `@`).

- **The repository and its design.** `docs/DESIGN.md` sets out how steward
  sits on purser, Path A (accepting the per-user Google tokens a Gemini
  Enterprise app sends), Path B (a service as its own authorization server,
  later), the hard rules, and the phase plan. The `dev/` tooling, CI,
  adversarial-review gate and agent-attribution check follow purser and
  supercargo. No exported API yet.

[Unreleased]: https://github.com/go-steer/steward/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/go-steer/steward/releases/tag/v0.1.0
