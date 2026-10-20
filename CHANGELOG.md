# Changelog

All notable changes to this module are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the module
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html); before
1.0, a minor version may change the exported API (see "Changing the
exported API" in [`CONTRIBUTING.md`](./CONTRIBUTING.md)).

## [Unreleased]

### Security

- **`SSRFSafeClient` refuses zoned IPv6 addresses.** `netip.Prefix.Contains`
  is false for an address with a zone, so a CIMD `client_id` such as
  `https://[64:ff9b::a9fe:a9fe%25eth0]/c.json` got past every
  special-purpose range: an unauthenticated caller could make the
  authorization server connect to a NAT64, 6to4 or Teredo address that
  embeds an internal IPv4 one (169.254.169.254, say) on networks that route
  them. A zoned address is now never public. The filter also refuses the
  IPv4 documentation ranges, RFC 9637's `3fff::/20`, deprecated IPv6
  site-local `fec0::/10`, IPv6 discard-only `100::/64` and SRv6's
  `5f00::/16`.

### Fixed

- **A CIMD host that redirects is an unknown client.** `authserver` gave
  it the 503 page or `server_error` ("try again"), though redirects are
  never followed and a retry cannot help.
- **An outage is a 503, not a 401 (purser#23).** steward requires purser
  v0.3.0, and `googletoken.ErrUnavailable` (Google not answering, 429, 5xx,
  load shed, a failed allow-list group lookup) and
  `authserver.ErrUnavailable` (sealing keys unavailable) now wrap
  `purser.ErrUnavailable`. Through a `Protector`, a Google, directory or key
  outage answers 503 with `Retry-After` and no challenge, so MCP clients
  retry with the credential they have instead of signing in again. Bad and
  disallowed credentials are still 401. `errors.Is` against the steward
  sentinels is unchanged; their messages now end with purser's.

## [0.2.0] - 2026-10-17

Path B: a go-steer service can be its own OAuth 2.1 authorization server
in front of Google sign-in, so generic MCP clients (Claude Code,
gemini-cli, IDEs), which discover an authorization server and register
with it, can sign people in, and the service acts as each person with
their own Google token, exactly as it does for Path A's Gemini Enterprise
callers.

**What v0.2.0 is for.** k8s-lookout#702: lookout mounts `authserver`,
and one `httpauth.Protector` takes both Gemini Enterprise's Google tokens
and steward's own, yielding the same `purser.Caller` and token source.
The authorization server, its token sealing and the group allow-list are
taken from kode-gopher `internal/oauth` at
`8b53617b7d4d0b08b158de64ab7416dc84a1281e`, which will not import steward;
the fixes made here in review are listed in DESIGN.md for porting back.
The exported API changed additively only; two behaviour changes are under
*Changed*.

### Added

- **`httpauth`: one Protector for both paths.** `Options.AuthServer`
  makes a `Protector` accept steward's own access tokens as well as Google
  ones (`Options.Authenticator` is now optional; one of the two is
  required). A request is routed by its token's shape to purser's enforced
  middleware around the right verifier. A person reaches the handler the
  same way on either path, with `TokenSourceFromContext` and
  `IdentityFromContext`; a steward token also yields the
  `authserver.Principal` (`PrincipalFromContext`), which is all a
  client-credentials workload gets (even one whose service account's token
  rides in its access token). The metadata names steward's issuer and its
  service scopes; the 401 challenge names the server's `DefaultScopes`
  (`authserver.Server.DefaultScopes`), so generic clients ask for least
  privilege. `Options.RequiredScopes` refuses a steward token without them
  with a 403 `insufficient_scope` step-up challenge. A steward token at a
  Protector without an `AuthServer` is refused locally, never sent to
  Google.
- **`mcpauth`: Path B in tool handlers.** For a steward token the SDK
  session's `UserID` is the person's Google `sub` (as on Path A, so one
  person's session continues across both paths) or `client:<id>` for a
  workload; `TokenInfo.Scopes` are the granted service scopes;
  `mcpauth.Principal(req)` reads the `Principal` per call. Tested end to
  end with the SDK's own client: DCR sign-in, client credentials, and one
  endpoint taking both paths.
- **`authserver`: steward's OAuth 2.1 authorization server** (Path B,
  k8s-lookout#702). A service mounts it at an issuer URL in front of
  Google sign-in, so MCP clients that discover and register with an
  authorization server can sign people in. Metadata (RFC 8414), DCR,
  Client ID Metadata Documents and pre-registered clients; PKCE (S256
  only); resource indicators (RFC 8707) binding every token to the
  protected resource; service-defined scopes beside the Google scopes held
  upstream; the client-credentials grant for workloads, with an optional
  service account. The allow-list (`allow.Admitter`) is checked at sign-in
  and at every refresh. `Custody` holds the user's Google grant: the Agent
  Identity credential vault (`VaultCustody`, which checks every vault token's
  tokeninfo `sub` and scopes, spells scopes canonically, and ignores the
  vault's `expireTime`) or the Google refresh token sealed in steward's own
  (`SealedCustody`). Every token, code and DCR client ID is sealed, so
  nothing is stored; a pluggable `ReplayCache` spends codes and tracks
  refresh-token families, revoking a family whose rotated token is reused
  (OAuth 2.1 §4.3.1). `Server.Verify` and `Server.Authenticator` (a purser
  authenticator, verdict `oidc` for persons and workloads alike) check
  access tokens and yield a `Principal` with the same `purser.Caller` Path
  A gives a person. No MCP SDK. Taken from kode-gopher `internal/oauth` at
  `8b53617` with its tests (harness, end-to-end flows, client credentials,
  units), generalized, and hardened by review in ways worth porting back
  (see DESIGN.md, "Differences from kode-gopher").
- **`seal`: stateless, rotatable token envelopes** (Path B groundwork,
  k8s-lookout#702). A `Keyring` seals values as AES-256-GCM envelopes
  (`st1.<key id>.…`) bound to a purpose; the first key seals and every key
  opens, so keys rotate without a database (in two steps across replicas:
  see the package doc). `ParseKeyring` and `LoadKeyring` read the
  `<id> <base64 key>` text form, and no error quotes key material. A
  `KeyProvider` supplies the keyring: a `*Keyring` itself, or a `Reloader`
  that re-reads it in the background every few minutes, shares one load
  among waiting callers, and keeps the previous keyring when a reload
  fails. Taken from kode-gopher `internal/oauth` at `8b53617`, with key IDs
  restricted to `A-Z a-z 0-9 _ -`, unambiguous associated data and strict
  decoding.
- **`seal/secretmanager`: keys from Secret Manager** without the Cloud SDK:
  `Source.Load` reads a secret version over REST with a caller-supplied
  `*http.Client` (the regional endpoint for a regional secret) and checks
  its CRC32C; `NewProvider` wraps a `Source` in a `Reloader`.
- **`allow`: Google groups.** `Parse` accepts `group:<group email>`
  entries (`List.Groups`). `CloudIdentityGroups` is a `GroupChecker` that
  asks Cloud Identity as the service's own identity:
  `checkTransitiveMembership`, falling back on its 403 (editions below
  Workspace Enterprise) to a bounded walk of nested groups with
  `memberships.list`, cached for 5 minutes so one walk serves every
  account. An `Admitter` answers for emails, domains and groups, caching
  group verdicts per account for 5 minutes (a removal takes effect within
  10); any group admits, a group that cannot be checked does not lock out
  the others, and a failed lookup is an error, never a refusal and never
  cached. Taken from kode-gopher `internal/oauth` at `8b53617` with its
  tests, plus fixes to port back: a member address with a quote is matched
  exactly instead of being stripped (`o'brien` matched `obrien`), a 404 on
  a cached group name re-checks the name, and member listings are capped
  at 100 pages.
- **`googletoken.NewAdmittingAuthenticator`** admits through an
  `allow.Admitter`, so Path A can admit by group. A failed group lookup is
  `ErrUnavailable`, logged without the token.

### Changed

- `allow.Parse` reads an entry starting with `group:` as a group (it
  previously parsed as an odd email address), and `List.Empty` counts
  group entries. `List.Admits` never admits through a group. `Parse` also
  rejects a domain containing a second `@` (`@a@example.com` used to parse
  as a domain that matched nothing), so such a configuration now fails at
  startup.
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

[Unreleased]: https://github.com/go-steer/steward/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/go-steer/steward/releases/tag/v0.2.0
[0.1.0]: https://github.com/go-steer/steward/releases/tag/v0.1.0
