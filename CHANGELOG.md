# Changelog

All notable changes to this module are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the module
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html); before
1.0, a minor version may change the exported API (see "Changing the
exported API" in [`CONTRIBUTING.md`](./CONTRIBUTING.md)).

## [Unreleased]

### Added

- `authserver.Config.RefreshReuseGrace`, `authserver.GraceReplayCache`
  (`RotateGrace`), `authserver.RotateResult` and its constants, and
  `MemoryReplayCache.RotateGrace`: the refresh-token reuse grace below.

### Changed

- **A refresh token presented twice at once no longer signs the person
  out.** MCP clients whose processes share one token store (for example
  two Claude Code processes) can refresh with the same token within
  milliseconds; the second presentation used to revoke the whole family,
  the first one's fresh tokens with it. Now, within
  `authserver.Config.RefreshReuseGrace` (default 10 seconds, at most a
  minute, negative for off) of a rotation, the generation just rotated
  away is refused with `invalid_grant` without revoking the family, so the
  winner's tokens stay valid and a client that re-reads its store finds
  them. Nothing is ever issued for a rotated token; an older generation,
  or the same one after the window, still revokes. A shared replay cache
  gets the grace by implementing `GraceReplayCache`; one that does not
  keeps revoking on every reuse. `MemoryReplayCache` implements it, so a
  wrapper that embeds it and overrides `Rotate` must now override
  `RotateGrace` too, or the server skips the override.

### Security

- **A client's name can no longer disguise its client ID or redirect host
  on `authserver`'s consent page.** A DCR or CIMD `client_name` was shown
  as `name (client_id)` in one element, so a name with a right-to-left
  override or a bidi isolate could visually reverse the client ID and the
  redirect host after it, and a short name could carry a fake
  `(https://...)` of its own. Names are now cleaned at registration, at
  resolution (covering registrations sealed before this release) and at
  display: control and format characters, bidi controls, zero-width and
  other default-ignorable, private-use and unassigned code points are
  dropped, whitespace and newlines collapse to one space, stacked
  combining marks are capped, and truncation to 100 bytes happens after
  cleaning, on a character boundary. The page shows the name in its own
  `<bdi>` element ("a client calling itself ..."), and the CIMD client ID
  and redirect host each in an element of their own, percent-encoded to
  printable ASCII; a DCR client gets a line saying nothing vouches for its
  name, so a fake `(https://...)` reads as part of the claim.
  `StaticClient.Name` is cleaned the same way in logs.

### Fixed

- **A recreated allow-listed group no longer locks its members out for up
  to an hour.** `CloudIdentityGroups` caches a group's resource name for
  an hour, and a group deleted and recreated in that hour has a new one.
  Cloud Identity can answer the old name with 403 "Permission denied ...
  (or it may not exist)" rather than 404, and only a 404 from
  `checkTransitiveMembership` used to trigger a fresh lookup: a 403 there
  sent the check to the walk, whose 403 or 404 on the old name was an
  error, as was any 403 or 404 on the walk path (editions without the
  transitive call, and member addresses with a quote or backslash). Now a
  403 or 404 about the group itself on a cached name, on either path,
  looks the group up again once and retries; the edition fallback still
  follows a 403 on a freshly looked-up name, a 5xx or 429 never counts as
  a stale name, and a check costs at most one extra `groups:lookup`.
  Members saw an error (a 503 on Path A, `server_error` from the
  authorization server on Path B), never a refusal, but were kept out
  until the cached name expired. Still not covered: a membership list
  cached under the old name answers as the old group did for up to 5
  minutes, and a recreated nested group is still an error until its name
  expires.
- **`authserver`: starting sign-in twice in one browser no longer fails
  both.** Each `/authorize` replaced the browser's binding cookie, so an
  earlier tab, a retry, or a copied link opened next to the client's own
  tab ended on "Sign-in expired". The cookie is now kept across starts,
  renewed when the user approves the consent page, and no longer cleared
  by Google's callback. An issuer with a path still starts each sign-in
  with a fresh cookie, because a sibling subdomain could plant one there
  (see "Browser binding" in `docs/DESIGN.md`), so the fix applies to
  issuers at the root of an https host and to loopback. Two sign-ins that
  both reach the credential vault's own consent screen still collide;
  finish one first. When a sign-in can't continue, the page and the log
  (`step`, `reason`) now say why: the link is unreadable, it's more than
  10 minutes old, this browser didn't start it, or this browser started a
  different one. The sealing keys being unavailable is now a 503 page to
  retry rather than "Sign-in expired". Ported from kode-gopher `fb8ea5e`.
- **`googletoken`: only Google's verdict on a token is a refusal**
  (#14). A non-200 tokeninfo or userinfo answer other than 429 or 5xx was
  `ErrInvalid`: cached for 30 s and a 401, so an egress proxy's 403 or
  407, or a 404 from a moved endpoint, sent clients to sign in again. Only
  tokeninfo's 400 `invalid_token` and userinfo's 401 are `ErrInvalid` now;
  every other status is `ErrUnavailable` (never cached, a 503 with
  `Retry-After` behind purser).
- **`googletoken`: a client that went away is not an outage.** The
  Verifier's `Config.Logger` line and the Authenticator's group-check line
  are Debug, not Warn, when the request's context was cancelled, as
  purser's middleware does. A deadline that ran out is still a Warn.
- **`authserver`: a busy vault no longer signs people out.** Under
  `VaultCustody`, a `pending` or empty answer from the credential vault was
  treated as a grant only the user could repair: `invalid_grant` at
  refresh. It is `server_error` now (the refresh token is given back for
  the retry), and `server_error`, not `access_denied`, at sign-in: the
  vault's API reference says to retry a `pending` answer.
- **`authserver`: a nearly spent vault token no longer signs people out.**
  A vault token with under 5 minutes left is force-refreshed, and the vault
  answers a forced refresh of a token that is still valid by asking for
  consent; that was `invalid_grant`. When forcing a valid token brings no
  better one, short of a refusal, the valid token is now used if it has 3
  minutes left, and the answer is otherwise `server_error`.
- **`authserver`: a vault token Google's tokeninfo refuses is a refusal.**
  A 400 `invalid_token` from tokeninfo was `server_error`. The token is now
  force-refreshed once (it may have expired before the vault's
  `expireTime`). If the vault then asks for consent, sign-in detours
  through it and refresh answers `invalid_grant`; if Google refuses the new
  token too, sign-in answers `access_denied` and refresh `invalid_grant`.
  Other tokeninfo failures stay `server_error`.
- **`authserver`: a vault error that quotes a forced token back** has the
  token replaced before the error is logged.

### Security

- **`authserver`: flow cookies are `__Secure-` prefixed for an https
  issuer with a path.** `__Host-` needs `Path=/`, so such an issuer's
  cookies had no prefix and a network attacker could plant one over plain
  http (absent HSTS). A sign-in in progress on such an issuer during the
  upgrade fails once, since the cookie's name changes. Issuers at the root
  of their host keep `__Host-`; see "Browser binding" in `docs/DESIGN.md`
  for who can plant a binding cookie in each case.

## [0.3.0] - 2026-10-20

Outages answer 503, not 401, and the CIMD fetch filter is closed against zoned IPv6 literals. steward now requires purser v0.3.0 (purser#23): Google, group-directory and sealing-key outages reach a `Protector`'s callers as 503 with `Retry-After`, so MCP clients retry instead of signing in again. The purser bump reaches consumers through MVS and changes their own `httpmw.CallerMiddleware` too (see Changed). The security fix closes an SSRF in `SSRFSafeClient` (#12).

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

### Changed

- **steward requires purser v0.3.0, which changes your own purser
  middleware too.** Go's minimum version selection gives a service that
  imports steward purser v0.3.0, so every `httpmw.CallerMiddleware` it
  builds changes along with steward's: under `Enforce`, only an error
  wrapping `purser.ErrUnauthenticated` is a 401, and anything else is a 503
  with `Retry-After`. An authenticator of yours that reports a bad
  credential with a bare error, not wrapping `ErrUnauthenticated`, now
  draws a 503 and an invitation to retry instead of a 401. Check yours
  before upgrading; see "Check before upgrading" in purser's
  [v0.3.0 changelog](https://github.com/go-steer/purser/blob/v0.3.0/CHANGELOG.md).
  purser v0.3.0 also logs through `CallerOptions.Logger` (else
  `slog.Default()`): a Warn for every 503 and a Debug for every 401.

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
  sentinels is unchanged; their messages now end with purser's. The
  `Protector`'s own 503, for a token that became uncheckable between
  purser's layer and the attach layer, sends `Retry-After: 10` as purser
  does, instead of 5.

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

[Unreleased]: https://github.com/go-steer/steward/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/go-steer/steward/releases/tag/v0.3.0
[0.2.0]: https://github.com/go-steer/steward/releases/tag/v0.2.0
[0.1.0]: https://github.com/go-steer/steward/releases/tag/v0.1.0
