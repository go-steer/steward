# steward — design

steward lets a go-steer service act as its caller. A request arrives
carrying a person's Google access token; steward decides whether the token
is good for this service, who it belongs to and whether that person is let
in, and hands the service a `purser.Caller` plus a token source for calling
Google APIs and GKE clusters **as that person**.

purser (`github.com/go-steer/purser`) checks who is aboard: it turns a
request into a `purser.Caller` from mTLS, SPIFFE, OIDC or a bearer table,
and owns authorization rules. Two Google-specific jobs fall outside it by
its own design:

- A Google access token is opaque. It is checked by asking Google
  (tokeninfo, userinfo), not by verifying a signature, so purser's
  `authn/oidc` does not apply.
- Running an OAuth authorization code flow is excluded outright (purser
  `docs/DESIGN.md`, `authn/oidc`: "obtaining a token is the client's
  problem").

steward does those jobs and plugs into purser, so a consuming service sees
one caller type however the caller arrived.

## Consumers

| Consumer | Uses | Status |
|---|---|---|
| go-steer/k8s-lookout | Path A: Gemini Enterprise users read clusters as themselves (k8s-lookout#699) | planned |
| go-steer/supercargo | Path A: its `internal/googleauth` moves here, and supercargo adopts steward | planned |

## Path A — the client holds the user's token

The first and main case is a **Gemini Enterprise** app calling a service's
MCP endpoint through a Custom MCP Server data store:

- Gemini Enterprise is the OAuth client, configured with the service's own
  OAuth client (ID and secret). Google is the authorization server. Gemini
  Enterprise runs the code flow per user, keeps the refresh token, and
  sends the user's Google access token as a bearer token on every request.
- steward checks that token and hands it back to the service as a token
  source for the life of the request. It stores nothing.

This is supercargo's shipped implementation (`internal/googleauth`,
supercargo#110), moved here with its tests and generalized:

### Verification (`googletoken`)

A token is accepted only if all of these hold:

1. It is not a JWT (an ID token is never an access token; refused before
   Google is asked), not empty, and at most 4 KiB.
2. Google's **tokeninfo** says it is unexpired, was issued to one of the
   service's configured OAuth clients (`aud` or `azp`), carries every scope
   the service requires (always `userinfo.email`; lookout also requires
   `cloud-platform`), and belongs to a verified email.
3. Google's **userinfo** answers for the same email, and gives the account's
   Workspace domain (`hd`), which tokeninfo does not.

The result is an `Identity`: subject, email (lower-cased), `hd`, scopes and
expiry.

Bounds, so that garbage tokens cannot turn into a flood of calls to Google:

- Results are cached by SHA-256 of the token, never the token itself, for
  at most 10 minutes or the token's own expiry, whichever is sooner.
- A refusal is remembered for 30 s.
- At most 8 lookups run at once; past that a token not in the cache is
  turned away as unavailable (load-shedding, not a verdict).
- At most 1024 cache entries.
- Only a complete non-2xx answer other than 429 is Google refusing
  (`ErrInvalid`, cached). Everything else is `ErrUnavailable` and
  **never** cached: no answer, 429, 5xx, a body cut short (the client went
  away, a timeout fired, the connection dropped), and a 200 that does not
  parse. Caching a half-read answer as a refusal would let one
  disconnecting client lock a person's valid token out for 30 s.
- `exp` and `email_verified` are accepted as strings (what Google sends
  today), numbers or booleans, so a type change at Google cannot turn
  every token into a refusal.
- A lookup slot is released however the lookup ends, including a panic in
  a caller-supplied transport.

### Admission (`allow`)

Who is let in, decided after verification:

- an exact email address;
- `@domain`, which needs Google's `hd` to name that domain: a consumer
  Google account can carry any company address that once received its
  verification mail, so the email suffix alone never admits;
- a Google group, by Cloud Identity transitive membership
  (`groups.memberships.checkTransitiveMembership`, as the service's own
  identity), cached for 5 minutes. Added after the first release.

An empty list admits no one.

### Wiring (`httpauth`)

- `googletoken.Authenticator` implements purser's `authn.Authenticator` and
  `authn.CredentialGate`, so it runs inside purser's
  `httpmw.CallerMiddleware`, which already owns attaching the caller,
  enforcement, the proxy-assertion path and the 401.
- **The middleware must be built with `Enforce` and no `Fallback`.** With
  `Enforce` off, purser gives every failed request `CallerOptions.Fallback`;
  a Fallback naming the service would serve unadmitted people as the
  service, which breaks "no fallback identity". `httpauth` builds the
  middleware itself, so a consumer cannot get this wrong through steward.
- **Under `Enforce`, an unavailable Google is a 401 too.** purser maps every
  authentication error to 401 and logs none of them, so a Google outage
  looks like a wave of bad tokens, and MCP clients typically answer a 401
  by signing in again. Until purser has a 503 path for errors that do not
  wrap `ErrUnauthenticated` (purser#23), `googletoken.Config.Logger`
  logs every `ErrUnavailable`, without the token, so an operator can tell
  the two apart.
- A steward middleware, placed after purser's, attaches the verified
  token's `oauth2.TokenSource` to the request context
  (`steward.TokenSourceFromContext`). It runs only when purser's verdict
  for the request is Google's, so it never trusts a header purser did not
  verify.
- A handler serves RFC 9728 Protected Resource Metadata naming Google as
  the authorization server, and the 401 challenge points at it
  (`resource_metadata`).

### MCP (`mcpauth`)

The only package that imports the MCP Go SDK. It adapts steward's caller
to the SDK's `auth.TokenInfo`, so a service that runs stateful MCP
sessions gets each session bound to its caller (the SDK refuses a session
ID presented by another user). A service that runs stateless HTTP does not
need it.

### Browser sign-in (`signin`)

supercargo's server-side code flow (PKCE, state and nonce, ID-token check)
comes along because supercargo's browser UI uses it. Whether the ID token
is verified with purser's `authn/oidc` (go-jose, already a purser
dependency) or `cloud.google.com/go/auth/credentials/idtoken` (what
supercargo uses today, a much larger dependency tree) is decided in that
package's PR; purser's verifier is preferred if it can check the nonce.

## Path B — later: the service is its own authorization server

Generic MCP clients (Claude Code, gemini-cli, IDEs) expect to discover an
authorization server and register with it by DCR or CIMD, which Google's
does not support. For them, a service mounts steward's own OAuth 2.1
authorization server in front of Google sign-in: PKCE (S256 only), resource
indicators (RFC 8707), CIMD/DCR/static clients, client credentials, Agent
Identity credential vault custody with a sealed-refresh-token fallback, and
AEAD-sealed stateless tokens.

The implementation is kode-gopher's (`gke-demos/kode-gopher`,
`internal/oauth`, `docs/design-in-cluster.md` §3). kode-gopher is in another
org and will not adopt steward, so the code is taken from a recorded commit
and fixes are ported by hand in both directions. Tracked in
k8s-lookout#702.

## Hard rules

- **Never accept a token issued to someone else's client.** The `aud`/`azp`
  check is what keeps a service from being used to replay a grant the user
  gave another app. It is also why Path A is not the token passthrough the
  MCP authorization spec forbids.
- **The token never leaves the request.** It is never logged, never in an
  error string, never a cache key (the SHA-256 is), and never stored.
- **Google failing is not Google refusing.** A 429 or 5xx is an error the
  caller can retry, never a cached refusal.
- **A domain needs Google's word.** `@domain` matches on `hd`, never on the
  email suffix.
- **No service policy.** Roles, personas, tool lists and which clusters a
  person may read belong to the consuming service. steward supplies
  identity, admission and the token source, and stays out of the
  vocabulary, like purser.
- **No fallback identity.** A request steward refuses is refused; steward
  never substitutes the service's own identity for a person's.

## Prerequisites in purser

Both additive:

1. An `AuthSource` for a verified Google access token
   (`AuthSourceGoogleAccessToken`, wire value `google-access-token`).
   Neither `oidc` (a signed JWT) nor `bearer` (a static table) is true of
   it, and `AuthSource.Known` and the conformance suite reject a value
   purser does not define.
2. A `CallerOptions` field for the 401 challenge, so a protected resource
   can send `Bearer resource_metadata="…"` (RFC 9728 §5.1) instead of the
   fixed `Bearer realm="purser"`.

## Dependencies

Minimal, per go-steer policy:

- `github.com/go-steer/purser` — the caller contract.
- `golang.org/x/oauth2` — token sources and the sign-in exchange.
- `github.com/modelcontextprotocol/go-sdk` — only in `mcpauth`.

## Testing

The default run is hermetic: no network, no credentials. Google's
tokeninfo, userinfo, token and Cloud Identity endpoints are `httptest`
servers. `googletoken.Authenticator` passes purser's `authtest` conformance
suite. Every rejection path has a test (foreign client, missing scope,
unverified email, expired, mismatched userinfo email, JWT, oversize,
consumer account claiming a domain, Google 429/5xx not cached, lookup
limit). Ported tests keep their supercargo coverage.

## Phases

| Phase | Content | Tracked |
|---|---|---|
| 0 | Repository, tooling, this design | done |
| 1 | The two purser additions | done: purser v0.2.0 |
| 2a | Path A verification: `googletoken`, `allow` (emails, domains) | steward#1 |
| 2b | Path A wiring: `httpauth`, `mcpauth`; tag v0.1.0 | steward#1 |
| 3 | k8s-lookout and supercargo adopt v0.1.0 | k8s-lookout#699 |
| 4 | `signin`; `allow` groups | steward#1 |
| 5 | Path B | k8s-lookout#702 |
