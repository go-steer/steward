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
| go-steer/k8s-lookout | Path A: Gemini Enterprise users read clusters as themselves (k8s-lookout#699) | planned, on v0.1.0 |
| go-steer/supercargo | Path A: the source of `googletoken`; adopting steward would replace its `internal/googleauth` | deferred (2026-10-15): supercargo stays as it is for now; port fixes by hand |

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
- `group:<group email>`, a Google group, directly or through nested
  groups. `CloudIdentityGroups` asks Cloud Identity as the service's own
  identity (or a service account it impersonates; either needs the Groups
  Reader admin role): `groups.memberships.checkTransitiveMembership`
  first, and on that call's 403 (Workspace editions below Enterprise do
  not have it) a breadth-first walk with `memberships.list`, bounded at 10
  levels and 100 groups. A walk that could not read part of the tree and
  did not find the member is an error, not a "no". Taken from kode-gopher
  (`internal/oauth/allow.go` at `8b53617`), with three fixes from review
  that should be ported back: a member address with a quote or backslash
  is matched exactly by the walk instead of being stripped into the
  transitive call's quoted query (kode-gopher's stripping let `o'brien`
  match `obrien`); a 404 on a cached group name looks the group up again
  before it counts as "not a member" (a group deleted and recreated within
  the hour would otherwise refuse its members); and a group's member
  listing is capped at 100 pages.
- Group membership is matched by email, as Cloud Identity keys it. Like an
  exact-email entry, and unlike a domain entry, a group entry admits any
  Google account verified for a member's address.

`List.Admits` answers from the list alone and never admits through a
group. An `Admitter` pairs a `List` with a `GroupChecker` and answers for
all three kinds, caching group verdicts per account for 5 minutes, so a
removal takes effect within 10 minutes (a verdict computed from a
membership list cached for 5). Any group admits; a group that cannot be
checked does not lock out the members of the others, and only when nothing
matched is a failure the answer: an error (on Path A, `ErrUnavailable`),
never cached and never a refusal. Under purser's enforced middleware that
error is still a 401 on the wire, including a permanent one such as a
nested group from an external identity source; `Config.Logger` on the
Verifier is how an operator sees it. `googletoken.NewAuthenticator` refuses
a list with group entries, which it could not look up;
`NewAdmittingAuthenticator` takes an `Admitter`.

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
- An `httpauth.Protector` builds that middleware itself and wraps it
  around a second layer that attaches the verified token as an
  `oauth2.TokenSource` (`httpauth.TokenSourceFromContext`) and its
  `googletoken.Identity` (`httpauth.IdentityFromContext`). That layer acts
  only when purser's verdict for the request is Google's, so it never
  trusts a header purser did not verify, and it re-reads the identity from
  the Verifier's cache, so the token's expiry rides on the token source.
  The accessors live in `httpauth`, not the root package, so the root
  imports nothing.
- The token source does not refresh. The client holds the refresh token
  (Gemini Enterprise does) and sends a fresh access token on a later
  request.
- The Protector serves RFC 9728 Protected Resource Metadata naming Google
  as the authorization server, at the well-known path RFC 9728 §3.1
  derives from the resource URL, and every 401 challenge points at it
  (`resource_metadata`, plus `scope` when scopes are configured). The
  resource URL must be https, except for a loopback host, because clients
  send the user's Google token to it. The Protector is an `httpmw.Gate`,
  so purser's `CheckBind` accepts it for a non-loopback bind.

### MCP (`mcpauth`)

The only package that imports the MCP Go SDK. The SDK's streamable HTTP
handler refuses a session ID presented by a different user than the one
who opened it (403), but only when it finds an `auth.TokenInfo` with a
`UserID` on the request, and only the SDK's own `auth.RequireBearerToken`
can put one there. `mcpauth.Middleware` therefore runs the Protector and
then `RequireBearerToken` with a verifier that checks nothing itself: it
converts the already-verified identity into a `TokenInfo` whose `UserID`
is Google's `sub` (the email if Google sent none, since an empty `UserID`
turns binding off). A service that runs stateless HTTP has no sessions to
bind and does not need it.

**The token inside a tool handler comes from the request, not the
context.** In a stateful session the SDK runs every call with a context
derived from the session's first request (initialize), so context values
attached to a later request never reach the handler, and
`httpauth.TokenSourceFromContext` would return the token from initialize,
which expires within the hour while the client keeps sending fresh ones.
What the SDK does pass per call is that HTTP request's `TokenInfo`
(`req.Extra`). So `mcpauth` puts the request's token source and identity in
`TokenInfo.Extra`, and tool handlers read them with
`mcpauth.TokenSource(req)` and `mcpauth.Identity(req)`. The person cannot
change within a session (the binding enforces it); the token can. Found by
the adversarial review of the wiring PR; `TestToolSeesCurrentToken` pins
it.

`mcpauth` also strips `Authorization` before the SDK handler, so the raw
token is not in `req.Extra.Header` for a tool (or a header-logging layer) to
find. The SDK writes its own 401 in two edge cases (a `TokenInfo` whose
expiry passed between the layers, or a missing one); its challenge names the
metadata but not the scopes.

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
k8s-lookout#702. The port is from kode-gopher
`8b53617b7d4d0b08b158de64ab7416dc84a1281e`.

### Sealing (`seal`)

Everything the authorization server hands out is an AES-256-GCM envelope,
`st1.<key id>.<base64url(nonce || ciphertext)>`, so nothing is stored and
any replica holding the keyring opens what another sealed:

- The first key in a `Keyring` seals; every key opens. Replicas reload on
  their own schedules, so a rotation takes two steps: add the new key
  second and wait longer than the reload interval (every replica can now
  open with it), then move it first (every replica seals with it). Drop
  the old key once everything it sealed has expired (for the authorization
  server, the 30-day refresh-token life).
- Key IDs are 1 to 64 of `A-Z a-z 0-9 _ -`, so an envelope is safe in a
  header, a URL and a form. The key ID and the purpose (access token,
  refresh token, code, sign-in state, DCR client) are the AEAD's
  associated data, ID first, so one kind never opens as another and an
  envelope relabelled to another key does not open. Decoding is strict, so
  one value has one envelope string (it can key a replay cache).
- Keyring errors name a line or a position, never key material, even when
  the columns of a keyring file are swapped.
- The `st1.` prefix tells an envelope apart from a Google access token in
  the same `Authorization` header, which is how a protected resource routes
  a request to the right verifier before verifying anything.
- A `KeyProvider` supplies the keyring. A `*Keyring` is a static one.
  `Reloader` re-reads one every 5 minutes (`FileLoader` for a mounted
  file). One load runs at a time, in the background and detached from the
  triggering request's context (with a 30 s timeout); first callers share
  the first load and stop waiting when their own context ends. A failed
  reload keeps the previous keyring and retries in 30 s, so a key store
  outage does not sign everyone out.
- `seal/secretmanager` reads the keyring from a Secret Manager secret
  version over REST with a caller-supplied `*http.Client` (kode-gopher's
  Secret Manager key, without the Cloud SDK), using the regional endpoint
  for a regional secret and checking the payload's CRC32C.

### The authorization server (`authserver`)

`authserver.New(Config)` builds the server. A service mounts it with
`Register(mux)` (or `Handler()`), at the paths its `Issuer` implies:

| Path (below the issuer) | Does |
|---|---|
| `/.well-known/oauth-authorization-server`, `/.well-known/openid-configuration` | RFC 8414 metadata (for an issuer with a path, RFC 8414 §3.1 places the first between host and path; both OIDC spellings are served) |
| `/register` | open DCR (RFC 7591), only with `OpenRegistration` |
| `/authorize` (GET, and POST for the consent form) | the client's authorization request |
| `/callback` | Google's redirect after sign-in (register it with the Google client) |
| `/consent/continue` | the vault's consent leg returns here |
| `/token` | `authorization_code`, `refresh_token`, `client_credentials` |

The protected resource's RFC 9728 metadata is not served here: the
resource serves it (`httpauth`), naming this issuer.

**Clients.** Pre-registered (`StaticClient`, `LoadStaticClients`), DCR
(the issued `client_id` is the sealed registration) and CIMD (an https
`client_id`, fetched with `SSRFSafeClient`: public IPs only, no redirects,
64 KiB, cached per `Cache-Control` up to an hour). DCR and CIMD clients
get a consent page naming the client and its redirect host before Google
sign-in, because one Google client fronts them all; pre-registered clients
skip it. The flow is bound to the browser by a random cookie (`__Host-`
prefixed when the issuer allows it) whose hash rides in the sealed state,
so neither the consent form nor Google's callback works in another
browser. Redirect URIs match exactly, except a loopback redirect may use
any port (RFC 8252). Why a client could not be resolved (a CIMD document's
contents, a dial error naming an internal address) goes to the log only;
a CIMD host that is down, or our keys being unavailable, is a 503 page or
`server_error`, not "unknown client".

**Authorization requests.** `response_type=code`, PKCE with S256 only
(the verifier is RFC 7636's 43 to 128 unreserved characters), and a
`resource` (RFC 8707) that, if present, must be `Config.Resource` (one
of them); every token is bound to it and the verifier refuses any other.
Service scopes (`Config.Scopes`, for lookout `lookout:read` and
`lookout:write`) are granted as requested where they exist and the client
may have them (`StaticClient.Scopes`), others dropped (RFC 6749 §3.3); a
request naming none of them gets `DefaultScopes`. The client-credentials
grant drops scopes the same way, because MCP clients ask for every scope
the resource advertises. A refresh may narrow the access token's scope,
never widen it, and the new refresh token keeps the whole grant (RFC 6749
§6). Every refresh re-intersects the grant with what the configuration
still allows the client, and `Verify` does the same for a live access
token, so narrowing a client's scopes takes effect within one access-token
life.

**Google.** Sign-in asks Google for `openid` and `userinfo.email`, plus,
under sealed custody, `GoogleScopes` (default `cloud-platform`) offline.
The ID token comes straight from Google's token endpoint over TLS, so its
claims are checked and its signature is not (OIDC Core §3.1.3.7); `New`
therefore requires Google's endpoints (and the vault's) to be https.
Google scopes must be spelled as Google's canonical URLs, because the
vault matches stored grants by exact spelling.

**Admission.** `Config.Admit`, an `allow.Admitter`, is asked at the
callback and again at every refresh. A refusal is `access_denied` at
sign-in (the description does not name the account) and `invalid_grant`
at refresh, and keeps the refresh token spent; a lookup that fails is
`server_error` and, at refresh, gives the refresh token back so the
client's retry works. If the account's email has changed since sign-in
(the vault's tokeninfo, or the ID token Google returns with a refresh,
says so), the refresh is `invalid_grant`: the identity and admission
sealed in the refresh token are stale.

**Custody** is a sealed interface (only this package implements it):

- `*VaultCustody`, the Agent Identity credential vault. Sign-in only
  identifies the user; the vault runs its own consent leg. Every token it
  returns is checked with Google's tokeninfo: its `sub` must be the
  signed-in user's (the vault stores whichever account consented, under
  whatever user ID it is given, and has no delete API), it must carry
  every configured Google scope, and its expiry is tokeninfo's, never the
  vault's `expireTime`. A token with under 5 minutes left is
  force-refreshed once.
- `SealedCustody`: the Google refresh token rides inside steward's sealed
  refresh token.

A grant only the user can repair (consent declined, another account's
grant, a missing scope) is `access_denied` at sign-in and `invalid_grant`
at refresh; Google or the vault failing is `server_error`, and a retry may
work.

**Tokens.** All sealed, the issuer bound into every purpose:

| Token | Carries | Life |
|---|---|---|
| authorization code | the request, the user, the Google access token (and refresh token, sealed custody) | 1 min, single use |
| access token | sub, email, hd, client, resource, scopes, the Google access token and its expiry | 15 min, never past the Google token's life minus a minute |
| refresh token | the user, client, resource, scopes, the Google refresh token (sealed custody only), its family and generation | 30 days, renewed by each use, rotated every time |

**Replay.** A `ReplayCache` spends authorization codes and tracks
refresh-token families (OAuth 2.1 §4.3.1). Every refresh token belongs to
the family its sign-in started, with a generation number; a refresh moves
the family to the next generation. Presenting a generation the family has
moved past is a replay, so the whole family is revoked and the user signs
in again. Storage grows with live families (one per sign-in per client),
not with refreshes. The default is in memory, and with one cache per
replica reuse detection is per replica: a stolen refresh token can go on
being used on a replica that never saw its family revoked, and a code can
be exchanged once on each (PKCE still binds it to its client's verifier).
A later generation than a replica knows moves the family on rather than
revoking it, since only another replica can have minted it. A service that
runs replicas supplies a shared `ReplayCache`; its doc states what one
must guarantee (atomic per family, no eviction before expiry, revocation
until expiry, an error means not applied). A cache that cannot answer is
`server_error`, never a pass. Giving a claim or a rotation back after a
transient failure runs detached from the request's context, so a client
that went away mid-refresh can retry; a `Rotate` error is followed by a
conditional `Unrotate` in case it was applied. There is no grace period: a
client that loses a refresh response and retries with the old token signs
in again.

**Client credentials.** A pre-registered confidential client with
`ClientCredentials` (or a `ServiceAccount`, which implies it) gets an
access token with its secret alone, and no refresh token. Its subject is
`client:<id>`. With a `ServiceAccount`, `Config.ServiceTokens` mints that
account's Google token and it is sealed in; without one, the token carries
no Google token and the resource acts as itself. Removing the client,
rotating its secret, changing its service account or narrowing its scopes
revokes its tokens at once.

**Verifying.** `Server.Verify` returns a `Principal`: subject, email, hd,
client, scopes, expiry, whether it is a workload, and the sealed Google
token behind `TokenSource()` (unexported, so formatting a `Principal` never
prints it). `Principal.Caller()` is the `purser.Caller`: a person's
Identity is their email with `google.sub` and `google.hd`, exactly as on
Path A; a workload's is `client:<id>`. Both add `steward.client_id`,
`steward.scope` and `steward.kind` (`user` or `workload`).
`Server.Authenticator()` is the purser authenticator. Its verdict is
`purser.AuthSourceOIDC` for every token, a person's or a workload's: the
token is checked locally against the issuer's keys, audience and expiry
included, as an OIDC token is. purser has no source for an authorization
server's own sealed token, and a source is fixed per authenticator, so the
verdict does not say whether a person is behind a request: services branch
on `steward.kind` (or `Principal.Workload`), never on the source. A
dedicated source would be a purser addition.

**Differences from kode-gopher**, besides the generalizations (scopes,
resource, Google scopes, optional workload service account, `Admitter`,
pluggable replay cache and keys, slog), most from this port's adversarial
review and worth porting back: refresh-token families with reuse
detection instead of one replay entry per refresh; refresh re-checks the
grant's scopes against the configuration; a narrowing refresh does not
narrow the grant; rotating a workload's secret revokes its tokens; an
email change since sign-in forces a new sign-in; the refresh token's
audience is checked against the configured resource; more than one
`resource` parameter is refused; an authorization code is given back if
sealing the tokens fails; custody failures that are Google failing are
`server_error`, not `access_denied`; client-resolution errors (CIMD
contents, dial errors) are not echoed; error descriptions keep to RFC
6749's character set; the SSRF filter also refuses NAT64, 6to4, Teredo
and other special-purpose ranges; flow cookies are `__Host-` where
possible; client secrets are compared by digest; a static client's
redirect URIs are validated at load and its slices copied; Google's
endpoints must be https; the keys being unavailable is `server_error`,
never `invalid_grant`; and the consent page's text is the service's
(`ServiceName`).

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
- `github.com/modelcontextprotocol/go-sdk` — only in `mcpauth`, pinned to
  the version k8s-lookout uses (v1.8.0). Its `auth` package brings
  `segmentio/encoding` and `segmentio/asm`; they are compiled only into a
  service that imports `mcpauth`.

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
| 2a | Path A verification: `googletoken`, `allow` (emails, domains) | done: steward#3 |
| 2b | Path A wiring: `httpauth`, `mcpauth`; tag v0.1.0 | done: steward#4, v0.1.0 |
| 3 | k8s-lookout adopts v0.1.0 (supercargo deferred) | k8s-lookout#699 |
| 4 | `signin`; `allow` groups | steward#1 |
| 5 | Path B | k8s-lookout#702 |
