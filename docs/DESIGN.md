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
| go-steer/k8s-lookout | Path A: Gemini Enterprise users read clusters as themselves (k8s-lookout#699); Path B: generic MCP clients sign in through steward's authorization server (k8s-lookout#702) | Path A on v0.1.0; Path B on v0.2.0 |
| go-steer/supercargo | Path A: the source of `googletoken`; adopting steward would replace its `internal/googleauth` | not planned (2026-10-20): supercargo keeps its own `internal/googleauth`; port fixes by hand |

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
- Only an endpoint's own verdict on the token is Google refusing
  (`ErrInvalid`, cached, a 401): tokeninfo's 400 `invalid_token` and
  userinfo's 401, the statuses each answers a bad token with (checked
  against Google, 2026-10-20). Everything else is `ErrUnavailable` and
  **never** cached (a 503): no answer, 429, 5xx, any other status (an
  egress proxy's 403 or 407, a 404 from a moved endpoint, which say
  nothing about the token; steward#14), a body cut short (the client went
  away, a timeout fired, the connection dropped), and a 200 that does not
  parse. Caching a half-read answer as a refusal would let one
  disconnecting client lock a person's valid token out for 30 s.
- A lookup that failed because the client went away (its context
  cancelled) is logged at Debug, not Warn, by `Config.Logger` and the
  Authenticator alike, as purser's middleware does: it is no outage. A
  deadline that ran out is still a Warn.
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
  match `obrien`); a cached group name (kept for an hour) that draws a 403
  or 404 about the group itself looks the group up again and asks once
  more before the answer counts; and a group's member listing is capped
  at 100 pages. A group deleted and recreated within the hour has a new
  name, and Cloud Identity may answer the old one with 403 "Permission
  denied ... (or it may not exist)" instead of 404 (AIP-211's wording for
  not leaking existence). On the transitive call a 403 is also the edition
  signal, so a cached name's 403 there still falls back to the walk, and
  it is the walk's 403 or 404 on the group's own listing (or the
  transitive call's 404) that marks the name stale. On a freshly looked-up
  name the usual meanings apply: the transitive call's 404 is "not a
  member", its 403 is the edition fallback (cached per resource name, so a
  new name gets its own decision), and a walk that cannot list the group
  is an error. A 5xx or 429 never marks a name stale, and a check costs at
  most one extra `groups:lookup`. Two limits remain: a membership list
  cached under the old name (5 minutes) answers as the old group did, and
  a nested group's stale name is not retried, so any account the walk does
  not match elsewhere gets an error rather than a "no" until that name
  expires.
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
never cached and never a refusal. Under purser's enforced middleware
(v0.3.0 and later) that error is a 503 with `Retry-After`, not a 401, so
the client keeps its token and retries. The trade-off: a lookup that fails
for a permanent reason, such as a nested group from an external identity
source, is a 503 that clients keep retrying until an operator fixes the
cause; it never becomes a 401. An operator sees it as purser's Warn line
("authenticator could not reach a verdict") on every such request, written
to `httpauth.Options.Logger` or `slog.Default()`, plus the Authenticator's
own Warn when the Verifier has a `Config.Logger`. An account in no listed
group is a 401 only once every group has answered.
`googletoken.NewAuthenticator` refuses
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
- **Under `Enforce`, an unavailable Google is a 503 with `Retry-After`.**
  `googletoken.ErrUnavailable` and `authserver.ErrUnavailable` wrap
  `purser.ErrUnavailable`, which purser's enforced middleware answers with
  503 and a Warn log line since purser v0.3.0 (purser#23). A client keeps
  its credential and retries, rather than signing in again for a token that
  may be fine, which an MCP client does on a 401. A rejected credential
  (no token, `ErrInvalid`, `ErrNotAdmitted`, `authserver.ErrInvalidToken`)
  is still a 401 with the challenge. purser writes its Warn line to
  `httpauth.Options.Logger`, or `slog.Default()` when that is nil, so it is
  always on; `googletoken.Config.Logger` still logs every `ErrUnavailable`
  without the token, and is optional: setting it at all gives two lines per
  outage request, whether or not `Options.Logger` is set. Both drop to
  Debug when the client had already gone (a cancelled request context).
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

**Deferred: no consumer.** supercargo's server-side code flow (PKCE, state
and nonce, ID-token check) was to come along because supercargo's browser
UI uses it, and supercargo is not moving to steward (2026-10-20). Path B's
`authserver` runs its own Google sign-in and needs nothing from here. If a
consumer appears: whether the ID token is verified with purser's
`authn/oidc` (go-jose, already a purser dependency) or
`cloud.google.com/go/auth/credentials/idtoken` (what supercargo uses, a
much larger dependency tree) is decided in that package's PR; purser's
verifier is preferred if it can check the nonce.

## Path B — the service is its own authorization server

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
`client_id`, fetched with `SSRFSafeClient`: public IPs only (no zoned
address, and none of the special-purpose ranges `IsGlobalUnicast` admits
that could reach an internal network; a NAT64 network-specific prefix is
the operator's choice and a matter for egress policy), no redirects, 64 KiB,
cached per `Cache-Control` up to an hour). A redirect, like an address the
filter refuses, is an unknown client, never "unavailable". DCR and CIMD clients
get a consent page naming the client and its redirect host before Google
sign-in, because one Google client fronts them all; pre-registered clients
skip it. The flow is bound to the browser by a random cookie whose hash
rides in the sealed state, so neither the consent form nor Google's
callback works in another browser (below). Redirect URIs match exactly,
except a loopback redirect may use any port (RFC 8252). Why a client could
not be resolved (a CIMD document's contents, a dial error naming an
internal address) goes to the log only; a CIMD host that is down, or our
keys being unavailable, is a 503 page or `server_error`, not "unknown
client".

**Browser binding.** `/authorize` sets `steward_auth` (HttpOnly,
SameSite=Lax, the issuer's path, 10 minutes; on https Secure and named
`__Host-steward_auth`, or `__Secure-steward_auth` for an issuer with a
path, which `__Host-` forbids). Approving the consent page renews it and
the callback leaves it alone. Where nobody else can plant the cookie (see
below), a browser that already has a well-formed one (`rand.Text`'s
alphabet and length) keeps it, so two sign-ins started in one browser (a
retry, a copied link next to the client's tab, a prefetch) don't break
each other. A refused flow says why, on the page and in the log (`step`,
`reason`): the envelope is unreadable, it is more than 10 minutes old,
the browser has no cookie, or it has another sign-in's. The keys being
unavailable is a 503 page to retry, not a damaged link. A callback URL
replayed in the same browser passes the binding now that the callback no
longer clears the cookie; Google refuses the spent code, and the client
gets `server_error`.

Who can plant a binding cookie decides whether an existing one is kept.
Anyone who can set a cookie for the issuer's path in a victim's browser
defeats the binding either way: start a flow in their own browser, plant
that browser's cookie value in the victim's, and send the victim the
Google sign-in link. Keeping an existing cookie adds a second attack: a
value the attacker planted earlier becomes the binding of the victim's
own later flows, so a stolen Google `state` (it travels through Google,
the URL bar and perhaps history sync) lets the attacker finish the
victim's flow signed in as themselves, and hand the victim's client a code
for the attacker's account, which the client redeems with its own PKCE
verifier. A long-lived binding value also outlasts one seen in a log of
`Cookie` headers. So the prefix decides who can plant, and that decides
reuse:

| Issuer | Cookie | Who can plant it | Existing cookie kept |
|---|---|---|---|
| https, at the root | `__Host-steward_auth` | nobody but the host, over https | yes |
| https, with a path | `__Secure-steward_auth` | a sibling subdomain over https (not a network attacker over http) | no: a fresh cookie per start, so two sign-ins in one browser still break each other |
| http, loopback only | `steward_auth` | any server on this machine's loopback, at any port (another local user, a container's published port, a local web app) | yes: a single-user development setup accepts that; on a shared machine, serve https at the root of a host |

Another app on the issuer's own host is the same origin and outside any
cookie's protection. Put the issuer at the root of its own host for the
binding to hold against everyone. (Older browsers let a nameless cookie
whose value began `__Host-x=` pass as `__Host-x`; current ones refuse it.)

**Client names.** A DCR or CIMD client chooses its own name, so the
consent page must not let it pass for something else. The name is cleaned
wherever a client is resolved or registered, and again at display:
control and format characters (bidi overrides, embeddings and isolates,
zero-width characters) and other default-ignorable, private-use and
unassigned code points are dropped, whitespace runs (line and paragraph
separators included) become one space, non-spacing and enclosing marks
are capped at four per character, and the result is cut to 100 bytes on
a character boundary. Cleaning at resolution covers registrations sealed
before it existed, and static clients' names (which only reach the log).
The page calls the client "a client calling itself" its name, in a
bidi-isolated element (`<bdi>`) of its own, and shows the CIMD client ID
and the redirect host in separate elements as printable ASCII (anything
else percent-encoded, since `url.Parse` keeps non-ASCII and decodes a
host's escapes), so no name can reorder them. A DCR client, whose client
ID is a sealed blob, gets a line saying it registered itself and nothing
vouches for its name, so a fake "(https://...)" in a name still reads as
the client's claim, not as a client ID line. `html/template` escapes
markup but passes these characters through, so the cleaning is ours.
Blank but visible characters (U+2800, say) survive: they can pad a name,
not reorder or hide anything; nor is a homoglyph name caught.

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
  vault's `expireTime`. A token with under 5 minutes left, or one
  tokeninfo refuses (400 `invalid_token`: expired early or revoked), is
  force-refreshed once. The vault's API reference says a forced refresh
  "fetches a new token or initiates a new consent flow". For a refused
  token, a consent request is the grant gone: sign-in detours through
  consent, refresh is `invalid_grant`. For a token Google still accepts it
  is not: the vault declines to force-refresh a valid token by asking for
  consent (kode-gopher's vault spike). So when forcing a valid token
  brings no better one, short of a refusal, that token is used if it has 3
  minutes left (enough for an access token that stops a minute before it,
  after a code that may wait a minute), and the answer is otherwise
  `server_error`.
- `SealedCustody`: the Google refresh token rides inside steward's sealed
  refresh token.

A grant only the user can repair is `access_denied` at sign-in and
`invalid_grant` at refresh (the client signs the person in again): consent
declined, another account's grant, a missing scope, a changed email,
Google's `invalid_grant` on a sealed refresh token, and a vault token
tokeninfo refuses both before and after a forced refresh. The vault asking
for consent is the consent detour at sign-in and `invalid_grant` at
refresh. Google or the vault failing is `server_error`, and at refresh
gives the refresh token back, so a retry may work: no answer, any HTTP
error from the vault, a tokeninfo answer other than 200 or 400, the vault
answering `pending` (its API reference: "the caller should retry ... after
some time") or nothing usable, and a forced refresh that returns the same
token or another nearly spent one (each unless the token it was to replace
is still usable, above). A vault error message that quotes a forced token
back has it replaced before it is logged.

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
`server_error`, not `access_denied`, including a `pending` or empty vault
answer (a sign-out before); the vault declining to force-refresh a
still-valid token leaves that token in use (with 3 minutes left) or is
`server_error`, rather than signing the person out; a vault token
tokeninfo refuses is force-refreshed once, then a consent detour at
sign-in or a refusal, rather than `server_error`; client-resolution
errors (CIMD contents, dial errors) are not echoed; error descriptions
keep to RFC 6749's character set; the SSRF filter also refuses NAT64, 6to4, Teredo
and other special-purpose ranges; flow cookies are `__Host-` where
possible and `__Secure-` on https otherwise; client secrets are compared
by digest; a static client's redirect URIs are validated at load and its
slices copied; Google's endpoints must be https; the keys being
unavailable is `server_error`, never `invalid_grant`; the consent page's
text is the service's (`ServiceName`); and a client's name there is
cleaned and kept apart from its client ID and redirect host (see Client
names above). Scopes are granted in the configuration's order, so a grant
reads the same however the client ordered its request.

**Ported from kode-gopher since `8b53617`.** `fb8ea5e` (kode-gopher#48):
the browser-binding cookie is kept across sign-ins started in one browser,
renewed on approval and no longer cleared by the callback, and a refused
flow names its reason (Browser binding, above). steward's version keeps
its own cookie names (kode-gopher sets every cookie on `/` and prefixes
`__Host-` on any https issuer; steward scopes cookies to the issuer's
path, which `__Host-` forbids for an issuer with a path), adds
`__Secure-` for that case and keeps no existing cookie there (a sibling
subdomain can plant one; kode-gopher has no such case), logs through the
server's logger, and answers the keys being unavailable with a 503
instead of a damaged-link page. kode-gopher's known limitation holds here
too: the vault's consent leg parks the flow in one `steward_consent`
cookie, so two sign-ins that both reach the vault's own consent screen
still collide (the later one replaces the earlier one's); finish one
first.

### Both paths on one resource (`httpauth`, `mcpauth`)

`httpauth.Options` gains `AuthServer` (and `Authenticator` becomes
optional: at least one of them). The Protector then:

- **Routes by shape, verifies fully.** A bearer token with the `st1.`
  prefix goes to a second purser `CallerMiddleware` around
  `Server.Authenticator()`, also with `Enforce` and no `Fallback`; anything
  else goes to the Google one. Routing decides only which verifier looks;
  each refuses what it does not recognize. Without an `Authenticator`,
  everything goes to the steward verifier; without an `AuthServer`, a
  steward token is refused locally and never sent to Google's tokeninfo.
- **Gives a person the same shape on both paths.** Behind it, a steward
  token from a person puts the Google token sealed inside on
  `TokenSourceFromContext` and a `googletoken.Identity` (sub, email, hd,
  the Google token's scopes and expiry) on `IdentityFromContext`, as Path A
  does, plus the `authserver.Principal` on `PrincipalFromContext`. A
  workload gets only the `Principal`: no person, no person's token, so a
  service cannot mistake it for one (`TokenSourceFromContext` reports
  false), even when its service account's token rides in its access token
  (that is `Principal.TokenSource()`). A person's token without a Google
  token inside is refused rather than passed as if it were a workload.
- **Names steward's issuer** in the RFC 9728 metadata (only it: a generic
  client picks the first server listed, and Google's cannot register it),
  advertising the server's service scopes, with CORS for browser-based
  clients. The 401 challenge names the server's `DefaultScopes`: MCP
  clients request what the challenge names, so a service that sets
  `DefaultScopes` to its read scope gets least-privilege tokens from
  generic clients. Explicit `Scopes` must be the server's.
- **Two allow-lists.** Path A admits through the `Authenticator`'s
  `Admitter`, Path B through `authserver.Config.Admit` (at sign-in and
  every refresh). Give them the same entries.
- **Enforces `RequiredScopes`** on steward tokens: one without them is a
  403 with `error="insufficient_scope"`, which starts a client's step-up.
  Google tokens carry no service scopes and are not held to them; on Path
  A the service's own rules decide.
- **Answers 503** with `Retry-After` if the keys vanish between the two
  layers, as for a Google outage on Path A. (Keys already unavailable when
  the request arrives are a 503 from purser's middleware, before this
  layer: `authserver.ErrUnavailable` wraps `purser.ErrUnavailable`.) Both
  layers send the same `Retry-After`, 10 seconds.

`mcpauth.TokenInfo` builds the SDK `TokenInfo` from the `Principal` for a
steward token: `UserID` is the Google `sub` for a person, the same as on
Path A, so one person's session continues across the two paths, and
`client:<id>` for a workload, which therefore cannot use a person's
session. Binding is per person, not per client: the same person keeps a
session across paths and clients. `Scopes` are the granted service scopes (on Path A, the Google
scopes), and `Expiration` is the access token's. `mcpauth.Principal(req)`
reads the `Principal` in a tool handler, per call like `TokenSource`.

Verified end to end with the MCP SDK's own client (v1.8.0): discovery
from the resource's metadata, DCR, consent, Google sign-in and a tool call
as the person; the client-credentials handler as a workload; and one
endpoint taking both paths. That run found one interoperability bug, now
fixed: the SDK's client asks for every advertised scope, which the
client-credentials grant first refused instead of dropping the ones the
client may not have.

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
- `github.com/modelcontextprotocol/go-sdk` — only in `mcpauth` (and the
  test helper `internal/pathbtest`), pinned to the version k8s-lookout
  uses (v1.8.0). Its `auth` package brings `segmentio/encoding` and
  `segmentio/asm`; they are compiled only into a service that imports
  `mcpauth`. `authserver`, `seal` and `httpauth` do not import it.
- No Google Cloud SDK anywhere: the vault, Cloud Identity and Secret
  Manager are called over REST with a caller-supplied `*http.Client`.

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
| 3 | k8s-lookout adopts v0.1.0 (supercargo not planned) | done: k8s-lookout#699 |
| 4 | `allow` groups; `signin` | groups: done (steward#6); `signin`: deferred, no consumer |
| 5 | Path B: `seal`, `authserver`, both paths in `httpauth` and `mcpauth`; tag v0.2.0 | done: steward#6, #7, #8, #9, v0.2.0 (k8s-lookout#702) |
