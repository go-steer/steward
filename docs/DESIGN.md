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
| go-steer/k8s-lookout | Path A: Gemini Enterprise users read clusters as themselves (k8s-lookout#699); Path B: generic MCP clients sign in through steward's authorization server (k8s-lookout#702) | Paths A and B on v0.3.0 (2026-11-01) |
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
  (`ErrInvalid`, cached, a 401): tokeninfo's 400 with a JSON body whose
  `error` is `invalid_token`, and userinfo's 401, what each answers a bad
  token with (checked against Google, 2026-10-20 and 2026-11-01: every
  bad, expired or missing token got exactly that). userinfo's body says
  only `invalid_request`, too generic to check, so its status decides; a
  proxy asking for credentials sends 407. Everything else is
  `ErrUnavailable` and **never** cached (a 503): no answer, 429, 5xx, any
  other status (an egress proxy's 403 or 407, a 404 from a moved
  endpoint, which say nothing about the token; steward#14), a tokeninfo
  400 without `invalid_token` (an egress proxy's, an HTML page; the rule
  kode-gopher#56 applies to its vault's tokeninfo check), a body cut short
  (the client went away, a timeout fired, the connection dropped), and a
  200 that does not parse. Caching a half-read answer as a refusal would
  let one disconnecting client lock a person's valid token out for 30 s.
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
  vault's `expireTime`. Renewal follows the vault's own rules (below):
  only a token tokeninfo refuses is force-refreshed, a token Google still
  accepts is used for as long as it lasts, and one too close to expiry to
  use is waited out and retrieved again.
- `SealedCustody`: the Google refresh token rides inside steward's sealed
  refresh token.

**Vault renewal.** The evidence:

- The vault's API reference (discovery document, revision 20261016) on
  `forceRefreshToken`: "Set this field only if the previous token was
  expired or invalid. ... Setting this field triggers a refresh of the
  access token with a stored refresh token, if possible, or a new consent
  flow." On `Success.token`: on a `PERMISSION_DENIED`, retry "with
  force_refresh_token set to the expired/invalid token string, which will
  fetch a new token or initiate a new consent flow".
- kode-gopher's vault spike (2026-09-30, `docs/design-in-cluster.md`,
  phase B): forcing a refresh of a still-valid token returned
  `uriConsentRequired`; after the hour-long token expired, a plain
  `retrieve` "silently returned a fresh token for the same `sub`", and a
  forced one minted another, with no consent; `expireTime` was once 4
  hours out when tokeninfo said 1.

So steward forces a refresh only for a token tokeninfo refuses (400 with
`error` `invalid_token`, which is also how an expired token answers), and
never for one Google still accepts. Asked to force a valid token, the
vault asked for consent, an answer that brings no token and says nothing
about the grant. steward used to force tokens with under 5 minutes left,
as kode-gopher does, and then (#20) to fall back to the valid token when
the vault asked for consent; this policy leaves that fallback unreachable,
and it is gone. A valid token is used if it has `need` left: at
refresh 75 seconds (an access token of at least 15 seconds, stopping a
minute before the Google token); at sign-in 90 seconds, allowing the
authorization code 15 seconds to be exchanged. Clients exchange within a
second or two; one that waits longer (`CodeTTL` allows a minute) may get
`server_error` at the exchange and start again, as it would have at the
redirect had the token been held back. Its access token stops a minute
before it, as always.

A token with less than `need` left can only be renewed by expiring.
steward waits it out (its remaining life plus 3 seconds, cancelled with
the request: at most 78 seconds at refresh, 93 at sign-in) and asks the
vault again, plainly: a fresh token is used; the expired token handed back
is refused by tokeninfo and forced, which the reference allows.

Consent to a forced refresh is checked once more with a plain retrieve
before it counts: another client of the same person may have forced the
same expired token a moment earlier, and the vault may refuse the stale
second force. A token other than the forced one that tokeninfo accepts
with `need` left goes on to the full checks (account, scopes, email) and
is used if it passes; anything else (consent again, pending, the same
token, a refused or short one) leaves the verdict, and failing to ask
(the vault or tokeninfo failing) is `server_error`. If the verdict stands and
the forced token is the one this request waited out, a refresh gets
`server_error`, not yet a sign-out, in case the vault lags tokeninfo by a
few seconds in counting the token expired; the next request does not wait,
forces the expired token again, and reads consent as the grant gone. A
sign-in detours through consent, as for any other consent request. This
does not protect against a vault that judged "expired" by its own
`expireTime` (once 4 hours out) and so answered every forced refresh of a
spent token with consent: refreshes would then still sign people out
hourly, one request later. The live check below (how soon after expiry
the vault renews) settles it.

steward waits once. A token still short after the wait, or one a forced
refresh brought, is `server_error` at once.

The wait matters because an active client's refresh lands exactly in that
window: its access token stopped a minute before the Google token, so it
refreshes when the Google token has a minute left. Answering that refresh
with `server_error`, as steward did when the vault would not force (from 3
minutes left), is not a cheap back-off: the MCP TypeScript SDK
(`client/auth.js` in 1.25.3) treats a `server_error` at refresh by
starting a new interactive authorization, so it would mean a browser
sign-in every hour. A client that refreshes whenever its access token has
less than some margin left refreshes on each request while the capped
access token stays inside that margin (one vault retrieve, one tokeninfo
and one rotation per refresh, at the client's own pace) until the wait
ends it; forcing had the same loop, with two vault calls per refresh from
5 minutes left.

**Ordering at refresh.** The wait runs before the refresh token's family
is rotated, through the sealed `Custody` interface's `prepare` step,
which the token endpoint calls first. A refresh:

1. opens and checks the refresh token (expiry, client, resource, scopes);
2. `prepare`: under `VaultCustody`, all the vault work, the wait
   included: retrieve, tokeninfo (account, scopes, email, life), the wait
   and the second retrieve, a forced refresh of a refused token. Nothing
   is rotated yet, so a failure (the vault or Google failing, the client
   going away) is `server_error` with nothing to give back.
   `SealedCustody` does nothing here;
3. rotates the family (reuse detection, the grace);
4. checks the allow-list;
5. answers a refusal from step 2 (`errReauth`) with `invalid_grant`, after
   the rotation, so the token stays spent and a replayed generation still
   revokes its family;
6. issues the grant step 2 prepared, the token every check was made on,
   with no second vault call. (Under `SealedCustody` the Google refresh
   happens here, after reuse detection, as before: it is quick, and a
   refresh token Google rotates is never lost to a refresh that is then
   refused.)

What this ordering means:

- **Concurrent refreshes.** Two processes of one client presenting the
  same refresh token while the token is nearly spent both wait, side by
  side, and rotate moments apart. Within `RefreshReuseGrace` the loser is
  refused without revoking and can re-read the winner's tokens from the
  shared store. Without a grace it revokes the family, as any concurrent
  refresh does; that is #18's trade-off, unchanged. The grace need not
  cover the wait as long as a refresh arriving during another's wait also
  gets the nearly spent token and waits too. If the vault renews early
  (before expiry, unverified), a later arrival can get a fresh token at
  once and rotate while the first still waits, and the first then loses
  the race by up to the rest of its wait: outside a short grace it revokes
  the family. If both force the same expired token, the vault may refuse
  the second ("not the latest token", or consent, which is checked again
  as above): `server_error` at worst, nothing rotated, and the retry finds
  the fresh token.
- **The client going away, or a front end timing out, during the wait.**
  Nothing is rotated, so nothing is given back and the retry, on any
  replica, works: no sign-out in steward's state. That needs steward to
  see the request end: the client's connection closing, or the front end
  closing or cancelling its backend request. A front end that answers
  the client with its timeout but keeps the backend request open lets
  the wait finish and the family rotate, and that answer goes nowhere.
  The client's retry then presents a refresh token the abandoned request
  spent: a replay, `invalid_grant` (the family revoked, or within
  `RefreshReuseGrace` refused and kept, but the tokens it was rotated to
  are lost either way), or, if it arrives during the wait, a concurrent
  refresh (above). Either way, a proxy's 504 is not
  an OAuth error, and an MCP client may answer it with a browser sign-in,
  so give the token endpoint, the sign-in callback and the consent return
  a front-end timeout of at least 2 minutes (78 or 93 seconds of wait plus
  the vault, tokeninfo and allow-list calls). Common defaults are shorter
  (a Google Cloud load balancer's backend timeout is 30 seconds, nginx's
  `proxy_read_timeout` and an AWS ALB's idle timeout 60); kode-gopher's
  GKE Gateway allows 900 seconds.
- **`http.Server.WriteTimeout` shorter than the wait.** Over HTTP/1.1 a
  write timeout does not cancel the request, so a refresh that waited and
  then rotated would have lost its answer, and the retry would be a
  replay. Over HTTP/2 it resets the stream, which cancels the request:
  every waiting refresh and sign-in would fail, nothing rotated. Each
  endpoint records the server's deadline before any other work, and
  before waiting, custody moves the response's write deadline
  past the wait plus 30 seconds (`http.ResponseController`), on the token
  endpoint, the sign-in callback and the consent return, and the token
  endpoint moves it 30 seconds past the rotation again, so slow vault
  calls after the wait cannot use it up (with a `WriteTimeout` under 30
  seconds, every refresh, waited or not, gets those 30 seconds). It only ever moves the server's
  own deadline (`WriteTimeout`, counted from when the handler starts)
  later: without a `WriteTimeout` it sets none, and it never shortens a
  longer one. The server starts its own count a little earlier (once the
  request's headers are read over HTTP/1.1, when the stream opens over
  HTTP/2), so time spent in middleware in front of these endpoints goes
  unseen: a wait whose end plus 30 seconds crosses the real deadline by
  less than that time is not extended. A `ResponseWriter` wrapped by middleware without `Unwrap` cannot be
  extended; there, or with slow middleware, keep `WriteTimeout` above 2
  minutes.
- **`http.Server.ReadTimeout` shorter than the wait** does not cancel it,
  in the Go this module requires (1.26.10): once the request body is read
  (sign-in requests have none; the token endpoint reads its form before
  any custody work), HTTP/1.1 clears the read deadline for the background
  read that watches for the client going away, and over HTTP/2 the
  timeout only closes the request body (`connReader.startBackgroundRead`
  and `http2stream.onReadTimeout` in net/http).
  `TestVaultWaitOutlastsReadTimeout` pins the HTTP/1.1 case.
- **Shutdown or a pod killed mid-wait.** Nothing is rotated until the wait
  is over. `Shutdown` lets the handler finish (rotate and answer); a kill
  leaves nothing to give back. Only the moment between the rotation and
  the answer remains, as for every refresh.
- **A replayed token** gets the vault work, wait included, before the
  rotation detects the replay and revokes the family. That costs vault
  calls, never a token: nothing is issued for it. But reuse detection now
  needs the vault and Google up: while either fails (or answers
  `pending`, or the request is cancelled), a replayed or revoked-family
  token gets `server_error`, with no revocation and no "reused" log line,
  until a request gets past `prepare`; and a client looping on a revoked
  token costs a vault retrieve and a tokeninfo call per attempt rather
  than a replay-cache lookup. A replay-cache peek before `prepare` (an
  optional interface) would restore both; it is left for a follow-up.
- **The grant ages** between step 2 and step 6 by the rotation and the
  allow-list check: a token prepared with 75 seconds left has 15 seconds
  of margin before the access token would be born expired, which
  `sealAccess` refuses (`server_error`, the rotation given back).

Tested live on 2026-11-01 (kode-gopher v0.4.0, vault custody): the user
removed the app's access at myaccount.google.com/connections and then
signed in again four times over about 5 minutes. Every sign-in completed
and the vault's token worked against Cloud Storage as that user: revoking
through myaccount did not invalidate the vault's grant within minutes. So
a token tokeninfo refuses, forced, then consent meaning the grant is gone
was not exercised, and that reading remains the reference's, unverified.
A later attempt could revoke the vault's token directly through Google's
OAuth revoke endpoint.

Not yet seen live, and what a check on the real vault should settle:
what a plain `retrieve` returns for a valid token with 5 minutes, 1
minute and 10 seconds left (the same token, or a fresh one early: if
fresh, the wait never happens); how soon after tokeninfo's expiry a plain
`retrieve` renews (immediately, or only at the vault's own `expireTime`,
in which case the forced refresh of the expired token does it); whether
forcing a valid token near expiry (1 minute left) also asks for consent;
whether a consent answer to a forced valid token leaves a plain
`retrieve` working; what forcing a revoked token returns (consent, as
the reference implies); and whether a forced refresh of a token another
caller has just force-refreshed is refused or asks for consent.

A grant only the user can repair is `access_denied` at sign-in and
`invalid_grant` at refresh (the client signs the person in again): consent
declined, another account's grant, a missing scope, a changed email,
Google's `invalid_grant` on a sealed refresh token, and a vault token
tokeninfo refuses both before and after a forced refresh. The vault asking
for consent (on a plain retrieve, after a token was waited out, or after
forcing a token Google refused, checked once more) is the consent detour
at sign-in and `invalid_grant` at refresh, except consent to renew the
token a refresh just waited out, which is `server_error` once (Vault
renewal). Google or the vault failing is `server_error`, and at refresh
gives the refresh token back (or, failing before the rotation, never
took it), so a retry may work: no
answer, any HTTP error from the vault, a tokeninfo answer other than 200
or a 400 `invalid_token` (an egress proxy's 400 included), the vault
answering `pending` (its API reference: "the caller should retry ... after
some time") or nothing usable, a forced refresh that returns the same
token, and a token too close to expiry to use (above). A vault error
message that quotes a forced token back has it replaced before it is
logged.

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
conditional `Unrotate` in case it was applied.

**Rotation IDs.** A refresh rotates its family first and gives the
rotation back if it then fails for a transient reason (the directory,
Google or the vault unavailable, sealing failing), so the client's retry
is not taken for a replay. `Unrotate` is conditional only on the
generation, which a shared cache makes unsafe: when replica A's `Rotate`
fails without applying (or times out, outcome unknown) while replica B's
refresh with the same token applies, A's `Unrotate` gives back B's
rotation, and A's client's retry rotates the family again. A rotated token
has yielded tokens and two refresh tokens of the next generation are
live: a second branch of the family, so whichever holder refreshes second
is never caught presenting a rotated token. A cache closes that by also
implementing `RotationIDReplayCache` (additive beside `ReplayCache`, like
`GraceReplayCache`; `MemoryReplayCache` implements it). The server then
rotates with `RotateWithID`, carrying a fresh random ID per refresh (and
the grace, if one is set), and gives back with `UnrotateWithID` and that
ID, which does nothing unless the family is at the next generation by
that very rotation.

- *An unknown outcome.* After a `RotateWithID` error the server still
  gives the rotation back and answers `server_error`: if the rotation
  applied, it is undone and the retry works; if it did not and another
  refresh rotated the family, that rotation stands and the retry is a
  replay (refused, and revoking outside a grace), which is the truth: the
  token was spent. A write that lands after the give-back meant to undo it
  either rotates the family with no token issued for it or, if another
  refresh rotated it meanwhile, is a replay (revoking, or refused in a
  grace); either way the retry is refused and the user signs in again: a
  sign-out, never a second branch. The same call delivered twice (a cache
  client retrying after a lost reply) is not a replay: `RotateWithID` is
  idempotent for its own ID, reporting the rotation applied and changing
  nothing, and a duplicated `UnrotateWithID` finds nothing to give back.
- *State.* One more value per family, the ID of the rotation that moved
  it to its current generation, set atomically with the generation by
  every rotation (`Rotate` and `RotateGrace` set none, which no ID
  matches), so a replaced rotation's ID never matches again. A refusal
  leaves it; a give-back clears it, since the rotation it named no longer
  exists. The in-memory cache keeps one 26-character ID per family, so
  storage still grows with families, not refreshes.
- *Rolling upgrades.* The fix holds once every server sharing the cache
  calls the ID methods: a replica still running older code calls
  `Unrotate` after a `Rotate` error, which can give back a newer
  replica's rotation.
- *Caches without it.* A shared cache that does not implement the
  interface keeps today's behaviour: `Rotate` or `RotateGrace`, then the
  generation-only `Unrotate`, including after a `Rotate` error. That is
  racy under sharing as above; it is kept rather than skipping the
  give-back after an error, because the `ReplayCache` contract promised
  it and a timeout after a write would otherwise sign the person out. The
  race needs a give-back after a `Rotate` error, or an `Unrotate`
  delivered twice: after a rotation that did apply, no other request can
  have moved the family on, since the token that would do it has not been
  issued (unless an earlier racy give-back already let a second rotation
  in).

**Reuse grace.** MCP clients whose processes share one token store (for
example two Claude Code processes, or one client refreshing from several
goroutines through a token source that does not serialize them) present
the same refresh token twice within milliseconds when they refresh at
once. Without a grace the second presentation revokes the
family, the first one's fresh tokens with it, and the person is signed out
of every process. So an operator can set `Config.RefreshReuseGrace` (off
by default; 10 s is a reasonable value): for that long after a rotation,
presenting exactly the generation the family has just
moved away from is refused with `invalid_grant` but does not revoke the
family: the winner's tokens stay valid, and a client with a shared store
re-reads them. An older generation, the same one after the window, or any
token of a revoked family still revokes. Nothing is ever issued for a
rotated token, so the grace never adds a live token (unlike the reuse
intervals of some providers, which hand out a second set), and both
refusals read the same to the client, so a thief cannot tell whether the
family survived. The log tells them apart.

- *Concurrency.* The rotation is the cache's atomic step at the start of
  the refresh, so the first request to reach it wins; the second, still in
  flight or not, is refused at the same step. If the winner then fails for
  a transient reason, its `Unrotate` moves the family back and forgets the
  grace, so the shared token works again for both, and the generation
  before it is a replay again. A loser's give-back after a failed
  `Rotate` cannot undo the winner's rotation (rotation IDs, above), so it
  cannot make the loser's token live again either; with a cache without
  rotation IDs it can, as it could before the grace.
- *State.* One more time per family, the grace deadline of its last
  rotation, kept and checked with the generation. A cache supplies it by
  implementing `GraceReplayCache` (`RotateGrace`, additive beside
  `ReplayCache`, so existing shared caches still compile) or
  `RotationIDReplayCache`, whose `RotateWithID` carries it; one that does
  neither gets no grace and revokes on every reuse, as before. Replicas sharing
  a cache share the grace. With a per-replica `MemoryReplayCache`, the
  second presentation on another replica is the per-replica weakness above
  (a fresh rotation there), with or without a grace. The deadline is an
  absolute time from the server's clock, like the family's expiry, so
  clock skew between replicas stretches or shrinks the window by the skew.
- *What it costs.* Reuse detection (RFC 9700 §4.14.2) works by one of two
  holders of a token presenting it after the other has rotated it. Within
  the window that presentation is refused but not reported by revocation.
  If the victim refreshes first, the thief's token is dead anyway; the
  window only spares the victim the sign-out, and a thief retrying after
  the window revokes as before. The loss is the other order: a thief who
  refreshes less than the window before the victim's next refresh keeps
  the family, if the victim's client then signs in afresh rather than
  presenting the stale token again (which, after the window, revokes). A
  thief who cannot see the victim's schedule lands there with probability
  about window ÷ refresh interval: with a 10 s grace and 15-minute
  access tokens, about 1 %. One who knows the victim's token expiry (it
  sits in the same store) can aim for it; the window bounds how precisely
  they must aim, and no window short of zero removes it. That loss, and
  the go-sdk client's limited benefit below, are why the grace is off by
  default: an operator whose clients share a token store and see these
  sign-outs turns it on. 10 s covers a winner's round trip from rotation
  to writing its store (admission, one or two Google or vault calls, the
  response); the limit is a minute, and a negative value is refused.
- *Clients.* The grace helps a client that, refused, re-reads its store
  before trying again; it is for such clients that it exists. The go-sdk
  MCP client (v1.8.0) does not: its token source
  (`oauth2.Config.TokenSource`) serializes refreshes per handler, so it
  collides only across handlers or processes that share tokens (through
  `NewTokenSource` or `InitialTokenSource`). On `invalid_grant` it sends
  the request without a token and runs `Authorize` on the 401, keeping the
  stale token source until a new sign-in completes. Any request it sends
  meanwhile, after the window, presents the stale token again and revokes
  the family, so for it the grace often only delays the sign-out; a
  `NewTokenSource` that re-reads the shared store on `invalid_grant`
  avoids that. (In the theft case, that later presentation is what
  restores detection.) A client that loses a refresh response and retries
  with the old token within the window gets `invalid_grant` (it lost the
  new token) and signs in again; the family it leaves behind expires.

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
pluggable replay cache and keys, slog, the consent page's text being the
service's `ServiceName`). Most came from this port's adversarial review,
and most of those have since been ported to kode-gopher (state as of
kode-gopher `66fbee8`, which is v0.4.0 plus docs):

- **Not ported:** the reuse grace that spares a concurrent refresh's
  family (steward#18); flow cookies `__Secure-` on an https issuer with a
  path (kode-gopher sets every cookie on `/`, so `__Host-` always fits).
- **Port in progress:** rotation IDs, so a refresh gives back only its
  own rotation (steward#22); a vault token Google still accepts is never
  force-refreshed: it is used down to 75 seconds at refresh (90 at
  sign-in), and one with less is waited out and retrieved again, before
  the refresh token's family is rotated (steward#23, Vault renewal,
  above).
  kode-gopher#56 still forces one with under 5 minutes left, and keeps
  it if the vault then asks for consent and it has 3 minutes left.
- **Not needed there** (one fixed scope, a keyring loaded once at
  startup): refresh re-checks the grant's scopes against the
  configuration; a narrowing refresh does not narrow the grant; the keys
  being unavailable is `server_error`, never `invalid_grant`; scopes are
  granted in the configuration's order, so a grant reads the same however
  the client ordered its request.
- **Ported:** more than one `resource` parameter is refused, custody
  failures that are Google failing are `server_error` rather than
  `access_denied`, and error descriptions keep to RFC 6749's character set
  (kode-gopher#51); refresh-token families with reuse detection instead
  of one replay entry per refresh, rotating a workload's secret revokes
  its tokens, an email change since sign-in forces a new sign-in, the
  refresh token's audience is checked against the configured resource,
  and an authorization code is given back if sealing the tokens fails
  (kode-gopher#52); client-resolution errors (CIMD contents, dial errors)
  are not echoed, the SSRF filter also refuses NAT64, 6to4, Teredo, zoned
  and other special-purpose addresses, client secrets are compared by
  digest, a static client's redirect URIs are validated at load and its
  slices copied, and Google's endpoints must be https (kode-gopher#53); a
  cached group name is looked up again on a 403 as well as a 404
  (kode-gopher#54); a client's name is cleaned and kept apart from its
  client ID and redirect host on the consent page (kode-gopher#55, see
  Client names above); a `pending` or empty vault answer is
  `server_error` (a sign-out before), and a vault token tokeninfo refuses
  is force-refreshed once, then a consent detour at sign-in or a refusal,
  rather than `server_error` (kode-gopher#56).

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
first. `6cacac1` (kode-gopher#54), tests only: a retry that reads a group
name another check has just cached costs no lookup (the `retried`
guard), and a nested group's 403 or 404 leaves the root's cached name
alone. `7e11b72` (kode-gopher#55), tests only: a CIMD client's resolved
name is clean, and the consent page cleans a name whatever reaches it.
steward had the code right; nothing tested it. `2f33327` (kode-gopher#56),
in part: a tokeninfo 400 is Google refusing only with `error`
`invalid_token` in its body; any other 400 (an egress proxy's) is
`server_error`. kode-gopher has no Path A; steward applies the same rule
in `googletoken`, where such a 400 is `ErrUnavailable` (Verification,
above).

The reviews of those ports also found bugs that steward fixed first:
zoned IPv6 addresses passing the SSRF filter (steward#12, from
kode-gopher#53), a recreated group's 403 (steward#16, from
kode-gopher#50), bidi characters in client names (steward#17, from
kode-gopher#53) and a busy vault signing people out (steward#20, from
kode-gopher#51).

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
