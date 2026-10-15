# steward

Act as the caller: Google sign-in and per-user Google tokens for
[go-steer](https://github.com/go-steer) MCP and HTTP services, on top of
[purser](https://github.com/go-steer/purser).

A purser checks who is aboard; a steward looks after passengers' belongings
on their behalf. Given a request carrying a person's Google access token,
steward decides whether the token is good for this service, who it belongs
to and whether that person is let in, then hands the service a
`purser.Caller` and a token source for calling Google APIs and GKE clusters
**as that person**. What they can see is then what their own IAM and
Kubernetes RBAC allow.

> **Status: v0.1.0, Path A.** Verification (`googletoken`), admission
> (`allow`), request wiring (`httpauth`) and MCP session binding
> (`mcpauth`). Pin [`v0.1.0`](./CHANGELOG.md) rather than a commit.
> Pre-1.0, the exported API may break at a minor version. See
> [`docs/DESIGN.md`](./docs/DESIGN.md) and the
> [Path A issue](https://github.com/go-steer/steward/issues/1).

## Use

Protect an MCP endpoint that a Gemini Enterprise app calls with each
person's Google token, and read Google APIs as that person:

```go
v, err := googletoken.New(googletoken.Config{
	ClientIDs:      []string{oauthClientID}, // the client Gemini Enterprise is configured with
	RequiredScopes: []string{"https://www.googleapis.com/auth/cloud-platform"},
	Logger:         slog.Default(), // so a Google outage is visible
})
admit, err := allow.Parse([]string{"@example.com", "contractor@gmail.com"})
a, err := googletoken.NewAuthenticator(v, admit)
p, err := httpauth.New(httpauth.Options{
	Authenticator: a,
	Resource:      "https://svc.example.com/mcp",
	Scopes:        []string{"openid", "email", "https://www.googleapis.com/auth/cloud-platform"},
})

mux.Handle(p.MetadataPath(), p.MetadataHandler())  // RFC 9728, unauthenticated
mux.Handle("/mcp", mcpauth.Middleware(p)(mcpHandler)) // or p.Middleware() for stateless HTTP

// In an MCP tool handler (stateful sessions): read from the request, not
// the context, which the SDK freezes at the session's first request.
ts, _ := mcpauth.TokenSource(req) // the person's own Google token, for this call
id, _ := mcpauth.Identity(req)    // id.Email, id.HD, id.Subject

// In a plain HTTP handler behind p.Middleware():
caller, _ := purser.CallerFromContext(r.Context())   // caller.Identity is the email
ts, _ = httpauth.TokenSourceFromContext(r.Context()) // their own Google token
```

## Why it exists

Several go-steer services need the same thing: let a person reach the
service through an agent such as Gemini Enterprise, and have the service
read on that person's behalf, with that person's permissions, instead of
with one shared service identity.

- **supercargo** checks Gemini Enterprise users' Google tokens today, in its
  own `internal/googleauth`.
- **k8s-lookout** needs the same check plus the token itself, so its
  Kubernetes and Cloud reads run as the person
  ([k8s-lookout#699](https://github.com/go-steer/k8s-lookout/issues/699)).

Doing it once means one implementation of the parts that are easy to get
subtly wrong: checking that a token was issued to *your* client, telling
Google failing from Google refusing, and not trusting an email suffix as
proof of a Workspace domain.

## Two paths

| Path | Who holds the user's Google grant | For | Status |
|---|---|---|---|
| **A** | The client (Gemini Enterprise); the service checks the token it sends | Gemini Enterprise Custom MCP Servers | first |
| **B** | The service, as its own OAuth 2.1 authorization server | MCP clients that register dynamically (Claude Code, gemini-cli, IDEs) | later |

## Development

See [`CONTRIBUTING.md`](./CONTRIBUTING.md) and [`AGENTS.md`](./AGENTS.md).
`dev/tools/ci` runs every presubmit locally; [`dev/README.md`](./dev/README.md)
describes each one.

## License

Apache 2.0 — see [`LICENSE`](./LICENSE).
