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

> **Status: phase 0.** The repository and the design are in place; there is
> no exported API yet. The first release (v0.1.0) is Path A: accepting the
> per-user tokens a Gemini Enterprise app sends to a Custom MCP Server.
> See [`docs/DESIGN.md`](./docs/DESIGN.md) and the
> [Path A issue](https://github.com/go-steer/steward/issues/1).

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
