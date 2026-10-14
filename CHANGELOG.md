# Changelog

All notable changes to this module are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the module
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html); before
1.0, a minor version may change the exported API (see "Changing the
exported API" in [`CONTRIBUTING.md`](./CONTRIBUTING.md)).

## [Unreleased]

### Added

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
