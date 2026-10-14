# Contributing to steward

Thanks for contributing. steward follows the same contributor flow as
[core-agent](https://github.com/go-steer/core-agent) — a maintainer of one repo
should recognize the other.

## Workflow

- Single long-lived branch: `main`. Work on short-lived feature branches
  (`feat/…`, `fix/…`, `chore/…`, `docs/…`) → PR against `main` → merge
  once CI's required checks are green.
- **Rebase, don't merge.** Keep feature branches rebased on `main`;
  `git push --force-with-lease` on your own branch is normal. Never
  force-push `main`.

## Commits

- **Conventional Commits** subject lines: `feat:`, `fix:`, `docs:`,
  `chore:`, `refactor:`, `test:`, `ci:`, `build:`. Bodies explain *why*
  and call out the verification done.
- **DCO sign-off** on every commit: `git commit -s` (adds a
  `Signed-off-by:` trailer certifying the [Developer Certificate of
  Origin](https://developercertificate.org/)).
- **No `Co-Authored-By` trailer, and no assistant attribution anywhere.**
  Maintainer preference: author the work under your own name. Do not add
  `Co-Authored-By:` lines, "Generated with …" footers, or any
  tool/assistant credit to commits, PR titles/bodies, or other committed
  or published artifacts.

## Before you push

- Run `dev/tools/ci` — the full presubmit sweep, the same scripts CI
  runs (`dev/ci/presubmits/*`). A green local run is the green remote
  run.
- **Adversarial-review gate** on any PR touching Go code — see
  [`AGENTS.md`](./AGENTS.md) "How we develop". Record the outcome under an
  `## Adversarial review` heading in the PR body; the `review-gate`
  required CI check enforces it.

## Changing the exported API

steward is consumed as a Go module, so the exported surface *is* the
product: a removed field or a changed signature breaks a consumer's build
at `go get`. `dev/tools/verify-apidiff` compares the module's exported API
against the last release tag and fails on incompatible changes that
[`dev/api-breaks.txt`](./dev/api-breaks.txt) does not acknowledge.

Pre-1.0 the project reserves the right to break the surface at a minor
version — but "you may break it" is not "you may break it silently".
To make a deliberate break:

1. Run `dev/tools/verify-apidiff` locally. Copy the lines it prints under
   *Incompatible changes* into `dev/api-breaks.txt`, minus the leading `- `.
2. Add a `#` comment above them naming the PR or issue and the reason.
3. Commit both in the PR that makes the change, and record it under
   *Changed* or *Removed* in `CHANGELOG.md`.

Cutting a release empties the file: once the tag moves, those breaks sit
behind the new baseline, and a leftover entry would silently permit a
second, unrelated removal.

Prefer not to need the escape hatch. Add an option to a struct rather than
a parameter to a function; deprecate with an alias before removing.

## Cutting a release

A tag is not ceremony here — it is what gives `verify-apidiff` a baseline.
Before the first one it had nothing to compare against and skipped every
run, so the guard on the exported surface was inert. Keep tags coming or
that check quietly stops working.

1. **Land everything first.** `main` green, working tree clean.
2. **Close the changelog.** Rename `## [Unreleased]` to
   `## [X.Y.Z] - YYYY-MM-DD`, open a fresh `## [Unreleased]` above it with
   *Nothing yet.*, and add the two link references at the bottom of the
   file (`[Unreleased]` compares `vX.Y.Z...HEAD`; `[X.Y.Z]` points at the
   release tag).
3. **Empty [`dev/api-breaks.txt`](./dev/api-breaks.txt).** Once the tag
   moves, those breaks sit behind the new baseline; a leftover entry would
   silently permit a second, unrelated removal of a symbol that is already
   gone. Leave the header comments, drop the entries, and update the
   trailing note to name the new version.
4. **Merge that as its own `chore/release-vX.Y.Z` PR**, so the tag lands on
   a commit whose changelog already describes it.
5. **Tag the merge commit and push it:**
   ```bash
   git tag -a -s vX.Y.Z -m "vX.Y.Z"   # annotated + signed
   git push origin vX.Y.Z
   ```
6. **Verify the baseline took.** `dev/tools/verify-apidiff` should now
   report against the new tag instead of skipping.

Which number: pre-1.0, a breaking change is a **minor** bump (`v0.2.0`),
not a major one — `v0.x` reserves that right and the module path stays
unsuffixed. Post-1.0 an incompatible change means `v2` and a `/v2` module
path, and `dev/api-breaks.txt` should be empty on every release branch.

## Tests

Every new package ships with unit tests. A new feature without a test
is not done; a bug fix without a regression test lets the bug come back.

Auth code has a particular failure mode: a test that only asserts the
happy path passes just as well against a check that never runs. Every
verification path needs its negative case — the wrong CA, the expired
SVID, the peer whose identity the authorizer rejects — and an assertion
that the call *failed*, not merely that it returned something.

Mint certificates in-process from a test CA. No private keys in the repo,
not even expired ones.

## Coverage floors

`dev/tools/verify-coverage` holds every package to a floor in
[`dev/coverage-floors.txt`](./dev/coverage-floors.txt), reading the profile
`dev/tools/test-unit` writes. Per package, not one number for the module:
a repo-wide average lets a large, easily-covered package fund the gaps in a
small dangerous one.

This is a floor, not a bar. Coverage cannot tell a real assertion from a
vacuous one — an auth test that executes every line of a check and asserts
nothing about its verdict scores the same as one that would catch a
bypass. It says only that a branch was executed once, which is the weakest
useful claim and still worth having: the characteristic failure in this
repo is a verification path no test ever reaches.

- **A new package needs an entry.** Without one the check fails rather than
  letting the package in unmeasured. The tool prints the line to paste.
- **Lowering a floor is allowed** — in the PR that makes it necessary, with
  a `#` comment saying why, so the reviewer sees it next to the code.
- **Raising one** is never required to merge; the tool nags when a floor has
  drifted far enough below the truth to have stopped protecting anything.

## License

By contributing you agree your contributions are licensed under the
project's [Apache 2.0](./LICENSE) license. Every Go / shell / YAML source
file carries the Apache 2.0 header attributed to Google LLC.
