# Changelog

All notable changes to this module are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the module
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html); before
1.0, a minor version may change the exported API (see "Changing the
exported API" in [`CONTRIBUTING.md`](./CONTRIBUTING.md)).

## [Unreleased]

### Added

- **The repository and its design.** `docs/DESIGN.md` sets out how steward
  sits on purser, Path A (accepting the per-user Google tokens a Gemini
  Enterprise app sends), Path B (a service as its own authorization server,
  later), the hard rules, and the phase plan. The `dev/` tooling, CI,
  adversarial-review gate and agent-attribution check follow purser and
  supercargo. No exported API yet.
