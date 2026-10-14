# Opt-in Claude Code config for this repo

`settings-review-gate.json` — a `PreToolUse` hook that blocks
`gh pr create` locally when neither `--body` nor the `--body-file`
file contains an "Adversarial review" section, mirroring the
`review-gate` required CI check (see AGENTS.md "How we develop").

Opt in by merging it into your **personal, untracked**
`.claude/settings.json` at the repo root (or `~/.claude/settings.json`
for all projects). It is deliberately NOT committed as live config —
assistant harness settings are personal tooling; the repo-native
enforcement is AGENTS.md + the required CI check.

This mirrors the identical setup in
[core-agent](https://github.com/go-steer/core-agent),
[k8s-lookout](https://github.com/go-steer/k8s-lookout) and
[switchboard](https://github.com/go-steer/switchboard); a maintainer of
one repo should recognize the others.
