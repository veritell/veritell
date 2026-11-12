# Security

## Reporting

Report a vulnerability or a detection bypass privately, through this
repository's **Security** tab (**Report a vulnerability**). Please don't
open a public issue, pull request or discussion for either.

A detection bypass counts: a way for automated traffic to pass as a person,
or for a client to forge what the gateway relies on (probe reports,
behaviour summaries, tokens, challenge solutions, signatures).

Include what you can of:

- the version or commit, and how the gateway was run (flags, policy);
- what you did, what the gateway did, and what you expected;
- the smallest request or script that shows it.

Leave out real visitors' addresses and other personal data.

## What happens next

Veritell is maintained by one person, so these are targets, not promises:

- an acknowledgement within 7 days;
- an assessment within 30 days;
- a fix, or a plan for one, before anything is disclosed. We agree the
  disclosure date with you; 90 days is the default.

Credit in the release notes is yours if you want it. There is no bug bounty.

## Supported versions

Only the latest commit on `main` gets fixes.

## Scope

In scope: the gateway (`crates/`), the browser probe and behaviour script
(`probe/`), the rollout kit (`deploy/`) and the sidecar configurations
(`sidecar/`).

Out of scope: the lab clients in `lab/` (they are attack tools on purpose),
denial of service by sheer volume, and findings that need control of the
host the gateway runs on.
