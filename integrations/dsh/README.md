# @twinsearth/nau-dsh-plugin

NewAgentUniverseByDeepSeek tools for **DeepSeek Harness**.

## What this is

A DSH **bundle**: an npm package a profile lists in `dsh.profile.bundles`, contributing one
Cordis plugin — `@twinsearth/nau-dsh-plugin/tools` — which registers five **read-only** tools over
the `nau` command line.

| Tool | Answers |
|---|---|
| `nau_version` | project version, wire protocol, and **both** upstream releases this build names |
| `nau_inspect` | what a data directory restores to, plus the ledger audit — without starting a daemon |
| `nau_conformance` | whether this build still agrees with the shared conformance vectors |
| `nau_amount` | an exact decimal as the integer minor units this project stores |
| `nau_node_status` | whether something is listening on a host and port, and which binary would be used |

## Install

```sh
dsh plugin --profile <profile> add @twinsearth/nau-dsh-plugin
```

Or from a checkout or tarball:

```sh
dsh plugin --profile <profile> add /path/to/nau-dsh-plugin
dsh plugin --profile <profile> add ./twinsearth-nau-dsh-plugin-3.4.5.tgz
```

The manager installs, **validates**, and rolls back if validation fails — so a bad package leaves
the profile as it was.

## Point it at your binary

The tools run `nau`. Resolution order:

1. `config.bin` on the patch entry (what the shipped `cordis.patch.yml` sets),
2. `NAU_BIN` in the environment,
3. `nau` on `PATH`.

When none of them finds an executable the tool returns an error **naming the setting to fix**
rather than an empty success. Edit the `bin:` line in `cordis.patch.yml`, or drop it and set
`NAU_BIN`.

## What is deliberately not here

**Driving the node is not exposed.** Starting or stopping a daemon, depositing funds and sending
bus messages are privileged, audited operations in this project with their own refusals. A tool
that reached past them to `execFile` would make the audit trail optional, so the honest surface
today is read-only. A privileged surface belongs here only when it can carry the project's own
approval rules — not as a shell wrapper that happens to be shaped like a tool.

## Fail-closed choices

- Arguments are passed as an **array**, never a shell string: nothing here can make a caller's
  text be interpreted as a command.
- Every invocation is bounded by a timeout and an output cap.
- A non-zero exit is **reported with its stderr**, not thrown away: the CLI's refusals are
  answers, and hiding them would discard the most useful part.
- `nau_node_status` says only whether a TCP connection was accepted, and says so in the answer —
  a port that answers is not a node that agrees with you.

## Provenance

Built by the NewAgentUniverseByDeepSeek project; the tools report that project's own version
rather than this package's. See
<https://github.com/TwinsEarth/NewAgentUniverseByDeepSeek>.

Licence: MIT.
