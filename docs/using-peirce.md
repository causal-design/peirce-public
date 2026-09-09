# Using Peirce

This guide is the operator-specific usage reference for the public Peirce
showcase. It describes example configuration and behavior, not a live service;
deployment owners must supply and freshly verify their own Slack, GitHub, host,
model, and image state.

## Get started

In a deployment that has been configured and approved by its operator, invite
Peirce to the intended Slack channel and mention it with a clear request. Include
the question, scope, relevant sources, desired deliverable, validation criteria,
and important uncertainty when they matter. Do not send credentials or secrets
to Peirce. Direct messages and bot-authored requests are not supported by the
example contract.

`!help` is the stock Hermes command reference and may mention capabilities that
are unavailable in a particular deployment. Ask Peirce about current access,
project, or model state only after it performs the required fresh-state checks.

Normal persistent tool-progress messages and command/path previews are absent.
Full-command progress is disabled. Verb-only ephemeral status updates contain
no arguments. Natural interim commentary remains enabled. The configured
100-character budget is a dormant defense-in-depth bound for any
preview-capable path, including generic tool previews; it is not observed in
ordinary turns. If such a path is enabled later, truncation is not redaction,
and terminal commands and tool arguments must already be safe for persistent
Slack history.

## Session controls

Send commands as fresh Peirce mentions in the active thread:

| Slack message | What it does |
| --- | --- |
| `@Peirce !status` | Show session, model/provider, context, and run state. |
| `@Peirce !model` | Show current model/provider and available choices. |
| `@Peirce !model <name> [--once]` | Select a model for the session or next turn. |
| `@Peirce !reasoning [level]` | Show or set reasoning effort. |
| `@Peirce !stop` | Request cancellation of the active run. |

Session overrides are thread-scoped unless the runtime explicitly confirms
otherwise. Model/provider names in `config.yaml` are illustrative aliases, not
proof that a provider is configured or reachable.

## Project work

Each authorized channel normally has one active project. A human creates the
repository and grants the GitHub App access; Peirce does not create repositories
or grant itself access. The example fixed routes are
`peirce-example/peirce` (ID `101`) and `peirce-example/peirce-admin` (ID `202`).
They are unverified placeholders. The public repository
`causal-design/peirce-public` is not a runtime source/admin association.

Within the current project, the gateway can inspect state, prepare bounded local
Git changes, publish ordinary task-branch updates, and work with reviewed GitHub
issues, pull requests, checks, statuses, and comments. Humans review proposed
changes and decide whether to merge. Peirce does not silently cross project
boundaries, force-push, merge provider pull requests, administer repositories,
or change secrets and workflows.

See the [project-gateway capability contract](../plugins/project-gateway/README.md)
for exact boundaries and the [access ledger](access-and-permissions.md) for
authority and credential scope.

## Privacy and self-development

Never paste tokens, private keys, OAuth state, session data, or other credentials
into Slack or a repository. Shared profile memory is not private per-user
storage. A public repository is never a raw runtime-memory sync target, and live
learning must not be exported wholesale.

Before pushing a branch or opening a pull request, review all private, personal,
and live-learning content. Publication is only a human-reviewable proposal;
merge and deployment are separate operator decisions. The checked-in memory
files are privacy-safe empty starters, not live profile evidence.

## References

- [`../AGENTS.md`](../AGENTS.md) — contributor and agent guidance
- [`../SOUL.md`](../SOUL.md) — durable profile principles
- [`../skills/using-peirce/SKILL.md`](../skills/using-peirce/SKILL.md) — fresh-state help routing
- [`../skills/peirce-self-development/SKILL.md`](../skills/peirce-self-development/SKILL.md) — reviewed source improvement
- [`../config.yaml`](../config.yaml) — illustrative non-secret configuration
