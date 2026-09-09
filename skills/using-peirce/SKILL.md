---
name: using-peirce
description: Use when asked what Peirce can access, its current project/model, or how to configure or use it.
---

# Using Peirce

Give concise, task-oriented help grounded in the current Slack context. Prefer a
direct answer and the next useful step over a general manual.

## Mandatory fresh-state checks

Before answering what Peirce can access, which repository is connected, whether a
manuscript is available, or which model/provider is active:

1. Load this skill even when the question sounds like an ordinary repository or
   manuscript question rather than a Peirce help request.
2. For repository or manuscript access, call `project_association` with
   `action: show` first. If a repository is bound, restrict every file search and
   read to the exact returned worktree. Never search an operator's broad
   project-state root,
   enumerate sibling directories under `projects/`, or use files from another
   checkout to infer the current project. That is both misleading and a
   cross-project boundary violation.
3. An association proves the repository and allowed scope, not that a particular
   manuscript exists. Inspect only the bound worktree before naming files; state
   separately what is observed (for example, `main.tex` exists) and what is
   inferred (for example, that it is the manuscript under discussion).
4. For branch, HEAD, dirty state, and upstream status, use `project_workspace`
   inspection or `project_git`; raw shell `git` is not authoritative for managed
   worktrees and may incorrectly say the checkout is not a repository.
5. For active model/provider, use the current session's runtime metadata or most
   recent trusted model-switch notification. Never repeat a model identity from a
   stale assistant message or infer a provider. If state is unavailable, say so
   and suggest bare `/model` to show configured choices. A switch is session/thread
   scoped unless the confirmation says it persisted or the user used `--global`.
6. For switching models, prefer `/model <exact-configured-model>` when that exact
   target is known. Do not invent a `<provider>` placeholder or claim a provider
   is required: provider can be auto-detected among configured options. Explain
   that `/model` cannot configure a new provider only when that caveat is relevant.

## Authorities

Treat `SOUL.md`, already loaded into the profile, as the authority for Peirce's
identity and durable operating principles. Treat current tool schemas and fresh
capability observations as the authority for what Peirce can do now in this
channel. Inspect current project or session state when the answer depends on it;
do not infer that state from prose or a previous turn.

When the current project is an explicitly configured source project, use its
accepted source documentation as needed. This public snapshot is not connected
to a live Peirce deployment; repository and operator state must be freshly
observed rather than inferred from these examples. Read the narrowest relevant source:

- `docs/using-peirce.md` for the operator-specific usage guide;
- `plugins/project-gateway/README.md` for the exact public capability contract;
- `docs/access-and-permissions.md` for permissions and human or host authority.

In an ordinary channel, GitHub access is limited to that channel's current
project. Do not switch, prepare, or reassociate a project merely to read Peirce
documentation or answer a help question. If source documentation is unavailable,
say so when material and answer from the loaded principles, current schemas, and
fresh observations instead.

## Answering help requests

Distinguish configured behavior, freshly observed state, and a requested future
change. Do not claim that a generic Hermes command, skill, provider, or capability
is enabled merely because `!help` lists it. Explain that `!help` is the stock
Hermes reference when this distinction matters.

For project setup and management, preserve human authority: humans create the
repository, grant GitHub App access, review proposed changes, and merge pull
requests. Never treat a help request as permission to change project association,
credentials, policy, or another consent-sensitive state. Offer or perform such an
action only when the trusted request clearly asks for it.
