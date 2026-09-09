# Access and permissions ledger

This checked-in, non-secret ledger describes the example permissions and trust
boundaries for this public showcase. The [plugin contract](../plugins/project-gateway/README.md)
is authoritative for exact capabilities and behavior; this ledger is
authoritative for credential permissions and human/host authority. Nothing here
proves a deployment or live cutover. Any authorized channel member may use the
registered gateway capabilities; there is no owner-membership gate.

## Public architecture

For permission review, the `project-gateway` manifest and runtime register exactly:

| Capability | Actions | Authority |
|---|---|---|
| `repository_access` | `observe` | Read-only candidate repository observation |
| `project_association` | `show`, `set`, `clear` | One schema-v2 SQLite association effect |
| `project_workspace` | `inspect`, `initialize`, `fetch`, `learning_snapshot` | One local initialization, remote fetch, or bounded profile read |
| `channel_bookmarks` | `list`, `add`, `delete` | Trusted current-channel Slack bookmarks |
| `project_git` | `help`, `run`, `commit`, `remote_ref`, `push`, `delete_remote_branch`, `checkout_default` | Static policy or one local/remote Git effect |
| `project_github` | `help`, `run`, `comment_delete` | Exact current-project GitHub collaboration |
| `risk_report` | `create` | One fixed-admin issue creation |

These capabilities do not expose lifecycle, publication-recovery, comment-confirmation, profile-publication, or embedded-report workflows. Peirce composes independent effects and decides sequencing, recovery, consent, significance, and completion.

## GitHub App and runtime tokens

The host GitHub App is the credential broker. Installation selection breadth is not a repository selector. Each mint is narrowed to one immutable repository ID and one reviewed permission profile:

| Effect | Exact requested permissions | Recipient |
|---|---|---|
| Repository observation | `metadata:read` | Bounded provider observation |
| Workspace fetch or remote observation | `metadata:read`, `contents:read` | Sterile Git child |
| Task-branch push or exact non-default deletion | `metadata:read`, `contents:write` | Sterile Git transport child |
| Current-project collaboration | `metadata:read`, `contents:read`, `issues:write`, `pull_requests:write`, `checks:read`, `statuses:write` | Isolated GitHub child |
| Fixed-admin risk report | `metadata:read`, `issues:write` | Fixed report transport |

Tokens never request Administration, Actions, secrets, or workflow permissions. The host validates expiry, selected-repository scope, canonical owner/name, and immutable repository ID. The App key and token contents stay host-only. Provider HTTP ignores ambient proxies and redirects. Structured Git transport receives credentials only through a transient sterile HTTPS environment; local Git receives no token and no allowed protocol. GitHub CLI receives `GH_TOKEN` only in an isolated temporary environment.

## Git and GitHub policy

`project_git` resolves only the trusted current project. Inspection and fetch accept an exact valid detached HEAD, and local checkout accepts one full lowercase SHA or an exact task branch. The closed grammar adds only `merge --no-edit <full-lowercase-SHA>`, merge-state-guarded `commit --no-edit`, and merge-state-guarded `merge --abort`; it still excludes shell, arbitrary cwd/gitdir, repository selectors, credential override, aliases, hooks, arbitrary merge/commit options, strategies, drivers, editors, message/path inputs, raw transport, and default-branch mutation. The dedicated `commit` action stages explicit literal paths with `git add -A`, including deletion-only changes, under one repository lock and expected branch/HEAD. Push remains one exact normal non-force task-branch update under standard fast-forward semantics and may publish merge commits. Remote deletion remains limited to one freshly revalidated non-default branch.

`project_github(help)` is the filtered policy source. `run` permits reviewed issues, pull requests, comments, checks, statuses, repository views, and exact-current-repository REST methods. It blocks alternate hosts, repository selectors, GraphQL, host-file expansion, merge/update-branch, contents/ref writes, repository administration, secrets, Actions, workflows, issue deletion, and comment deletion through the generic route.

`project_github.comment_delete` is the sole comment-deletion path. It revalidates one typed issue-conversation or review comment in the exact current repository immediately before deletion and reports direct uncertainty without retrying. Trusted-human consent remains Peirce's judgment rather than host confirmation state.

## Slack and bookmarks

The approved bot scopes retain strict mention handling, authorized public/private channel context, threaded replies, files, reactions, and exact bookmark read/write access. DMs, MPIMs, automated pins, links, reminders, and onboarding workflows remain unused or disabled.

Bookmark observations come fresh from the trusted current channel. Add and delete affect only that channel and return direct provider evidence. The registry stores no bookmark ID, ownership, adoption, pending, or reconciliation state. Same-URL bookmarks remain distinct observations. Clearing a project association neither reads nor mutates Slack bookmarks.

## Registry, paths, and fixed projects

Registry schema v2 stores dynamic repository facts and one-channel/one-repository associations. Immutable repository ID is the identity for uniqueness, ID-derived workspace/Git paths, and locks; owner/name, URL, installation, and default branch are freshly corroborated mutable facts. Fixed projects are configuration, not registry rows.

The checked source mapping fixes:

- `peirce-example/peirce`, repository ID `101`, to the example source channel,
  isolated worktree `workspace/projects/peirce`, and external metadata
  `gateway/reserved/peirce.git`;
- `peirce-example/peirce-admin`, repository ID `202`, to the example admin
  channel, isolated worktree `workspace/projects/peirce-admin`, and external
  metadata `gateway/reserved/peirce-admin.git`.

These are unverified illustrative identities and paths, not actual deployment
associations. The public repository `causal-design/peirce-public` is not a
runtime source/admin association.

Deployment supplies and validates actual workspace/channel IDs, secure roots,
UID/GID, modes, and existing schema before activation. The example config uses
`/srv/hermes/project-state`; it is not a preserved production state root.

## Learning and profile isolation

The live profile is not project state and is never a Git target. The fixed source project may obtain a read-only bounded snapshot containing exact `memories/MEMORY.md`, `memories/USER.md`, and first-level learned `skills/*/SKILL.md` definitions with byte counts and hashes. Other profile files, nested assets, plugins, credentials, caches, telemetry, locks, and bundled skills are excluded.

Source publication uses an operator-selected isolated workspace and ordinary
task-branch review. The `peirce-self-development` skill distinguishes accepted
source from live learning. Review all private and live-learning material before
push or PR creation; human merge and later deployment are separate decisions.

## Fixed admin reporting

`risk_report.create` can create one issue only in illustrative
`peirce-example/peirce-admin` by immutable repository ID. The host supplies
trusted Slack event identity, bounds the agent-authored summary to 1,000 UTF-8
bytes, narrows credentials, and permits no alternate destination. Peirce decides
whether behavior is significant and normally does not announce the report or
outcome; generic tool activity may remain visible.

## Human safety boundaries

Humans create and delete repositories, approve App access and permissions, review commits and pull requests, merge protected changes, manage secrets/workflows/administration, and perform deployment. Peirce never requests credentials in Slack and never claims merge or deployment from source state alone.
