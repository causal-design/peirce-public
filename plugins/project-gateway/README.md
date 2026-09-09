# `project-gateway` plugin

`project-gateway` is the trusted host boundary for seven independently useful project capabilities. It supplies fresh observations and one bounded effect at a time. It does not prescribe linking, recovery, publication, consent, reporting, or completion workflows. The fixed identities and destinations shown by this public contract are illustrative and unverified; deployment must adapt them without weakening the checks.

The terminal and project worktrees receive no GitHub App key, installation token, authenticated GitHub CLI configuration, arbitrary repository selector, or host path authority.

## Trusted context

Every non-help action derives Slack workspace and channel identity from the host session store. Model arguments cannot provide workspace, channel, event, destination, or learning paths. The configured Slack workspace must match the trusted session origin.

Dynamic current projects come from schema-v2 `projects.db`. The fixed source and admin channels resolve directly to immutable configured repository IDs and cannot be changed or cleared. Association mutation, Git/GitHub effects, and fixed-repository reservation use a consistent channel-before-repository lock order.

## Public capabilities

### `repository_access`

- `observe(owner, name)` returns a fresh read-only candidate repository observation.
- It uses metadata-read credentials narrowed to the observed repository.
- It creates no workspace, association, bookmark, or current-project authority.

### `project_association`

- `show` returns the current fixed or dynamic route.
- `set` takes canonical owner/name, immutable repository ID, and expected current ID. It freshly re-observes the candidate before one SQLite transaction.
- `clear` removes only the expected dynamic association.
- Fixed routes and fixed repository IDs reject ordinary association mutation.

The registry stores repository facts and one-channel/one-repository uniqueness. It stores no workflow phase, bookmark ownership, pending state, confirmation, or recovery record.

### `project_workspace`

- `inspect` reports exact workspace/Git metadata identity, attached branch or valid detached HEAD, exact commit, upstream, dirtiness, ahead/behind facts, and uncertainty without mutation.
- `initialize` creates one absent exact worktree/external-bare-Git-metadata pair. The bare gitdir has no `core.worktree`; every ordinary Git operation supplies the separately trusted worktree explicitly. It does not fetch or check out.
- `fetch` performs one authenticated fetch for an existing validated pair, including one at a valid detached HEAD. It does not initialize, clean, or check out.
- `learning_snapshot` is available only for the fixed source project. It reads exact live-profile `memories/MEMORY.md`, `memories/USER.md`, and first-level `skills/*/SKILL.md` definitions with hashes and bytes. It excludes all other profile state and performs no write.

Candidate workspace actions re-observe immutable identity but do not change the active project. Current workspace actions hold the trusted route lock through the effect.

### `channel_bookmarks`

- `list` reads current bookmarks from the trusted current Slack channel.
- `add(title, url)` adds one link bookmark to that channel.
- `delete(bookmark_id)` deletes one supplied current-channel bookmark ID.

Same-URL bookmarks remain distinct. No ownership, adoption, pending, reconciliation, or disconnect lifecycle is maintained. Bookmark failure cannot block repository work or association clear.

### `project_git`

- `help` returns static filtered policy without requiring a route or environment.
- `run` accepts a closed grammar of bounded repository observations and selected local branch/worktree/index effects. Checkout accepts either an exact task branch or one intentional full lowercase SHA, allowing detached local recovery and later reattachment without a host-owned recovery workflow.
- Its only merge lifecycle forms are `merge --no-edit <full-lowercase-SHA>`, merge-state-guarded `commit --no-edit`, and merge-state-guarded `merge --abort`. Conflict state and process evidence remain ordinary local state for independent inspection and resolution.
- `commit` validates explicit literal paths, expected task branch, expected HEAD, shared-index state, and candidate delta containment; it uses a private candidate index and creates one local commit. `git add -A` supports modified, untracked, and deletion-only changes. It mints no credential and does not push.
- `remote_ref` observes one exact remote branch.
- `push` freshly revalidates provider/default-branch and remote-target facts, requires the expected remote base to remain an ancestor, and normally pushes one exact nonempty task-branch range under standard fast-forward semantics. The range may contain merge commits; it never force-pushes.
- `delete_remote_branch` deletes one exact freshly observed non-default branch using an exact lease. Clear trusted-human consent remains Peirce's judgment.
- `checkout_default` checks out an already-fetched exact default commit into a clean local workspace without overwriting ignored collisions. Its expected HEAD is a full lowercase SHA, or explicit `null` only for the freshly observed default branch with a canonically validated unborn symbolic HEAD; unborn checkout creates rather than force-resets the branch. Every branch, HEAD, upstream, cleanliness, and remote-target postcondition must be proven before success is reported. It does not fetch or update the remote default branch.

Local `run` receives no token and no allowed Git transport protocol. Structured fetch, remote observation, push, and deletion retain only reviewed exact-repository HTTPS transport. Unavailable Git authority includes shell, arbitrary cwd/gitdir/config, repository/credential override, aliases, hooks, arbitrary merge/commit forms, strategies, drivers, editors, message/path inputs, raw transport, force-push, tags, multiple refs, mirror, default-branch update/deletion, and repository administration. Human pull-request/default-branch integration remains outside the gateway.

### `project_github`

- `help` returns the static reviewed high-level and REST policy.
- `run` targets only the exact current repository. It supports reviewed issue, pull-request, comment, checks, status, and repository-view work plus bounded exact-repository REST requests.
- `comment_delete` is the sole deletion path for one typed issue-conversation or pull-request review comment. It freshly revalidates repository, parent, and comment identity, deletes once, and observes absence without retrying.

The collaboration token has metadata/read, contents/read, issues/write, pull-requests/write, checks/read, and statuses/write. Generic GitHub calls block alternate hosts, repository selectors, GraphQL, file expansion, merge/update-branch, contents/ref writes, administration, secrets, Actions, workflows, issue deletion, and direct comment DELETE.

### `risk_report`

- `create(category, summary)` creates one issue only in fixed illustrative
  `peirce-example/peirce-admin`.
- The host derives workspace, channel, and event identity, freshly observes the immutable admin repository ID, narrows the token to metadata/read and issues/write, and bounds the summary to 1,000 UTF-8 bytes.
- It accepts no destination, arbitrary repository, URL, raw provider payload, or credential.

Peirce decides whether behavior is significant, how to summarize it, and whether disclosure is appropriate. Ordinary mistakes are not reports. Generic tool activity may be visible; no requester-visibility or confirmation workflow is maintained.

## Credentials and uncertainty

Every token mint is short-lived, exact-repository scoped, permission-checked, and opaque to the model. Git credentials exist only in a sterile structured-transport child environment, never a local `run` child. GitHub CLI uses a temporary isolated home/config/cache and exact `GH_REPO`. Process output and structured results are recursively redacted.

Timeouts, signals, truncation, malformed provider responses, uncertain transmission, descriptor drift, and unverifiable absence remain direct uncertainty. Effects are never silently retried or converted into workflow phases. A later independent observation is the recovery primitive.

## Source verification

```bash
python3 -m unittest discover -s plugins/project-gateway/tests -p 'test_*.py'
python3 -m py_compile plugins/project-gateway/*.py plugins/project-gateway/tests/*.py
git diff --check
```

Provider, Linux descriptor/UID/GID, migration, service, Slack, deployment, and live acceptance belong to the later operational phase.
