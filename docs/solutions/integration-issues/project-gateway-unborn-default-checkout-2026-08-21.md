---
title: "Project Gateway Could Not Checkout a Canonically Unborn Default Branch"
date: 2026-08-21
category: integration-issues
module: project-gateway
problem_type: integration_issue
component: tooling
symptoms:
  - "A freshly initialized and fetched workspace remained on its symbolic default branch with head: null."
  - "checkout_default could not express the observed state because expected_head required a full lowercase SHA."
  - "The implementation required a resolvable HEAD, making safe default-branch materialization unreachable for a canonical unborn workspace."
root_cause: wrong_api
resolution_type: code_fix
severity: high
tags:
  - "project-gateway"
  - "git"
  - "checkout-default"
  - "unborn-branch"
  - "default-branch"
  - "tool-schema"
  - "safe-recovery"
  - "repository-workspace"
---

# Project Gateway Could Not Checkout a Canonically Unborn Default Branch

## Problem

A newly initialized project workspace could fetch an existing remote history but remain stuck with a symbolic, unborn default branch: the branch was `main`, `HEAD` had no commit, and `origin/main` already pointed to the fetched target. The only bounded local operation capable of materializing the branch, `project_git.checkout_default`, rejected that valid state because its contract and implementation required `expected_head` to be a commit SHA.

This was a mismatch between the public tool schema, workspace-state model, and Git implementation. It was not a fetch, association, provider, or deployment failure.

## Symptoms

- Workspace inspection reported `branch=main` and `head=null` after successful initialization and fetch.
- `refs/remotes/origin/main` already resolved to the intended commit, so another fetch changed nothing.
- The old public schema rejected `expected_head: null` before the bounded checkout could run.
- The implementation also required `rev-parse --verify HEAD` to succeed, so changing only the schema would not have repaired the workflow.
- The valid project association remained intact and did not need to be recreated.

## What Didn't Work

### Fetching again

The required commit was already present at `refs/remotes/origin/main`. Fetch and checkout are intentionally separate effects:

```text
project_workspace.fetch      # network effect
project_git.checkout_default # bounded local Git effect
```

Adding fetch behavior to `checkout_default` would have hidden the contract defect and weakened the one-effect capability boundary.

### Making the schema nullable by itself

Schema-only acceptance would still have passed `None` into code that assumed `HEAD` resolved to a commit. It also would have treated an absent HEAD like a generic process failure instead of proving a canonical unborn state.

### Reusing force-reset checkout for branch creation

Using `git checkout -B` after a non-atomic pre-check could overwrite a destination branch created concurrently. Repeating observations does not close the race between the final observation and Git executing the checkout.

### Treating any failed HEAD lookup as unborn

A timeout, signal, truncated response, malformed process result, or unexpected exit code is uncertainty—not proof that a symbolic branch is unborn. The accepted absence result must have the validated Git process shape and agree with canonical repository metadata.

## Solution

An implementation change made `checkout_default` explicitly support a canonical
unborn default branch while preserving the born-branch contract. The commit and
deployment evidence are intentionally omitted from this public showcase.

### Make null explicit and action-specific

`plugins/project-gateway/__init__.py` defines a nullable SHA schema for `checkout_default` only:

```python
SHA = {"type": "string", "pattern": "^[0-9a-f]{40}$"}
NULLABLE_SHA = {"oneOf": [SHA, {"type": "null"}]}
```

The argument remains required. A full SHA selects the existing born-HEAD path; explicit `null` requests the canonical-unborn path. Other operations such as `commit` remain SHA-only. Runtime validation mirrors the schema so the boundary does not depend on schema enforcement alone.

### Prove a canonical unborn default

The nullable path is admitted only when all of these observations agree:

- the supplied branch equals the freshly observed provider default branch;
- `HEAD` is a valid symbolic reference to that branch;
- the symbolic target ref is absent;
- raw and peeled HEAD resolution fail with the exact expected Git absence shape;
- process results are complete, correctly typed, untruncated, and not uncertain;
- the workspace is completely clean and repository metadata remains canonical.

This distinguishes a valid unborn branch from corruption or an indeterminate command result.

### Resolve and preserve the exact target

The requested SHA must resolve as that exact commit, not merely as an object Git could peel to another commit. The corresponding `refs/remotes/origin/<default>` ref is checked before checkout and again afterward.

### Create rather than force-reset

The checkout mode now depends on the expected state:

```python
branch_mode = "-b" if expected_head is None else "-B"
```

The unborn path uses `git checkout -b` with `--no-overwrite-ignore`. If another writer creates the destination branch first, Git fails rather than resetting that writer's commit. Ignored local collisions are preserved instead of being silently overwritten.

### Require proven postconditions

After checkout, the gateway re-observes the branch, HEAD, upstream, cleanliness, remote-tracking target, and canonical metadata. It reports confirmed success only when every postcondition matches. A failed, truncated, uncertain, or mismatched post-observation returns an unknown effect rather than a false success.

## Why This Works

The fix models an unborn branch as a distinct and narrowly authorized Git state instead of pretending it is a born branch with a missing SHA. Explicit `null` selects that state, fresh provider-default equality limits which branch may be created, and canonical metadata separates absence from uncertainty. Non-force `-b` makes concurrent branch creation fail safely, while exact target and post-effect checks prevent object substitution or false success.

The local checkout subprocess receives no credential or transport-enabling environment and cannot fetch or push. The capability may still obtain fresh provider metadata through the host-owned observation path before the local effect.

An operator can validate the example behavior with provider-free tests; this
snapshot contains no live acceptance evidence or deployment claim.

## Prevention

- Keep the nullable schema isolated to `checkout_default`, and require canonical symbolic-HEAD evidence plus fresh provider-default equality before accepting `HEAD=None`.
- Keep fetch and checkout separate; the local checkout child receives no credential or network-enabling environment.
- Resolve supplied targets as exact commits, use branch-creation semantics for the unborn transition, and preserve ignored-collision protection.
- Require exact postconditions before returning `checked_out`; otherwise return an unknown effect.
- Keep the provider-free `initialize → fetch → inspect unborn → checkout` regression alongside adversarial tests for branch races, collisions, stale targets, non-commit objects, malformed results, truncation, and uncertain post-state.

The pre-existing born-branch behavior was unchanged and still uses `checkout -B`. Destination-ref compare-and-swap for that path was outside the scope of this fix.

## Related Issues

- [Project Gateway public contract](../../../plugins/project-gateway/README.md)
- `plugins/project-gateway/tests/test_contract.py` for nullable-schema isolation
- `plugins/project-gateway/tests/test_git.py` for direct and adversarial Git behavior
- `plugins/project-gateway/tests/test_project.py` for the end-to-end initialize/fetch/unborn-checkout regression
