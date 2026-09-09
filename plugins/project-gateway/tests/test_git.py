# SPDX-License-Identifier: AGPL-3.0-only
"""Provider-free contract tests for the split Git capability."""

from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
import os
import stat
import subprocess
import tempfile
import unittest
from unittest import mock


from _package import project, project_git, registry


SHA_A = "a" * 40
SHA_B = "b" * 40


def facts(**changes):
    values = dict(
        repository_id="11", alias="repo", installation_id="7", owner="owner", name="repo",
        worktree="/private/tmp/worktrees/11", url="https://github.com/owner/repo.git",
        default_branch="main", trusted_gitdir="/private/tmp/state/git/11",
    )
    values.update(changes)
    return registry.RepositoryFacts(**values)


class GitGrammarTests(unittest.TestCase):
    def test_closed_grammar_accepts_bounded_reads_and_local_composition(self):
        accepted = (
            ["status", "--short"], ["diff", "--cached", "--", "src/a.py"],
            ["log", "--oneline", "HEAD"], ["show", SHA_A],
            ["rev-parse", "--verify", "HEAD"], ["rev-list", "--count", "HEAD"],
            ["ls-files", "--cached"], ["branch", "--show-current"],
            ["branch", "topic"], ["branch", "-D", "hermes/task"],
            ["switch", "topic"], ["switch", "--create", "hermes/new-task"],
            ["branch", SHA_A], ["switch", SHA_A],
            ["checkout", "hermes/task"], ["checkout", "-b", "hermes/new-task"],
            ["checkout", SHA_A], ["merge", "--no-edit", SHA_A],
            ["add", "--", "src/a.py"],
            ["restore", "--source=HEAD", "--staged", "--worktree", "--", "src/a.py"],
            ["clean", "-fd", "--", "src/generated"],
        )
        for argv in accepted:
            with self.subTest(argv=argv):
                self.assertEqual(project_git.validate_run_argv(list(argv), facts()), list(argv))

    def test_closed_grammar_rejects_transport_routing_and_destructive_forms(self):
        rejected = (
            ["commit", "-m", "x"], ["fetch"], ["pull"], ["merge", "main"],
            ["merge", SHA_A], ["merge", "--no-edit", "HEAD"],
            ["merge", "--no-edit", SHA_A, SHA_B], ["merge", "-s", "ours", SHA_A],
            ["merge", "--strategy=ours", SHA_A], ["merge", "--abort", "x"],
            ["commit"], ["commit", "--no-edit", "x"], ["commit", "--file=msg"],
            ["rebase", "main"], ["push", "--force", "origin", "main"],
            ["push", "--mirror"], ["push", "origin", "a:b", "c:d"],
            ["push", "https://elsewhere.invalid/x", "main"], ["tag", "v1"],
            ["config", "alias.x", "push"], ["help"], ["--paginate", "status"],
            ["status", "--git-dir=/tmp/x"], ["status", "--help"],
            ["switch", "--detach", SHA_A], ["checkout", "--orphan", "x"],
            ["branch", "--delete", "hermes/task"], ["branch", "main"],
            ["reset", "--hard", "refs/remotes/origin/main"], ["clean", "-fd"],
            ["restore", "--", "src/a.py"], ["restore", "--staged", "--", "src/a.py"],
        )
        for argv in rejected:
            with self.subTest(argv=argv), self.assertRaises(project_git.GitError):
                project_git.validate_run_argv(list(argv), facts())

    def test_paths_are_literal_and_cannot_select_magic_or_metadata(self):
        rejected = ("/tmp/x", ".", "..", ".git/config", "src/../x", "src/*.py",
                    ":(top)README.md", "-n", "src\\x")
        for value in rejected:
            with self.subTest(value=value), self.assertRaises(project_git.GitError):
                project_git.validate_run_argv(["add", "--", value], facts())

    def test_branch_policy_rejects_default_and_force_forms(self):
        self.assertTrue(project_git._work_branch(SHA_A, facts()))
        rejected = (
            ["switch", "main"],
            ["checkout", "main"], ["switch", "--create", "main"],
            ["checkout", "-B", "hermes/task"], ["checkout", "hermes/task", "--force"],
        )
        for argv in rejected:
            with self.subTest(argv=argv), self.assertRaises(project_git.GitError):
                project_git.validate_run_argv(list(argv), facts())

    def test_literal_paths_ignore_retired_persisted_policy_and_require_deduplication(self):
        self.assertEqual(project_git._paths(["src/a.py", "docs/a.md"]),
                         ["src/a.py", "docs/a.md"])
        with self.assertRaises(project_git.GitError):
            project_git._paths(["src/a.py", "src/a.py"])

    def test_public_mutations_ignore_retired_policy_for_safe_literal_selectors(self):
        restricted = facts()
        for argv in (["add", "--", "src"],
                     ["restore", "--source=HEAD", "--staged", "--worktree", "--", "src"],
                     ["clean", "-fd", "--", "src"]):
            with self.subTest(argv=argv):
                self.assertEqual(project_git.validate_run_argv(argv, restricted), argv)
        self.assertEqual(project_git._paths(["src"]), ["src"])


class GitOutcomeTests(unittest.TestCase):
    @staticmethod
    def result(stdout="", *, exit_code=0, state="exited", uncertain=False):
        return {"state": state, "exit_code": exit_code, "stdout": stdout,
                "stderr": "", "uncertain": uncertain}

    def test_remote_exact_present_and_absent_are_definitive(self):
        present = project_git.ProjectGit._parse_remote(
            self.result(f"{SHA_A}\trefs/heads/hermes/task\n"), ["hermes/task"])
        absent = project_git.ProjectGit._parse_remote(self.result(), ["hermes/task"])
        self.assertEqual(present, {"hermes/task": SHA_A})
        self.assertEqual(absent, {"hermes/task": None})

    def test_remote_malformed_duplicate_nonzero_and_timeout_are_unknown(self):
        cases = (
            self.result("malformed\n"),
            self.result(f"{SHA_A}\trefs/heads/other\n"),
            self.result(f"{SHA_A}\trefs/heads/x\n{SHA_A}\trefs/heads/x\n"),
            self.result(exit_code=1),
            self.result(state="timed_out", uncertain=True),
        )
        for result in cases:
            with self.subTest(result=result):
                self.assertIsNone(project_git.ProjectGit._parse_remote(result, ["x"]))

    def test_multi_ref_preflight_maps_only_exact_requested_refs(self):
        output = f"{SHA_A}\trefs/heads/hermes/task\n"
        self.assertEqual(project_git.ProjectGit._parse_remote(
            self.result(output), ["hermes/task", "trunk"]),
            {"hermes/task": SHA_A, "trunk": None})

    def test_direct_results_are_frozen_and_identify_actual_repository(self):
        observation = project_git.GitObservation("present", "11", "main", SHA_A)
        effect = project_git.GitEffect("published", "11", "hermes/task", SHA_A, "b" * 40)
        self.assertEqual(observation.repository_id, "11")
        self.assertEqual(effect.repository_id, "11")
        with self.assertRaises(FrozenInstanceError):
            observation.state = "absent"  # type: ignore[misc]

    def test_process_uncertainty_never_treats_failure_as_success(self):
        self.assertFalse(project_git.ProjectGit._uncertain(self.result()))
        self.assertFalse(project_git.ProjectGit._uncertain(self.result(exit_code=1)))
        self.assertTrue(project_git.ProjectGit._uncertain(
            self.result(state="timed_out", uncertain=True)))


class ProjectGitPublicTests(unittest.TestCase):
    """Exercise the public object against the supported external-gitdir layout."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir="/private/tmp")
        self.root = Path(self.tmp.name)
        self.root.chmod(0o700)
        (self.root / "workspace-root").mkdir(mode=0o700)
        (self.root / "state").mkdir(mode=0o700)
        (self.root / "state" / "git").mkdir(mode=0o700)
        self.worktree = self.root / "workspace-root" / "11"
        self.gitdir = self.root / "state" / "git" / "11"
        self.worktree.mkdir(mode=0o700)
        subprocess.run(["/usr/bin/git", "init", "--bare", "--initial-branch", "main",
                        str(self.gitdir)], check=True, capture_output=True)
        (self.gitdir / "config").write_text(
            "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = true\n"
            "\tlogallrefupdates = true\n\thooksPath = /dev/null\n"
            "[remote \"origin\"]\n\turl = https://github.com/owner/repo.git\n"
            "\tfetch = +refs/heads/*:refs/remotes/origin/*\n"
            "[init]\n\tdefaultBranch = main\n[user]\n\tname = Peirce\n"
            "\temail = peirce@example.invalid\n"
            "[branch \"main\"]\n\tremote = origin\n\tmerge = refs/heads/main\n",
            encoding="utf-8")
        self.worktree.chmod(0o700)
        self.gitdir.chmod(0o700)
        self.git_argv = ["/usr/bin/git", f"--git-dir={self.gitdir}",
                         f"--work-tree={self.worktree}"]
        (self.worktree / "src").mkdir()
        (self.worktree / "src" / "modified.txt").write_text("one\n")
        (self.worktree / "src" / "deleted.txt").write_text("delete\n")
        env = dict(os.environ, GIT_AUTHOR_NAME="Test", GIT_AUTHOR_EMAIL="test@example.invalid",
                   GIT_COMMITTER_NAME="Test", GIT_COMMITTER_EMAIL="test@example.invalid")
        subprocess.run([*self.git_argv, "add", "--", "src"],
                       check=True, env=env, capture_output=True)
        subprocess.run([*self.git_argv, "commit", "-m", "base"],
                       check=True, env=env, capture_output=True)
        subprocess.run([*self.git_argv, "checkout", "-b", "hermes/task"],
                       check=True, capture_output=True)
        self.head = subprocess.run(
            [*self.git_argv, "rev-parse", "HEAD"], check=True,
            text=True, capture_output=True).stdout.strip()
        self.origin = project.TrustedOrigin("W1", "C1")
        self.facts = facts(worktree=str(self.worktree), trusted_gitdir=str(self.gitdir))
        state = self.root / "state"
        db = registry.ProjectRegistry(self.root / "projects.db",
                                      workspace_root=self.root / "workspace-root", state_root=state)
        observed = project.ProviderObservation("11", "7", "owner", "repo",
                                               "https://github.com/owner/repo.git", "main")
        self.gateway = project.ProjectGateway(
            db, lambda _candidate: observed, (), state_root=state)
        # Install a dynamic-layout route directly without exercising registry mutation.
        self.gateway._fixed[(self.origin.workspace_id, self.origin.channel_id)] = \
            project.FixedProject(self.origin, self.facts)
        self.git = project_git.ProjectGit(self.gateway)
        self.real_runner = self.gateway.process_runner

    @staticmethod
    def result(stdout="", *, stderr="", exit_code=0, state="exited", uncertain=False):
        return {"state": state, "exit_code": exit_code, "stdout": stdout,
                "stderr": stderr, "uncertain": uncertain,
                "stdout_truncated": False, "stderr_truncated": False}

    def token_response(self, profile):
        permissions = project_git.host_boundary.narrow_token_request("11", profile)["permissions"]
        return {"token": "test-token", "expires_at": (
                    datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat(),
                "permissions": permissions, "repository_selection": "selected",
                "repositories": [{"id": 11, "name": "repo", "full_name": "owner/repo"}]}

    def install_script(self, handler, profile="git_push_delete"):
        calls = []
        real = self.real_runner

        def runner(argv, **kwargs):
            command = list(argv[5:])
            calls.append((command, kwargs))
            if (command == ["config", "--local", "--null", "--list"]
                    or command == ["symbolic-ref", "--quiet", "HEAD"]):
                return real(argv, **kwargs)
            scripted = handler(command, kwargs)
            return real(argv, **kwargs) if scripted is None else scripted

        self.gateway.process_runner = runner
        self.gateway.token_reader = lambda _request: self.token_response(profile)
        return calls

    def make_child(self):
        modified = self.worktree / "src" / "modified.txt"
        modified.write_text(modified.read_text() + "child\n")
        env = dict(os.environ, GIT_AUTHOR_NAME="Test", GIT_AUTHOR_EMAIL="test@example.invalid",
                   GIT_COMMITTER_NAME="Test", GIT_COMMITTER_EMAIL="test@example.invalid")
        subprocess.run([*self.git_argv, "add", "--", "src/modified.txt"], check=True,
                       capture_output=True, env=env)
        subprocess.run([*self.git_argv, "commit", "-m", "child"], check=True,
                       capture_output=True, env=env)
        return subprocess.run([*self.git_argv, "rev-parse", "HEAD"], check=True,
                               text=True, capture_output=True).stdout.strip()

    def git_command(self, *args, input=None):
        env = dict(os.environ, GIT_AUTHOR_NAME="Test", GIT_AUTHOR_EMAIL="test@example.invalid",
                   GIT_COMMITTER_NAME="Test", GIT_COMMITTER_EMAIL="test@example.invalid")
        return subprocess.run([*self.git_argv, *args], input=input, check=True, text=True,
                              capture_output=True, env=env).stdout.strip()

    def side_commit(self, relative="side.txt", content="side\n"):
        self.git_command("checkout", "-b", "side", self.head)
        target = self.worktree / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)
        self.git_command("add", "--", relative)
        self.git_command("commit", "-m", "side")
        side = self.git_command("rev-parse", "HEAD")
        self.git_command("checkout", "hermes/task")
        return side

    def make_unborn_default(self, target=None):
        target = target or self.head
        self.git_command("update-ref", "refs/remotes/origin/main", target)
        self.git_command("symbolic-ref", "HEAD", "refs/heads/main")
        self.git_command("update-ref", "-d", "refs/heads/main")
        self.git_command("update-ref", "-d", "refs/heads/hermes/task")
        for path in sorted(self.worktree.rglob("*"), reverse=True):
            path.unlink() if path.is_file() or path.is_symlink() else path.rmdir()
        index = self.gitdir / "index"
        if index.exists():
            index.unlink()
        inspected = self.gateway.inspect_workspace(self.facts)
        self.assertEqual((inspected.state, inspected.branch, inspected.head),
                         ("invalid", "main", None))
        self.assertEqual(list(self.worktree.iterdir()), [])
        self.assertEqual(self.git_command("status", "--porcelain=v1"), "")
        return target

    def tearDown(self):
        self.tmp.cleanup()

    def test_commit_uses_private_candidate_for_modified_deleted_and_untracked(self):
        branch_read = self.git.run(self.origin, "11", ["branch", "--show-current"])
        self.assertEqual(branch_read.state, "observed", repr(branch_read.process))
        (self.worktree / "src" / "modified.txt").write_text("two\n")
        (self.worktree / "src" / "deleted.txt").unlink()
        (self.worktree / "src" / "untracked.txt").write_text("new\n")
        effect = self.git.commit(self.origin, "11", ["src"], "direct commit",
                                 self.head, "hermes/task")
        self.assertEqual(effect.effect, "committed")
        self.assertEqual(effect.parent, self.head)
        self.assertRegex(effect.commit or "", r"^[0-9a-f]{40}$")
        changed = subprocess.run(
            [*self.git_argv, "diff", "--name-only",
             "--no-renames", f"{self.head}..{effect.commit}"], check=True, text=True,
            capture_output=True).stdout.splitlines()
        self.assertEqual(changed, ["src/deleted.txt", "src/modified.txt", "src/untracked.txt"])
        self.assertFalse((self.gitdir / "index.lock").exists())

    def test_commit_marks_index_publication_failure_uncertain_after_ref_moves(self):
        (self.worktree / "src" / "modified.txt").write_text("candidate\n")
        with mock.patch.object(project_git.os, "rename", side_effect=OSError("rename failed")):
            effect = self.git.commit(self.origin, "11", ["src/modified.txt"],
                                     "candidate", self.head, "hermes/task")
        self.assertEqual((effect.effect, effect.uncertain, effect.local_state),
                         ("committed", True, "index_publication_unknown"))
        self.assertNotEqual(effect.commit, self.head)
        self.assertEqual(subprocess.run(
            [*self.git_argv, "rev-parse", "HEAD"], check=True, text=True,
            capture_output=True).stdout.strip(), effect.commit)

    def test_sha_shaped_branch_supports_switch_dedicated_commit_and_push(self):
        self.git_command("checkout", "-b", SHA_A)
        target = self.worktree / "src" / "modified.txt"
        target.write_text("sha branch\n")
        effect = self.git.commit(
            self.origin, "11", ["src/modified.txt"], "sha branch", self.head, SHA_A)
        self.assertEqual((effect.effect, effect.branch), ("committed", SHA_A))
        remote = f"{self.head}\trefs/heads/{SHA_A}\n{self.head}\trefs/heads/main\n"
        def handler(command, _kwargs):
            if command[0] == "ls-remote": return self.result(remote)
            if command[0] == "push": return self.result()
            return None
        calls = self.install_script(handler)
        pushed = self.git.push(self.origin, "11", SHA_A, effect.commit, self.head)
        self.assertEqual(pushed.effect, "published")
        self.assertEqual(next(command for command, _ in calls if command[0] == "push")[-1],
                         f"{effect.commit}^{{commit}}:refs/heads/{SHA_A}")

    def test_run_returns_distinct_public_result_types_and_no_token(self):
        read = self.git.run(self.origin, "11", ["status", "--short"])
        self.assertIsInstance(read, project_git.GitObservation)
        (self.worktree / "src" / "untracked.txt").write_text("new\n")
        mutation = self.git.run(self.origin, "11", ["clean", "-fd", "--", "src/untracked.txt"])
        self.assertIsInstance(mutation, project_git.GitEffect)
        self.assertEqual(mutation.effect, "applied")
        self.assertFalse((self.worktree / "src" / "untracked.txt").exists())

    def test_sha_checkout_is_explicit_detached_commit_despite_colliding_branch(self):
        child = self.make_child()
        requested = self.head
        self.git_command("update-ref", f"refs/heads/{requested}", child)
        commands = []
        real = self.real_runner

        def runner(argv, **kwargs):
            commands.append(list(argv[5:]))
            return real(argv, **kwargs)

        self.gateway.process_runner = runner
        value = self.git.run(self.origin, "11", ["checkout", requested])
        self.assertEqual(value.effect, "applied", repr(value))
        self.assertIn(["checkout", "--detach", f"{requested}^{{commit}}"], commands)
        self.assertEqual(self.git_command("rev-parse", "HEAD^{commit}"), requested)
        self.assertEqual(self.git_command("branch", "--show-current"), "")
        self.assertEqual(self.git_command("rev-parse", f"refs/heads/{requested}"), child)

    def test_switch_sha_shaped_branch_attaches_existing_branch(self):
        child = self.make_child()
        branch_name = self.head
        self.git_command("update-ref", f"refs/heads/{branch_name}", child)
        self.git_command("checkout", "main")
        value = self.git.run(self.origin, "11", ["switch", branch_name])
        self.assertEqual(value.effect, "applied", repr(value))
        self.assertEqual(self.git_command("branch", "--show-current"), branch_name)
        self.assertEqual(self.git_command("rev-parse", "HEAD^{commit}"), child)

    def test_annotated_tag_object_rejects_checkout_and_merge_before_mutation(self):
        self.git_command("tag", "-a", "annotated", "-m", "annotated")
        tag_object = self.git_command("rev-parse", "refs/tags/annotated")
        self.assertNotEqual(tag_object, self.git_command("rev-parse", "annotated^{commit}"))
        before = (self.git_command("rev-parse", "HEAD"),
                  (self.gitdir / "index").read_bytes(),
                  (self.worktree / "src" / "modified.txt").read_bytes())
        commands = []
        real = self.real_runner

        def runner(argv, **kwargs):
            commands.append(list(argv[5:]))
            return real(argv, **kwargs)

        self.gateway.process_runner = runner
        for operation in (["checkout", tag_object], ["merge", "--no-edit", tag_object]):
            with self.subTest(operation=operation), self.assertRaises(project_git.GitError):
                self.git.run(self.origin, "11", operation)
            self.assertEqual((self.git_command("rev-parse", "HEAD"),
                              (self.gitdir / "index").read_bytes(),
                              (self.worktree / "src" / "modified.txt").read_bytes()), before)
        self.assertFalse(any(command[:2] == ["checkout", "--detach"]
                             or command[:2] == ["merge", "--no-edit"]
                             for command in commands))

    def test_detached_checkout_postcondition_uncertainty_is_not_success(self):
        commands = []
        real = self.real_runner

        def runner(argv, **kwargs):
            command = list(argv[5:])
            commands.append(command)
            if command == ["symbolic-ref", "--quiet", "--short", "HEAD"]:
                return self.result(state="timed_out", exit_code=None, uncertain=True)
            return real(argv, **kwargs)

        self.gateway.process_runner = runner
        value = self.git.run(self.origin, "11", ["checkout", self.head])
        self.assertEqual((value.effect, value.uncertain, value.local_state),
                         ("unknown", True, "detached_post_state_unverified"))
        self.assertIn(["checkout", "--detach", f"{self.head}^{{commit}}"], commands)

    def test_exact_commit_preresolution_timeout_blocks_checkout_and_merge(self):
        side = self.side_commit()
        before = (self.git_command("rev-parse", "HEAD"),
                  (self.gitdir / "index").read_bytes(),
                  (self.worktree / "src" / "modified.txt").read_bytes())
        commands = []
        real = self.real_runner
        def runner(argv, **kwargs):
            command = list(argv[5:])
            commands.append(command)
            if command == ["rev-parse", "--verify", f"{side}^{{commit}}"]:
                return self.result(state="timed_out", exit_code=None, uncertain=True)
            return real(argv, **kwargs)
        self.gateway.process_runner = runner
        for operation in (["checkout", side], ["merge", "--no-edit", side]):
            with self.subTest(operation=operation), self.assertRaises(project_git.GitError):
                self.git.run(self.origin, "11", operation)
            self.assertEqual((self.git_command("rev-parse", "HEAD"),
                              (self.gitdir / "index").read_bytes(),
                              (self.worktree / "src" / "modified.txt").read_bytes()), before)
        self.assertFalse(any(command[:2] == ["checkout", "--detach"]
                             or command[:2] == ["merge", "--no-edit"]
                             for command in commands))

    def test_merge_success_uses_sterile_local_process_and_preserves_external_sentinels(self):
        side = self.side_commit()
        task = self.worktree / "task.txt"
        task.write_text("task\n")
        self.git_command("add", "--", "task.txt")
        self.git_command("commit", "-m", "task")
        other = self.root / "other-project-sentinel"
        profile = self.root / "live-profile-sentinel"
        other.write_text("other\n")
        profile.write_text("profile\n")
        hook = self.gitdir / "hooks" / "post-merge"
        hook.write_text(f"#!/bin/sh\nprintf hook > {self.root / 'hook-ran'}\n")
        hook.chmod(0o700)
        calls = []
        real = self.real_runner

        def runner(argv, **kwargs):
            calls.append((list(argv[5:]), dict(kwargs["env"])))
            return real(argv, **kwargs)

        self.gateway.process_runner = runner
        self.gateway.token_reader = lambda _request: self.fail("local merge requested token")
        value = self.git.run(self.origin, "11", ["merge", "--no-edit", side])
        self.assertEqual(value.effect, "applied", repr(value.process))
        self.assertEqual((other.read_text(), profile.read_text()), ("other\n", "profile\n"))
        self.assertFalse((self.root / "hook-ran").exists())
        merge_env = next(env for command, env in calls if command[0] == "merge")
        self.assertEqual(merge_env["GIT_ALLOW_PROTOCOL"], "")
        self.assertNotIn("Authorization", repr(merge_env))
        self.assertEqual(merge_env["GIT_EDITOR"], "/usr/bin/false")
        parents = self.git_command("rev-list", "--parents", "-n", "1", "HEAD").split()
        self.assertEqual(len(parents), 3)
        self.assertEqual((self.worktree / "side.txt").read_text(), "side\n")
        self.assertEqual(task.read_text(), "task\n")
        self.assertEqual(self.git_command("status", "--porcelain=v1"), "")

    def test_merge_commit_resolution_ignores_colliding_sha_shaped_branch(self):
        side = self.side_commit()
        task = self.worktree / "task-collision.txt"
        task.write_text("task\n")
        self.git_command("add", "--", "task-collision.txt")
        self.git_command("commit", "-m", "task collision")
        task_head = self.git_command("rev-parse", "HEAD")
        self.git_command("update-ref", f"refs/heads/{side}", self.head)
        commands = []
        real = self.real_runner
        def runner(argv, **kwargs):
            commands.append(list(argv[5:]))
            return real(argv, **kwargs)
        self.gateway.process_runner = runner
        value = self.git.run(self.origin, "11", ["merge", "--no-edit", side])
        self.assertEqual(value.effect, "applied", repr(value))
        self.assertIn(["merge", "--no-edit", f"{side}^{{commit}}"], commands)
        parents = self.git_command("rev-list", "--parents", "-n", "1", "HEAD").split()
        self.assertEqual(parents[1:], [task_head, side])
        self.assertEqual((self.worktree / "side.txt").read_text(), "side\n")
        self.assertEqual(self.git_command("rev-parse", f"refs/heads/{side}"), self.head)

    def test_merge_conflict_can_complete_or_abort_only_with_anchored_merge_state(self):
        side = self.side_commit("src/modified.txt", "side\n")
        (self.worktree / "src" / "modified.txt").write_text("task\n")
        self.git_command("add", "--", "src/modified.txt")
        self.git_command("commit", "-m", "task")
        premerge = self.git_command("rev-parse", "HEAD")
        conflicted = self.git.run(self.origin, "11", ["merge", "--no-edit", side])
        self.assertEqual(conflicted.effect, "failed")
        self.assertEqual(conflicted.local_state, "merge_in_progress")
        self.assertTrue((self.gitdir / "MERGE_HEAD").is_file())
        (self.worktree / "src" / "modified.txt").write_text("resolved\n")
        self.assertEqual(self.git.run(
            self.origin, "11", ["add", "--", "src/modified.txt"]).effect, "applied")
        completed = self.git.run(self.origin, "11", ["commit", "--no-edit"])
        self.assertEqual(completed.effect, "applied", repr(completed.process))
        self.assertFalse((self.gitdir / "MERGE_HEAD").exists())
        self.assertEqual(len(self.git_command(
            "rev-list", "--parents", "-n", "1", "HEAD").split()), 3)

        self.git_command("reset", "--hard", premerge)
        conflicted = self.git.run(self.origin, "11", ["merge", "--no-edit", side])
        self.assertEqual(conflicted.effect, "failed")
        aborted = self.git.run(self.origin, "11", ["merge", "--abort"])
        self.assertEqual(aborted.effect, "applied", repr(aborted.process))
        self.assertEqual(self.git_command("rev-parse", "HEAD"), premerge)
        self.assertFalse((self.gitdir / "MERGE_HEAD").exists())

        for command in (["commit", "--no-edit"], ["merge", "--abort"]):
            with self.subTest(command=command), self.assertRaises(project_git.GitError):
                self.git.run(self.origin, "11", command)

    def test_failed_completion_and_abort_preserve_merge_state_evidence(self):
        side = self.side_commit("src/modified.txt", "side\n")
        (self.worktree / "src" / "modified.txt").write_text("task\n")
        self.git_command("add", "--", "src/modified.txt")
        self.git_command("commit", "-m", "task")
        self.assertEqual(self.git.run(
            self.origin, "11", ["merge", "--no-edit", side]).local_state,
            "merge_in_progress")
        real = self.real_runner
        for command in (["commit", "--no-edit"], ["merge", "--abort"]):
            with self.subTest(command=command):
                def runner(argv, **kwargs):
                    if list(argv[5:]) == command:
                        return self.result(stderr="failed", exit_code=1)
                    return real(argv, **kwargs)
                self.gateway.process_runner = runner
                value = self.git.run(self.origin, "11", command)
                self.assertEqual((value.effect, value.uncertain, value.local_state),
                                 ("failed", False, "merge_in_progress"))
                self.assertTrue((self.gitdir / "MERGE_HEAD").exists())

    def test_failed_completion_and_abort_with_absent_merge_head_are_unknown(self):
        side = self.side_commit("src/modified.txt", "side\n")
        (self.worktree / "src" / "modified.txt").write_text("task\n")
        self.git_command("add", "--", "src/modified.txt")
        self.git_command("commit", "-m", "task")
        self.assertEqual(self.git.run(
            self.origin, "11", ["merge", "--no-edit", side]).local_state,
            "merge_in_progress")
        real = self.real_runner
        for command in (["commit", "--no-edit"], ["merge", "--abort"]):
            with self.subTest(command=command):
                if not (self.gitdir / "MERGE_HEAD").exists():
                    (self.gitdir / "MERGE_HEAD").write_text(side + "\n")
                def runner(argv, **kwargs):
                    if list(argv[5:]) == command:
                        (self.gitdir / "MERGE_HEAD").unlink()
                        return self.result(stderr="partial failure", exit_code=1)
                    return real(argv, **kwargs)
                self.gateway.process_runner = runner
                value = self.git.run(self.origin, "11", command)
                self.assertEqual((value.effect, value.uncertain, value.local_state),
                                 ("unknown", True, "merge_state_absent_after_failure"))

    def test_failed_merge_with_unverifiable_merge_head_is_unknown(self):
        side = self.side_commit("src/modified.txt", "side\n")
        (self.worktree / "src" / "modified.txt").write_text("task\n")
        self.git_command("add", "--", "src/modified.txt")
        self.git_command("commit", "-m", "task")
        real = self.real_runner
        def runner(argv, **kwargs):
            value = real(argv, **kwargs)
            if list(argv[5:])[:2] == ["merge", "--no-edit"]:
                (self.gitdir / "MERGE_HEAD").write_text("bad\n")
            return value
        self.gateway.process_runner = runner
        value = self.git.run(self.origin, "11", ["merge", "--no-edit", side])
        self.assertEqual((value.effect, value.uncertain, value.local_state),
                         ("unknown", True, "merge_state_unverified"))

    def test_merge_autostash_blocks_every_lifecycle_form_without_invocation(self):
        side = self.side_commit()
        commands = []
        real = self.real_runner
        def runner(argv, **kwargs):
            commands.append(list(argv[5:]))
            return real(argv, **kwargs)
        self.gateway.process_runner = runner
        autostash = self.gitdir / "MERGE_AUTOSTASH"
        autostash.write_text(self.head + "\n")
        before = (self.git_command("rev-parse", "HEAD"),
                  (self.gitdir / "index").read_bytes(),
                  (self.worktree / "src" / "modified.txt").read_bytes())
        for command in (["merge", "--no-edit", side],
                        ["commit", "--no-edit"], ["merge", "--abort"]):
            with self.subTest(command=command), self.assertRaises(project_git.GitError):
                self.git.run(self.origin, "11", command)
        self.assertEqual((self.git_command("rev-parse", "HEAD"),
                          (self.gitdir / "index").read_bytes(),
                          (self.worktree / "src" / "modified.txt").read_bytes()), before)
        self.assertTrue(autostash.exists())
        self.assertFalse(any(command[0] in {"merge", "commit"} for command in commands))

    def test_trained_rerere_cache_cannot_rewrite_merge_conflict(self):
        side = self.side_commit("src/modified.txt", "side\n")
        target = self.worktree / "src" / "modified.txt"
        target.write_text("task\n")
        self.git_command("add", "--", "src/modified.txt")
        self.git_command("commit", "-m", "task")
        task_head = self.git_command("rev-parse", "HEAD")
        raw = subprocess.run([*self.git_argv, "-c", "rerere.enabled=true",
                              "merge", "--no-edit", side], capture_output=True)
        self.assertNotEqual(raw.returncode, 0)
        target.write_text("trained resolution\n")
        self.git_command("add", "--", "src/modified.txt")
        self.git_command("-c", "rerere.enabled=true", "commit", "-m", "train rerere")
        self.assertTrue(any((self.gitdir / "rr-cache").rglob("postimage")))
        self.git_command("reset", "--hard", task_head)
        environments = []
        real = self.real_runner
        def runner(argv, **kwargs):
            environments.append(dict(kwargs["env"]))
            return real(argv, **kwargs)
        self.gateway.process_runner = runner
        value = self.git.run(self.origin, "11", ["merge", "--no-edit", side])
        self.assertEqual(value.local_state, "merge_in_progress")
        self.assertIn("<<<<<<<", target.read_text())
        self.assertTrue(self.git_command("ls-files", "-u"))
        merge_env = next(env for env in environments
                         if env.get("GIT_CONFIG_VALUE_7") == "false")
        self.assertEqual(merge_env["GIT_CONFIG_KEY_7"], "rerere.enabled")

    def test_merge_rejects_poisoned_driver_config_before_process(self):
        side = self.side_commit("src/modified.txt", "side\n")
        marker = self.root / "driver-ran"
        with (self.gitdir / "config").open("a", encoding="utf-8") as handle:
            handle.write(f"\n[merge \"evil\"]\n\tdriver = /usr/bin/touch {marker}\n")
        (self.worktree / ".gitattributes").write_text("* merge=evil\n")
        calls = []
        real = self.real_runner
        def runner(argv, **kwargs):
            calls.append(list(argv[5:]))
            return real(argv, **kwargs)
        self.gateway.process_runner = runner
        with self.assertRaises(project_git.GitError):
            self.git.run(self.origin, "11", ["merge", "--no-edit", side])
        self.assertFalse(marker.exists())
        self.assertFalse(any(command and command[0] == "merge" for command in calls))

    def test_dedicated_commit_rejects_active_merge_without_index_or_ref_change(self):
        side = self.side_commit("src/modified.txt", "side\n")
        (self.worktree / "src" / "modified.txt").write_text("task\n")
        self.git_command("add", "--", "src/modified.txt")
        self.git_command("commit", "-m", "task")
        head = self.git_command("rev-parse", "HEAD")
        conflict = self.git.run(self.origin, "11", ["merge", "--no-edit", side])
        self.assertEqual(conflict.local_state, "merge_in_progress")
        index = (self.gitdir / "index").read_bytes()
        with self.assertRaises(project_git.GitError):
            self.git.commit(self.origin, "11", ["src/modified.txt"],
                            "must not complete merge", head, "hermes/task")
        self.assertEqual(self.git_command("rev-parse", "HEAD"), head)
        self.assertEqual((self.gitdir / "index").read_bytes(), index)

    def test_default_branch_rejects_merge_start_and_completion_without_mutation(self):
        side = self.side_commit("src/modified.txt", "side\n")
        self.git_command("checkout", "main")
        (self.worktree / "src" / "modified.txt").write_text("main\n")
        self.git_command("add", "--", "src/modified.txt")
        self.git_command("commit", "-m", "main")
        before = (self.git_command("rev-parse", "HEAD"),
                  (self.gitdir / "index").read_bytes(),
                  (self.worktree / "src" / "modified.txt").read_bytes())
        before_tree = self.git_command("write-tree")
        with self.assertRaises(project_git.GitError):
            self.git.run(self.origin, "11", ["merge", "--no-edit", side])
        self.assertEqual((self.git_command("rev-parse", "HEAD"),
                          (self.gitdir / "index").read_bytes(),
                          (self.worktree / "src" / "modified.txt").read_bytes()), before)
        raw = subprocess.run([*self.git_argv, "merge", "--no-edit", side], capture_output=True)
        self.assertNotEqual(raw.returncode, 0)
        conflicted = (self.git_command("rev-parse", "HEAD"),
                      (self.gitdir / "index").read_bytes(),
                      (self.worktree / "src" / "modified.txt").read_bytes())
        with self.assertRaises(project_git.GitError):
            self.git.run(self.origin, "11", ["commit", "--no-edit"])
        self.assertEqual((self.git_command("rev-parse", "HEAD"),
                          (self.gitdir / "index").read_bytes(),
                          (self.worktree / "src" / "modified.txt").read_bytes()), conflicted)
        aborted = self.git.run(self.origin, "11", ["merge", "--abort"])
        self.assertEqual(aborted.effect, "applied", repr(aborted))
        self.assertEqual((self.git_command("rev-parse", "HEAD"),
                          self.git_command("write-tree"),
                          (self.worktree / "src" / "modified.txt").read_bytes()),
                         (before[0], before_tree, before[2]))

    def test_uncertain_default_branch_precheck_never_invokes_merge(self):
        side = self.side_commit()
        commands = []
        real = self.real_runner
        def runner(argv, **kwargs):
            command = list(argv[5:])
            commands.append(command)
            if command == ["symbolic-ref", "--quiet", "--short", "HEAD"]:
                return self.result(state="timed_out", exit_code=None, uncertain=True)
            return real(argv, **kwargs)
        self.gateway.process_runner = runner
        with self.assertRaises(project_git.GitError):
            self.git.run(self.origin, "11", ["merge", "--no-edit", side])
        self.assertFalse(any(command[:2] == ["merge", "--no-edit"] for command in commands))

    def test_detached_head_can_start_local_merge(self):
        side = self.side_commit()
        task = self.worktree / "task-detached.txt"
        task.write_text("task\n")
        self.git_command("add", "--", "task-detached.txt")
        self.git_command("commit", "-m", "detached task")
        detached = self.git_command("rev-parse", "HEAD")
        self.git_command("checkout", "--detach", detached)
        value = self.git.run(self.origin, "11", ["merge", "--no-edit", side])
        self.assertEqual(value.effect, "applied", repr(value))
        self.assertEqual(self.git_command("branch", "--show-current"), "")
        self.assertEqual(len(self.git_command(
            "rev-list", "--parents", "-n", "1", "HEAD").split()), 3)

    def test_merge_completion_and_abort_reject_unanchored_or_malformed_state(self):
        merge_head = self.gitdir / "MERGE_HEAD"
        outside = self.root / "outside-merge-head"
        outside.write_text(self.head + "\n")
        os.link(outside, merge_head)
        (self.worktree / "src" / "modified.txt").write_text("candidate\n")
        index = (self.gitdir / "index").read_bytes()
        with self.assertRaises(project_git.GitError):
            self.git.commit(self.origin, "11", ["src/modified.txt"], "candidate",
                            self.head, "hermes/task")
        self.assertEqual((self.gitdir / "index").read_bytes(), index)
        self.assertEqual(self.git_command("rev-parse", "HEAD"), self.head)
        for command in (["commit", "--no-edit"], ["merge", "--abort"]):
            with self.subTest(kind="hardlink", command=command), \
                    self.assertRaises(project_git.GitError):
                self.git.run(self.origin, "11", command)
        merge_head.unlink()
        merge_head.write_text("HEAD\n")
        for command in (["commit", "--no-edit"], ["merge", "--abort"]):
            with self.subTest(kind="malformed", command=command), \
                    self.assertRaises(project_git.GitError):
                self.git.run(self.origin, "11", command)

    def test_merge_does_not_materialize_or_execute_unsafe_special_entry(self):
        side = self.side_commit("special/item.txt", "merged\n")
        special = self.worktree / "special"
        special.mkdir()
        fifo = special / "item.txt"
        os.mkfifo(fifo, 0o600)
        value = self.git.run(self.origin, "11", ["merge", "--no-edit", side])
        self.assertEqual((value.effect, value.uncertain, value.local_state),
                         ("unknown", True, "merge_state_absent_after_failure"))
        self.assertTrue(fifo.exists())
        self.assertTrue(stat.S_ISFIFO(os.lstat(fifo).st_mode))

    def test_merge_does_not_follow_symlink_or_mutate_external_hardlink_inode(self):
        side = self.side_commit("boundary/item.txt", "merged\n")
        external = self.root / "external"
        external.mkdir()
        secret = external / "item.txt"
        secret.write_text("secret\n")
        boundary = self.worktree / "boundary"
        self.assertFalse(boundary.exists())
        boundary.symlink_to(external, target_is_directory=True)
        value = self.git.run(self.origin, "11", ["merge", "--no-edit", side])
        self.assertIn(value.effect, {"unknown", "applied"})
        self.assertEqual(secret.read_text(), "secret\n")

        if (self.gitdir / "MERGE_HEAD").exists():
            self.git_command("merge", "--abort")
        self.git_command("reset", "--hard", self.head)
        if boundary.is_symlink():
            boundary.unlink()
        boundary.mkdir()
        hardlink = boundary / "item.txt"
        hardlink.write_text("base\n")
        self.git_command("add", "--", "boundary/item.txt")
        self.git_command("commit", "-m", "boundary base")
        hardlink_base = self.git_command("rev-parse", "HEAD")
        self.git_command("checkout", "-b", "hardlink-side", hardlink_base)
        hardlink.write_text("merged hardlink\n")
        self.git_command("add", "--", "boundary/item.txt")
        self.git_command("commit", "-m", "hardlink side")
        hardlink_side = self.git_command("rev-parse", "HEAD")
        self.git_command("checkout", "hermes/task")
        secret.write_text("base\n")
        hardlink = boundary / "item.txt"
        hardlink.unlink()
        os.link(secret, hardlink)
        value = self.git.run(self.origin, "11", ["merge", "--no-edit", hardlink_side])
        self.assertEqual(value.effect, "applied", repr(value.process))
        self.assertEqual(secret.read_text(), "base\n")
        self.assertEqual(hardlink.read_text(), "merged hardlink\n")
        self.assertNotEqual(os.stat(secret).st_ino, os.stat(hardlink).st_ino)

    def test_hardlinked_gitdir_logs_and_merge_message_block_lifecycle_mutation(self):
        side = self.side_commit("src/modified.txt", "side\n")
        commands = []
        real = self.real_runner
        def runner(argv, **kwargs):
            commands.append(list(argv[5:]))
            return real(argv, **kwargs)
        self.gateway.process_runner = runner

        log = self.gitdir / "logs" / "HEAD"
        external = self.root / "external-log-sentinel"
        os.link(log, external)
        log_bytes = external.read_bytes()
        with self.assertRaises(project_git.GitError):
            self.git.run(self.origin, "11", ["merge", "--no-edit", side])
        self.assertEqual(external.read_bytes(), log_bytes)
        self.assertFalse(any(command[:2] == ["merge", "--no-edit"] for command in commands))
        external.unlink()

        target = self.worktree / "src" / "modified.txt"
        target.write_text("task\n")
        self.git_command("add", "--", "src/modified.txt")
        self.git_command("commit", "-m", "task")
        raw = subprocess.run([*self.git_argv, "merge", "--no-edit", side], capture_output=True)
        self.assertNotEqual(raw.returncode, 0)
        merge_message = self.gitdir / "MERGE_MSG"
        profile = self.root / "profile-sentinel"
        project_sentinel = self.root / "other-project-sentinel"
        os.link(merge_message, profile)
        os.link(merge_message, project_sentinel)
        message = merge_message.read_bytes()
        commands.clear()
        for command in (["commit", "--no-edit"], ["merge", "--abort"]):
            with self.subTest(command=command), self.assertRaises(project_git.GitError):
                self.git.run(self.origin, "11", command)
        self.assertEqual((profile.read_bytes(), project_sentinel.read_bytes()),
                         (message, message))
        self.assertFalse(any(command[0] in {"merge", "commit"} for command in commands))

    def test_annotated_tag_head_and_merge_head_are_never_authoritative_commits(self):
        self.git_command("tag", "-a", "tag-object", "-m", "tag object")
        tag_object = self.git_command("rev-parse", "refs/tags/tag-object")
        token_calls, transports = [], []
        self.gateway.token_reader = lambda request: token_calls.append(request)
        real = self.real_runner
        def runner(argv, **kwargs):
            command = list(argv[5:])
            if command[0] in {"ls-remote", "push"}:
                transports.append(command)
            return real(argv, **kwargs)
        self.gateway.process_runner = runner

        (self.gitdir / "HEAD").write_text(tag_object + "\n")
        inspected = self.gateway.inspect_workspace(self.facts)
        self.assertEqual((inspected.state, inspected.head), ("invalid", None))
        with self.assertRaises(project_git.GitError):
            self.git.remote_ref(self.origin, "11", "hermes/task")
        self.assertEqual((token_calls, transports), ([], []))

        self.git_command("symbolic-ref", "HEAD", "refs/heads/hermes/task")
        (self.gitdir / "refs" / "heads" / "hermes" / "task").write_text(tag_object + "\n")
        inspected = self.gateway.inspect_workspace(self.facts)
        self.assertEqual((inspected.state, inspected.head), ("invalid", None))
        with self.assertRaises(project_git.GitError):
            self.git.push(self.origin, "11", "hermes/task", tag_object, self.head)
        self.assertEqual((token_calls, transports), ([], []))

        self.git_command("update-ref", "refs/heads/hermes/task", self.head)
        (self.gitdir / "MERGE_HEAD").write_text(tag_object + "\n")
        commands = []
        self.gateway.process_runner = lambda argv, **kwargs: (
            commands.append(list(argv[5:])) or real(argv, **kwargs))
        for command in (["commit", "--no-edit"], ["merge", "--abort"]):
            with self.subTest(command=command), self.assertRaises(project_git.GitError):
                self.git.run(self.origin, "11", command)
        self.assertFalse(any(command[0] in {"commit", "merge"} for command in commands))

    def test_all_six_actions_reject_poisoned_metadata_before_provider_token_or_effect(self):
        original = (self.gitdir / "config").read_bytes()
        modified = self.worktree / "src" / "modified.txt"
        modified.write_text("real pending delta\n")
        operations = (
            lambda: self.git.run(self.origin, "11", ["status", "--short"]),
            lambda: self.git.commit(self.origin, "11", ["src/modified.txt"],
                                    "candidate", self.head, "hermes/task"),
            lambda: self.git.remote_ref(self.origin, "11", "hermes/task"),
            lambda: self.git.push(self.origin, "11", "hermes/task", self.head, SHA_A),
            lambda: self.git.delete_remote_branch(
                self.origin, "11", "hermes/task", self.head),
            lambda: self.git.checkout_default(
                self.origin, "11", "hermes/task", self.head, SHA_A),
        )
        for operation in operations:
            with self.subTest(operation=operation):
                provider = []
                tokens = []
                self.gateway.provider_reader = lambda value: provider.append(value)
                self.gateway.token_reader = lambda value: tokens.append(value)
                (self.gitdir / "config").write_bytes(
                    original + b"\n[credential]\n\thelper = store\n")
                before = (
                    subprocess.run([*self.git_argv, "rev-parse", "HEAD"], check=True,
                                   text=True, capture_output=True).stdout,
                    subprocess.run([*self.git_argv, "write-tree"], check=True,
                                   text=True, capture_output=True).stdout,
                    modified.read_bytes(),
                )
                with self.assertRaises(project_git.GitError):
                    operation()
                self.assertEqual((provider, tokens), ([], []))
                after = (
                    subprocess.run([*self.git_argv, "rev-parse", "HEAD"], check=True,
                                   text=True, capture_output=True).stdout,
                    subprocess.run([*self.git_argv, "write-tree"], check=True,
                                   text=True, capture_output=True).stdout,
                    modified.read_bytes(),
                )
                self.assertEqual(after, before)
                (self.gitdir / "config").write_bytes(original)

    def test_hardlinked_config_and_head_reject_before_provider_token_or_effect(self):
        for name in ("config", "HEAD"):
            with self.subTest(name=name):
                entry = self.gitdir / name
                link = self.root / f"linked-{name}"
                os.link(entry, link)
                provider, tokens = [], []
                self.gateway.provider_reader = lambda value: provider.append(value)
                self.gateway.token_reader = lambda value: tokens.append(value)
                with self.assertRaises(project_git.GitError):
                    self.git.remote_ref(self.origin, "11", "hermes/task")
                self.assertEqual((provider, tokens), ([], []))
                link.unlink()

    def test_safe_task_tracking_pair_is_accepted_but_hybrid_and_unknown_config_are_not(self):
        subprocess.run([*self.git_argv, "config", "branch.hermes/task.remote", "origin"],
                       check=True, capture_output=True)
        subprocess.run([*self.git_argv, "config", "branch.hermes/task.merge",
                        "refs/heads/hermes/task"], check=True, capture_output=True)
        self.assertEqual(self.git.run(
            self.origin, "11", ["branch", "--show-current"]).state, "observed")
        original = (self.gitdir / "config").read_bytes()
        for poison in (b"\n[branch \"hybrid\"]\n\tremote = origin\n",
                       b"\n[core]\n\tworktree = /tmp/escape\n",
                       b"\n[include]\n\tpath = /tmp/escape\n"):
            with self.subTest(poison=poison):
                (self.gitdir / "config").write_bytes(original + poison)
                with self.assertRaises(project_git.GitError):
                    self.git.run(self.origin, "11", ["status", "--short"])
        (self.gitdir / "config").write_bytes(original)

    def test_post_mutation_invalid_config_is_reported_unknown(self):
        real = self.real_runner
        changed = False

        def runner(argv, **kwargs):
            nonlocal changed
            result = real(argv, **kwargs)
            if list(argv[5:]) == ["branch", "hermes/new-task"]:
                with (self.gitdir / "config").open("a", encoding="utf-8") as handle:
                    handle.write("\n[filter \"unsafe\"]\n\tclean = /bin/false\n")
                changed = True
            return result

        self.gateway.process_runner = runner
        value = self.git.run(self.origin, "11", ["branch", "hermes/new-task"])
        self.assertTrue(changed)
        self.assertEqual((value.effect, value.uncertain, value.local_state),
                         ("unknown", True, "metadata_invalid_after_effect"))

    def test_add_and_commit_accept_symlink_and_hardlinked_binary(self):
        secret = self.root / "external-secret"
        secret.write_bytes(b"protected bytes\n")
        pdf_source = self.root / "artifact.pdf"
        pdf_bytes = b"%PDF-1.4\n%\x00binary\n%%EOF\n"
        pdf_source.write_bytes(pdf_bytes)
        pdf_source.chmod(0o664)
        link = self.worktree / "src" / "reference"
        link.symlink_to(secret)
        pdf = self.worktree / "main.pdf"
        os.link(pdf_source, pdf)

        added = self.git.run(self.origin, "11", ["add", "--", "src/reference", "main.pdf"])
        self.assertEqual(added.effect, "applied", repr(added))
        staged = self.git_command("ls-files", "--stage", "--", "src/reference", "main.pdf")
        self.assertIn("120000", staged)
        committed = self.git.commit(
            self.origin, "11", ["src/reference", "main.pdf"],
            "add generated artifacts", self.head, "hermes/task")
        self.assertEqual(committed.effect, "committed", repr(committed))
        self.assertEqual(self.git_command("show", "HEAD:src/reference"), str(secret))
        self.assertEqual(subprocess.run(
            [*self.git_argv, "show", "HEAD:main.pdf"], check=True,
            capture_output=True).stdout, pdf_bytes)
        self.assertEqual(secret.read_bytes(), b"protected bytes\n")

    def test_restore_and_clean_hardlinks_preserve_external_contents(self):
        external = self.root / "external"
        external.write_bytes(b"protected bytes\n")
        tracked = self.worktree / "src" / "modified.txt"
        tracked.unlink()
        os.link(external, tracked)

        restored = self.git.run(self.origin, "11", [
            "restore", "--source=HEAD", "--staged", "--worktree", "--",
            "src/modified.txt"])
        self.assertEqual(restored.effect, "applied", repr(restored))
        self.assertEqual(tracked.read_bytes(), b"one\n")
        self.assertEqual(external.read_bytes(), b"protected bytes\n")
        self.assertNotEqual(os.stat(tracked).st_ino, os.stat(external).st_ino)

        untracked = self.worktree / "src" / "untracked-hardlink"
        os.link(external, untracked)
        cleaned = self.git.run(
            self.origin, "11", ["clean", "-fd", "--", "src/untracked-hardlink"])
        self.assertEqual(cleaned.effect, "applied", repr(cleaned))
        self.assertFalse(untracked.exists())
        self.assertEqual(external.read_bytes(), b"protected bytes\n")

    def test_restore_and_clean_do_not_follow_symlinked_directory(self):
        external = self.root / "external-directory"
        external.mkdir()
        secret = external / "item.txt"
        secret.write_bytes(b"protected bytes\n")
        boundary = self.worktree / "boundary"
        boundary.symlink_to(external, target_is_directory=True)

        restored = self.git.run(self.origin, "11", [
            "restore", "--source=HEAD", "--staged", "--worktree", "--",
            "boundary/item.txt"])
        self.assertEqual(restored.effect, "failed", repr(restored))
        cleaned = self.git.run(
            self.origin, "11", ["clean", "-fd", "--", "boundary/item.txt"])
        self.assertEqual(cleaned.effect, "applied", repr(cleaned))
        self.assertTrue(boundary.is_symlink())
        self.assertEqual(secret.read_bytes(), b"protected bytes\n")

    def test_run_force_deletes_unmerged_task_and_exactly_restores_and_cleans_without_token(self):
        env = dict(os.environ, GIT_AUTHOR_NAME="Test", GIT_AUTHOR_EMAIL="test@example.invalid",
                   GIT_COMMITTER_NAME="Test", GIT_COMMITTER_EMAIL="test@example.invalid")
        tree = subprocess.run([*self.git_argv, "rev-parse", "HEAD^{tree}"], check=True,
                              text=True, capture_output=True).stdout.strip()
        divergent = subprocess.run(
            [*self.git_argv, "commit-tree", tree, "-p", self.head], input="divergent\n",
            check=True, text=True, capture_output=True, env=env).stdout.strip()
        subprocess.run([*self.git_argv, "update-ref", "refs/heads/hermes/unmerged", divergent],
                       check=True, capture_output=True)
        self.gateway.token_reader = lambda _request: self.fail("local run requested a token")
        deleted = self.git.run(self.origin, "11", ["branch", "-D", "hermes/unmerged"])
        self.assertEqual(deleted.effect, "applied")
        self.assertNotEqual(subprocess.run(
            [*self.git_argv, "show-ref", "--verify", "refs/heads/hermes/unmerged"],
            capture_output=True).returncode, 0)

        tracked = self.worktree / "src" / "modified.txt"
        tracked.write_text("dirty\n")
        subprocess.run([*self.git_argv, "add", "--", "src/modified.txt"], check=True,
                       capture_output=True)
        restored = self.git.run(self.origin, "11", [
            "restore", "--source=HEAD", "--staged", "--worktree", "--", "src/modified.txt"])
        self.assertEqual(restored.effect, "applied")
        self.assertEqual(tracked.read_text(), "one\n")
        untracked = self.worktree / "src" / "generated.txt"
        sentinel = self.worktree / "outside-sentinel.txt"
        untracked.write_text("remove\n")
        sentinel.write_text("keep\n")
        cleaned = self.git.run(self.origin, "11", ["clean", "-fd", "--", "src/generated.txt"])
        self.assertEqual(cleaned.effect, "applied")
        self.assertFalse(untracked.exists())
        self.assertEqual(sentinel.read_text(), "keep\n")

    def test_descriptor_command_paths_use_named_fallback_and_never_dev_fd(self):
        descriptor = self.git._descriptor(self.facts)
        with project_git.host_boundary.DescriptorAnchor(descriptor) as anchor:
            argv = project_git.host_boundary.sterile_git_argv(
                descriptor, ["status"], anchor=anchor)
            self.assertNotIn("/dev/fd/", " ".join(argv))
            if not Path("/proc/self/fd").is_dir():
                self.assertEqual(anchor.command_paths,
                                 (str(self.worktree), str(self.gitdir)))
        with mock.patch.object(project_git.host_boundary.DescriptorAnchor, "_proc_fdpath",
                               side_effect=lambda fd: f"/proc/self/fd/{fd}"):
            with project_git.host_boundary.DescriptorAnchor(descriptor) as anchor:
                self.assertTrue(anchor.command_worktree.startswith("/proc/self/fd/"))
                self.assertTrue(anchor.command_gitdir.startswith("/proc/self/fd/"))

    def test_post_invocation_worktree_and_gitdir_swaps_downgrade_to_unknown(self):
        for target in ("worktree", "gitdir"):
            with self.subTest(target=target):
                path = getattr(self, target)
                old = path.with_name(path.name + "-anchored")
                replacement = path.with_name(path.name + "-replacement")
                real = self.real_runner
                swapped = False

                def runner(argv, **kwargs):
                    nonlocal swapped
                    value = real(argv, **kwargs)
                    if not swapped and list(argv[5:]) == ["branch", "--show-current"]:
                        path.rename(old)
                        replacement.mkdir(mode=0o700)
                        replacement.rename(path)
                        swapped = True
                    return value

                self.gateway.process_runner = runner
                try:
                    value = self.git.run(self.origin, "11", ["branch", "--show-current"])
                    self.assertEqual((value.state, value.uncertain, value.anchor_state),
                                     ("unknown", True, "changed"))
                    self.assertIsNotNone(value.process)
                finally:
                    if swapped:
                        path.rename(replacement)
                        old.rename(path)
                        if replacement.is_dir():
                            replacement.rmdir()
                    self.gateway.process_runner = self.real_runner

    def test_pre_invocation_drift_rejects_with_zero_runner_calls(self):
        descriptor = self.git._descriptor(self.facts)
        anchor = self.git._open(descriptor)
        old = self.worktree.with_name("worktree-anchored")
        replacement = self.worktree.with_name("worktree-replacement")
        calls = 0
        original = project_git.host_boundary.sterile_local_git_environment

        def prepare(*args, **kwargs):
            self.worktree.rename(old)
            replacement.mkdir(mode=0o700)
            replacement.rename(self.worktree)
            return original(*args, **kwargs)

        def runner(*args, **kwargs):
            nonlocal calls
            calls += 1
            return self.result()

        self.gateway.process_runner = runner
        try:
            with mock.patch.object(project_git.host_boundary, "sterile_local_git_environment",
                                    side_effect=prepare):
                value = self.git._process(descriptor, ["status"], anchor)
            self.assertEqual(value["state"], "spawn_failed")
            self.assertEqual(calls, 0)
        finally:
            self.worktree.rename(replacement)
            old.rename(self.worktree)
            replacement.rmdir()
            self.git._close_anchor(anchor)

    def test_process_rejects_malformed_positive_results_for_checkout_target_and_clean(self):
        valid = self.result()
        malformed = []
        for missing in ("state", "exit_code", "stdout", "stderr", "uncertain",
                        "stdout_truncated", "stderr_truncated"):
            malformed.append({key: value for key, value in valid.items() if key != missing})
        malformed.extend((
            {**valid, "state": "unknown"},
            {**valid, "exit_code": False},
            {**valid, "exit_code": 0.0},
            {**valid, "exit_code": "0"},
            {**valid, "uncertain": 0},
            {**valid, "stdout_truncated": 0},
            {**valid, "stderr_truncated": 0},
            {**valid, "state": "timed_out", "exit_code": 0},
            {**valid, "state": "signaled", "exit_code": -9},
            {**valid, "state": "spawn_failed", "exit_code": 1},
            {**valid, "state": "rejected", "exit_code": 1},
        ))
        commands = (
            ["checkout", "--no-recurse-submodules", "--no-overwrite-ignore",
             "-b", "main", f"{self.head}^{{commit}}"],
            ["rev-parse", "--verify", "refs/remotes/origin/main"],
            ["status", "--porcelain=v1", "--untracked-files=all"],
        )
        descriptor = self.git._descriptor(self.facts)
        for command in commands:
            for raw in malformed:
                with self.subTest(command=command[0], raw=raw):
                    self.gateway.process_runner = lambda *args, value=raw, **kwargs: value
                    anchor = self.git._open(descriptor)
                    try:
                        result = self.git._process(descriptor, command, anchor)
                    finally:
                        self.git._close_anchor(anchor)
                    self.assertEqual(project_git.ProjectGit._status(result), "uncertain")
                    self.assertEqual(result["failure"], "runner_result_unknown")
                    self.assertIs(result["stdout_truncated"], False)
                    self.assertIs(result["stderr_truncated"], False)

    def test_remote_ref_public_present_absent_malformed_and_timeout(self):
        cases = ((f"{SHA_A}\trefs/heads/hermes/task\n", "exited", "present", False),
                 ("", "exited", "absent", False),
                 ("malformed\n", "exited", "unknown", True),
                 ("", "timed_out", "unknown", True))
        for stdout, state, expected, uncertain in cases:
            with self.subTest(expected=expected):
                self.gateway.token_reader = lambda _request: self.token_response("git_remote_read")
                def handler(command, _kwargs):
                    if command[0] == "ls-remote":
                        return self.result(stdout, state=state,
                                           exit_code=0 if state == "exited" else None,
                                           uncertain=state == "timed_out")
                    return None
                self.install_script(handler, "git_remote_read")
                value = self.git.remote_ref(self.origin, "11", "hermes/task")
                self.assertEqual((value.state, value.uncertain), (expected, uncertain))

    def test_same_id_provider_drift_supplies_live_route_and_token_identity_without_registry_write(self):
        fresh = project.ProviderObservation(
            "11", "99", "new-owner", "new-repo",
            "https://github.com/new-owner/new-repo.git", "trunk")
        self.gateway.provider_reader = lambda _candidate: fresh
        requests = []
        commands = []

        def token(request):
            requests.append(dict(request))
            response = self.token_response("git_remote_read")
            response["repositories"] = [
                {"id": 11, "name": "new-repo", "full_name": "new-owner/new-repo"}]
            return response

        self.gateway.token_reader = token
        def handler(command, _kwargs):
            if command[0] == "ls-remote":
                commands.append(command)
                return self.result()
            return None
        self.install_script(handler, "git_remote_read")
        self.gateway.token_reader = token
        before = self.facts
        value = self.git.remote_ref(self.origin, "11", "hermes/task")
        with self.gateway.locked_current_route(self.origin) as route:
            after = route.repository
        self.assertEqual(value.state, "absent")
        self.assertEqual(requests[0]["installation_id"], 99)
        self.assertEqual(commands[0][2], fresh.url)
        self.assertEqual(before, after)
        self.assertEqual((after.owner, after.name, after.default_branch),
                          ("owner", "repo", "main"))

    def test_every_route_descriptor_rejects_stale_fixed_non_id_and_profile_paths(self):
        calls = []
        self.gateway.process_runner = lambda argv, **kwargs: calls.append(argv)
        key = (self.origin.workspace_id, self.origin.channel_id)
        original = self.gateway._fixed[key]

        stale = replace(self.facts, owner="stale-owner",
                        url="https://github.com/stale-owner/repo.git")
        self.gateway._fixed_by_id["11"] = project.FixedProject(self.origin, stale)
        with self.assertRaises(project_git.GitError):
            self.git.run(self.origin, "11", ["status", "--short"])
        self.gateway._fixed_by_id.clear()

        self.gateway._fixed[key] = project.FixedProject(
            self.origin, replace(self.facts, worktree=str(self.root / "not-id-derived")))
        with self.assertRaises(project_git.GitError):
            self.git.run(self.origin, "11", ["status", "--short"])

        self.gateway._fixed[key] = original
        self.gateway.protected_profile_root = self.root / "workspace-root"
        with self.assertRaises(project_git.GitError):
            self.git.run(self.origin, "11", ["status", "--short"])
        self.gateway.protected_profile_root = None
        self.assertFalse(calls)

    def test_different_provider_id_rejects_before_token_or_transport(self):
        self.gateway.provider_reader = lambda _candidate: project.ProviderObservation(
            "12", "99", "other", "repo", "https://github.com/other/repo.git", "main")
        token_calls = []
        process_calls = []
        self.gateway.token_reader = lambda request: token_calls.append(request)
        self.gateway.process_runner = lambda argv, **kwargs: process_calls.append(argv)
        with self.assertRaises(project_git.GitError):
            self.git.remote_ref(self.origin, "11", "hermes/task")
        self.assertFalse(token_calls)
        self.assertFalse(any("ls-remote" in call or "push" in call for call in process_calls))

    def test_live_default_rename_blocks_push_and_delete_before_token(self):
        commit = self.make_child()
        self.gateway.provider_reader = lambda _candidate: project.ProviderObservation(
            "11", "7", "owner", "repo", "https://github.com/owner/repo.git", "hermes/task")
        token_calls = []
        transport_calls = []
        self.gateway.token_reader = lambda request: token_calls.append(request)
        self.gateway.process_runner = lambda argv, **kwargs: transport_calls.append(argv)
        for operation in (
                lambda: self.git.push(self.origin, "11", "hermes/task", commit, self.head),
                lambda: self.git.delete_remote_branch(
                    self.origin, "11", "hermes/task", self.head)):
            with self.assertRaises(project_git.GitError):
                operation()
        self.assertFalse(token_calls)
        self.assertFalse(any("ls-remote" in call or "push" in call for call in transport_calls))

    def test_push_is_non_forced_for_existing_and_absent_branches_and_classifies_outcomes(self):
        commit = self.make_child()
        cases = ((self.head, "", "published", False),
                  (None, "", "published", False),
                  (self.head, "[rejected] fetch first", "unknown", True),
                  (self.head, "fatal generic", "unknown", True))
        for target, error, effect, uncertain in cases:
            with self.subTest(target=target, error=error):
                remote = ((f"{target}\trefs/heads/hermes/task\n" if target else "")
                          + f"{self.head}\trefs/heads/main\n")
                def handler(command, _kwargs):
                    if command[0] == "ls-remote":
                        return self.result(remote)
                    if command[0] == "push":
                        return self.result(stderr=error, exit_code=1 if error else 0)
                    return None
                calls = self.install_script(handler)
                value = self.git.push(self.origin, "11", "hermes/task", commit, self.head)
                self.assertEqual((value.effect, value.uncertain), (effect, uncertain))
                push = next(command for command, _ in calls if command[0] == "push")
                self.assertFalse(any(argument.startswith("--force") for argument in push))
                self.assertEqual(push[2], "https://github.com/owner/repo.git")
                self.assertEqual(push[-1], f"{commit}^{{commit}}:refs/heads/hermes/task")

    def test_push_commit_source_ignores_colliding_sha_named_local_branch(self):
        commit = self.make_child()
        self.git_command("update-ref", f"refs/heads/{commit}", self.head)
        remote = f"{self.head}\trefs/heads/hermes/task\n{self.head}\trefs/heads/main\n"
        resolved = []
        def handler(command, _kwargs):
            if command[0] == "ls-remote":
                return self.result(remote)
            if command[0] == "push":
                source = command[-1].split(":", 1)[0]
                resolved.append(self.git_command("rev-parse", "--verify", source))
                return self.result()
            return None
        calls = self.install_script(handler)
        value = self.git.push(self.origin, "11", "hermes/task", commit, self.head)
        self.assertEqual(value.effect, "published")
        push = next(command for command, _ in calls if command[0] == "push")
        self.assertEqual(push[-1], f"{commit}^{{commit}}:refs/heads/hermes/task")
        self.assertEqual(resolved, [commit])
        self.assertEqual(self.git_command("rev-parse", f"refs/heads/{commit}"), self.head)

    def test_push_empty_range_rejects_before_provider_token_or_transport(self):
        provider, tokens, transport = [], [], []
        self.gateway.provider_reader = lambda value: provider.append(value)
        self.gateway.token_reader = lambda value: tokens.append(value)
        self.gateway.process_runner = lambda argv, **kwargs: transport.append(list(argv))
        with self.assertRaises(project_git.GitError):
            self.git.push(self.origin, "11", "hermes/task", self.head, self.head)
        self.assertEqual((provider, tokens, transport), ([], [], []))

    def test_push_accepts_two_commit_linear_descendant_range(self):
        self.make_child()
        commit = self.make_child()
        remote = f"{self.head}\trefs/heads/hermes/task\n{self.head}\trefs/heads/main\n"
        def handler(command, _kwargs):
            if command[0] == "ls-remote": return self.result(remote)
            if command[0] == "push": return self.result()
            return None
        calls = self.install_script(handler)
        value = self.git.push(self.origin, "11", "hermes/task", commit, self.head)
        self.assertEqual(value.effect, "published")
        self.assertEqual(len([command for command, _ in calls if command[0] == "push"]), 1)

    def test_push_ignores_retired_path_policy_across_linear_range(self):
        env = dict(os.environ, GIT_AUTHOR_NAME="Test", GIT_AUTHOR_EMAIL="test@example.invalid",
                   GIT_COMMITTER_NAME="Test", GIT_COMMITTER_EMAIL="test@example.invalid")
        forbidden = self.worktree / "forbidden.txt"
        forbidden.write_text("temporary\n")
        subprocess.run([*self.git_argv, "add", "--", "forbidden.txt"], check=True,
                       capture_output=True, env=env)
        subprocess.run([*self.git_argv, "commit", "-m", "forbidden intermediate"], check=True,
                       capture_output=True, env=env)
        forbidden.unlink()
        subprocess.run([*self.git_argv, "add", "--", "forbidden.txt"], check=True,
                       capture_output=True, env=env)
        subprocess.run([*self.git_argv, "commit", "-m", "revert forbidden"], check=True,
                       capture_output=True, env=env)
        commit = subprocess.run([*self.git_argv, "rev-parse", "HEAD"], check=True,
                                text=True, capture_output=True).stdout.strip()
        remote = f"{self.head}\trefs/heads/hermes/task\n{self.head}\trefs/heads/main\n"
        def handler(command, _kwargs):
            if command[0] == "ls-remote": return self.result(remote)
            if command[0] == "push": return self.result()
            return None
        self.install_script(handler)
        self.assertEqual(self.git.push(
            self.origin, "11", "hermes/task", commit, self.head).effect, "published")

    def test_push_replay_and_divergence_do_not_transmit(self):
        commit = self.make_child()
        for target, expected in ((commit, "already_published"), (SHA_A, "error")):
            pushed = []
            remote = f"{target}\trefs/heads/hermes/task\n{self.head}\trefs/heads/main\n"
            def handler(command, _kwargs):
                if command[0] == "ls-remote": return self.result(remote)
                if command[0] == "push": pushed.append(command); return self.result()
                return None
            self.install_script(handler)
            if expected == "error":
                with self.assertRaises(project_git.GitError):
                    self.git.push(self.origin, "11", "hermes/task", commit, self.head)
            else:
                self.assertEqual(self.git.push(self.origin, "11", "hermes/task",
                                               commit, self.head).effect, expected)
            self.assertFalse(pushed)

    def test_push_accepts_merge_containing_base_and_rejects_wrong_base_before_transmission(self):
        env = dict(os.environ, GIT_AUTHOR_NAME="Test", GIT_AUTHOR_EMAIL="test@example.invalid",
                   GIT_COMMITTER_NAME="Test", GIT_COMMITTER_EMAIL="test@example.invalid")
        tree = subprocess.run([*self.git_argv, "rev-parse", "HEAD^{tree}"], check=True,
                              text=True, capture_output=True).stdout.strip()

        def commit_tree(*parents):
            command = [*self.git_argv, "commit-tree", tree]
            for parent in parents:
                command.extend(["-p", parent])
            return subprocess.run(command, input="candidate\n", check=True, text=True,
                                  capture_output=True, env=env).stdout.strip()

        unrelated = commit_tree()
        merge = commit_tree(self.head, unrelated)
        subprocess.run([*self.git_argv, "update-ref", "refs/heads/hermes/task", merge],
                       check=True, capture_output=True)
        remote = f"{self.head}\trefs/heads/hermes/task\n{self.head}\trefs/heads/main\n"
        def handler(command, _kwargs):
            if command[0] == "ls-remote": return self.result(remote)
            if command[0] == "push": return self.result()
            return None
        calls = self.install_script(handler)
        self.assertEqual(self.git.push(
            self.origin, "11", "hermes/task", merge, self.head).effect, "published")
        self.assertEqual(len([command for command, _ in calls if command[0] == "push"]), 1)

        subprocess.run([*self.git_argv, "update-ref", "refs/heads/hermes/task", unrelated],
                       check=True, capture_output=True)
        token_calls = []
        self.gateway.token_reader = lambda request: token_calls.append(request)
        with self.assertRaises(project_git.GitError):
            self.git.push(self.origin, "11", "hermes/task", unrelated, self.head)
        self.assertFalse(token_calls)

    def test_delete_exact_lease_success_absent_mismatch_rejection_and_timeout(self):
        cases = ((self.head, "success", "deleted", False),
                 (None, "success", "no_effect", False),
                 (self.head, "reject", "no_effect", False),
                 (self.head, "timeout", "unknown", True))
        for target, outcome, effect, uncertain in cases:
            remote = f"{target}\trefs/heads/hermes/task\n" if target else ""
            def handler(command, _kwargs):
                if command[0] == "ls-remote": return self.result(remote)
                if command[0] == "push":
                    if outcome == "reject": return self.result(stderr="[rejected] stale info", exit_code=1)
                    if outcome == "timeout": return self.result(state="timed_out", exit_code=None, uncertain=True)
                    return self.result()
                return None
            calls = self.install_script(handler)
            value = self.git.delete_remote_branch(self.origin, "11", "hermes/task", self.head)
            self.assertEqual((value.effect, value.uncertain), (effect, uncertain))
            pushes = [command for command, _ in calls if command[0] == "push"]
            if target:
                self.assertEqual(pushes[0][2],
                    f"--force-with-lease=refs/heads/hermes/task:{self.head}")

    def test_delete_rejects_mismatch_and_default_before_transmission(self):
        pushed = []
        def handler(command, _kwargs):
            if command[0] == "ls-remote":
                return self.result(f"{SHA_A}\trefs/heads/hermes/task\n")
            if command[0] == "push": pushed.append(command); return self.result()
            return None
        self.install_script(handler)
        with self.assertRaises(project_git.GitError):
            self.git.delete_remote_branch(self.origin, "11", "hermes/task", self.head)
        with self.assertRaises(project_git.GitError):
            self.git.delete_remote_branch(self.origin, "11", "main", self.head)
        self.assertFalse(pushed)

    def test_delete_allows_exact_non_default_branch_without_legacy_prefix(self):
        def handler(command, _kwargs):
            if command[0] == "ls-remote":
                return self.result(f"{self.head}\trefs/heads/release\n")
            if command[0] == "push":
                return self.result()
            return None
        calls = self.install_script(handler)
        result = self.git.delete_remote_branch(self.origin, "11", "release", self.head)
        self.assertEqual(result.effect, "deleted")
        self.assertTrue(any(command[0] == "push" for command, _ in calls))

    def test_checkout_default_clean_success_records_exact_post_state_without_fetch_or_push(self):
        commands = []
        checked_out = False
        def handler(command, _kwargs):
            nonlocal checked_out
            commands.append(command)
            if command[0] == "checkout": checked_out = True; return self.result()
            if command[0] == "symbolic-ref":
                return self.result("main\n" if checked_out else "hermes/task\n")
            if command[:2] == ["rev-parse", "--verify"]:
                target = command[-1].startswith("refs/remotes/")
                exact = command[-1] == f"{SHA_A}^{{commit}}"
                return self.result((SHA_A if checked_out or target or exact else self.head) + "\n")
            if command[:2] == ["rev-parse", "--abbrev-ref"]: return self.result("origin/main\n")
            if command[:2] == ["status", "--porcelain=v1"]: return self.result()
            return None
        self.install_script(handler)
        value = self.git.checkout_default(
            self.origin, "11", "hermes/task", self.head, SHA_A)
        self.assertEqual((value.effect, value.commit, value.uncertain),
                         ("checked_out", SHA_A, False))
        self.assertEqual(value.local_state,
                          f"branch=main;head={SHA_A};upstream=origin/main;clean=true;target={SHA_A}")
        checkout = next(command for command in commands if command[0] == "checkout")
        self.assertEqual(checkout[-1], f"{SHA_A}^{{commit}}")
        self.assertIn("--no-overwrite-ignore", checkout)
        self.assertFalse(any(command[0] in {"fetch", "push"} for command in commands))

    def test_checkout_default_real_git_is_one_local_effect_and_mints_no_token(self):
        subprocess.run([*self.git_argv, "config", "remote.origin.url", self.facts.url],
                       check=True, capture_output=True)
        subprocess.run([*self.git_argv, "config", "remote.origin.fetch",
                        "+refs/heads/*:refs/remotes/origin/*"], check=True, capture_output=True)
        subprocess.run([*self.git_argv, "config", "branch.main.remote", "origin"],
                       check=True, capture_output=True)
        subprocess.run([*self.git_argv, "config", "branch.main.merge", "refs/heads/main"],
                       check=True, capture_output=True)
        subprocess.run([*self.git_argv, "update-ref", "refs/remotes/origin/main", self.head],
                       check=True, capture_output=True)
        self.gateway.token_reader = lambda _request: self.fail("token minted")
        value = self.git.checkout_default(
            self.origin, "11", "hermes/task", self.head, self.head)
        self.assertEqual((value.effect, value.branch, value.commit, value.uncertain),
                         ("checked_out", "main", self.head, False), repr(value))
        self.assertEqual(subprocess.run(
            [*self.git_argv, "branch", "--show-current"], check=True, text=True,
            capture_output=True).stdout.strip(), "main")
        self.assertEqual(subprocess.run(
            [*self.git_argv, "rev-parse", "--abbrev-ref", "@{upstream}"], check=True,
            text=True, capture_output=True).stdout.strip(), "origin/main")

    def test_checkout_default_materializes_fetched_default_from_canonical_unborn_workspace(self):
        target = self.make_unborn_default()
        commands = []
        real = self.real_runner

        def runner(argv, **kwargs):
            commands.append(list(argv[5:]))
            return real(argv, **kwargs)

        self.gateway.process_runner = runner
        self.gateway.token_reader = lambda _request: self.fail("checkout requested a token")
        value = self.git.checkout_default(
            self.origin, "11", "main", None, target)
        self.assertEqual((value.effect, value.branch, value.commit, value.uncertain),
                         ("checked_out", "main", target, False), repr(value))
        self.assertEqual(value.local_state,
                         f"branch=main;head={target};upstream=origin/main;clean=true;target={target}")
        self.assertEqual(self.git_command("branch", "--show-current"), "main")
        self.assertEqual(self.git_command("rev-parse", "HEAD"), target)
        self.assertEqual(self.git_command("rev-parse", "--abbrev-ref", "@{upstream}"),
                         "origin/main")
        self.assertEqual(self.git_command("status", "--porcelain=v1"), "")
        self.assertEqual((self.worktree / "src" / "modified.txt").read_bytes(), b"one\n")
        self.assertFalse(any(command[0] in {"fetch", "push"} for command in commands))

    def test_checkout_default_unborn_requires_fresh_provider_default_branch(self):
        target = self.make_unborn_default()
        self.git_command("update-ref", "refs/remotes/origin/trunk", target)
        self.gateway.provider_reader = lambda _candidate: project.ProviderObservation(
            "11", "7", "owner", "repo", self.facts.url, "trunk")
        commands = []
        real = self.real_runner
        self.gateway.process_runner = lambda argv, **kwargs: (
            commands.append(list(argv[5:])) or real(argv, **kwargs))
        with self.assertRaises(project_git.GitError):
            self.git.checkout_default(self.origin, "11", "main", None, target)
        self.assertFalse(any(command[0] == "checkout" for command in commands))

    def test_checkout_default_unborn_branch_creation_race_is_atomic_and_lossless(self):
        concurrent = self.make_child()
        target = self.make_unborn_default()
        commands = []
        real = self.real_runner

        def runner(argv, **kwargs):
            command = list(argv[5:])
            commands.append(command)
            if command and command[0] == "checkout":
                self.git_command("update-ref", "refs/heads/main", concurrent)
            return real(argv, **kwargs)

        self.gateway.process_runner = runner
        value = self.git.checkout_default(self.origin, "11", "main", None, target)
        self.assertEqual((value.effect, value.uncertain, value.local_state),
                         ("unknown", True, "checkout_unknown"))
        self.assertEqual(self.git_command("rev-parse", "refs/heads/main"), concurrent)
        self.assertEqual(list(self.worktree.iterdir()), [])
        checkout = next(command for command in commands if command[0] == "checkout")
        self.assertIn("-b", checkout)
        self.assertNotIn("-B", checkout)

    def test_checkout_default_does_not_overwrite_ignored_target_collision(self):
        target = self.side_commit("ignored.txt", "target bytes\n")
        self.make_unborn_default(target)
        info = self.gitdir / "info"
        info.mkdir(exist_ok=True)
        (info / "exclude").write_text("ignored.txt\n", encoding="utf-8")
        sentinel = self.worktree / "ignored.txt"
        sentinel.write_bytes(b"sentinel bytes\n")
        commands = []
        real = self.real_runner
        self.gateway.process_runner = lambda argv, **kwargs: (
            commands.append(list(argv[5:])) or real(argv, **kwargs))
        value = self.git.checkout_default(self.origin, "11", "main", None, target)
        self.assertEqual(value.effect, "unknown")
        self.assertTrue(value.uncertain)
        self.assertEqual(sentinel.read_bytes(), b"sentinel bytes\n")
        checkout = next(command for command in commands if command[0] == "checkout")
        self.assertIn("--no-overwrite-ignore", checkout)

    def test_checkout_default_rejects_noncommit_target_object_before_checkout(self):
        self.git_command("tag", "-a", "poison", "-m", "poison")
        tag_object = self.git_command("rev-parse", "refs/tags/poison")
        self.git_command("update-ref", "refs/remotes/origin/main", tag_object)
        commands = []
        real = self.real_runner
        self.gateway.process_runner = lambda argv, **kwargs: (
            commands.append(list(argv[5:])) or real(argv, **kwargs))
        with self.assertRaises(project_git.GitError):
            self.git.checkout_default(
                self.origin, "11", "hermes/task", self.head, tag_object)
        self.assertFalse(any(command[0] == "checkout" for command in commands))

    def test_checkout_default_unborn_rejects_local_ref_race_before_checkout(self):
        target = self.make_unborn_default()
        commands = []
        injected = False
        real = self.real_runner

        def runner(argv, **kwargs):
            nonlocal injected
            command = list(argv[5:])
            commands.append(command)
            result = real(argv, **kwargs)
            if command == ["rev-parse", "--verify", "refs/remotes/origin/main"]:
                self.git_command("update-ref", "refs/heads/main", target)
                injected = True
            return result

        self.gateway.process_runner = runner
        with self.assertRaises(project_git.GitError):
            self.git.checkout_default(self.origin, "11", "main", None, target)
        self.assertTrue(injected)
        self.assertFalse(any(command[0] == "checkout" for command in commands))

    def test_checkout_default_post_observation_failure_preserves_checkout_success(self):
        checked_out = False
        def handler(command, _kwargs):
            nonlocal checked_out
            if command[0] == "checkout": checked_out = True; return self.result()
            if command[0] == "symbolic-ref":
                return self.result("main\n" if checked_out else "hermes/task\n")
            if command[:2] == ["rev-parse", "--verify"]:
                if not checked_out:
                    return self.result((SHA_A if command[-1].startswith("refs/remotes/")
                                        or command[-1] == f"{SHA_A}^{{commit}}"
                                        else self.head) + "\n")
                return self.result(state="timed_out", exit_code=None, uncertain=True)
            if command[:2] == ["rev-parse", "--abbrev-ref"]: return self.result("origin/main\n")
            if command[:2] == ["status", "--porcelain=v1"]: return self.result()
            return None
        self.install_script(handler)
        value = self.git.checkout_default(
            self.origin, "11", "hermes/task", self.head, SHA_A)
        self.assertEqual(value.effect, "unknown")
        self.assertTrue(value.uncertain)
        self.assertIn("post_observation_uncertain:head,target", value.local_state or "")
        self.assertIn("metadata_invalid_after_effect", value.local_state or "")

    def test_checkout_default_success_then_poison_is_metadata_uncertain(self):
        checked_out = False
        original = (self.gitdir / "config").read_bytes()
        def handler(command, _kwargs):
            nonlocal checked_out
            if command[0] == "checkout":
                checked_out = True
                (self.gitdir / "config").write_bytes(
                    original + b"\n[credential]\n\thelper = store\n")
                return self.result()
            if command[0] == "symbolic-ref":
                return self.result("main\n" if checked_out else "hermes/task\n")
            if command[:2] == ["rev-parse", "--verify"]:
                return self.result((SHA_A if checked_out or command[-1].startswith(
                    "refs/remotes/") or command[-1] == f"{SHA_A}^{{commit}}"
                                    else self.head) + "\n")
            if command[:2] == ["rev-parse", "--abbrev-ref"]:
                return self.result("origin/main\n")
            if command[:2] == ["status", "--porcelain=v1"]:
                return self.result()
            return None
        self.install_script(handler)
        value = self.git.checkout_default(
            self.origin, "11", "hermes/task", self.head, SHA_A)
        self.assertTrue(checked_out)
        self.assertEqual((value.effect, value.uncertain, value.local_state),
                         ("unknown", True, "metadata_invalid_after_effect"))

    def test_checkout_default_post_head_mismatch_is_uncertain(self):
        checked_out = False
        def handler(command, _kwargs):
            nonlocal checked_out
            if command[0] == "checkout": checked_out = True; return self.result()
            if command[0] == "symbolic-ref":
                return self.result("main\n" if checked_out else "hermes/task\n")
            if command[:2] == ["rev-parse", "--verify"]:
                if (command[-1].startswith("refs/remotes/")
                        or command[-1] == f"{SHA_A}^{{commit}}"):
                    return self.result(SHA_A + "\n")
                return self.result((SHA_B if checked_out else self.head) + "\n")
            if command[:2] == ["rev-parse", "--abbrev-ref"]: return self.result("origin/main\n")
            if command[:2] == ["status", "--porcelain=v1"]: return self.result()
            return None
        self.install_script(handler)
        value = self.git.checkout_default(
            self.origin, "11", "hermes/task", self.head, SHA_A)
        self.assertEqual((value.effect, value.commit, value.uncertain),
                          ("unknown", SHA_B, True))
        self.assertIn("head", value.local_state or "")

    def test_checkout_default_post_target_mismatch_or_truncation_is_unknown(self):
        for outcome in ("mismatch", "truncated"):
            with self.subTest(outcome=outcome):
                checked_out = False

                def handler(command, _kwargs):
                    nonlocal checked_out
                    if command[0] == "checkout":
                        checked_out = True
                        return self.result()
                    if command[0] == "symbolic-ref":
                        return self.result("main\n" if checked_out else "hermes/task\n")
                    if command[:2] == ["rev-parse", "--verify"]:
                        if command[-1].startswith("refs/remotes/") and checked_out:
                            value = self.result((SHA_B if outcome == "mismatch" else SHA_A) + "\n")
                            if outcome == "truncated":
                                value["stdout_truncated"] = True
                            return value
                        return self.result((SHA_A if command[-1].startswith("refs/remotes/")
                                            or command[-1] == f"{SHA_A}^{{commit}}"
                                            or checked_out else self.head) + "\n")
                    if command[:2] == ["rev-parse", "--abbrev-ref"]:
                        return self.result("origin/main\n")
                    if command[:2] == ["status", "--porcelain=v1"]:
                        return self.result()
                    return None

                self.install_script(handler)
                value = self.git.checkout_default(
                    self.origin, "11", "hermes/task", self.head, SHA_A)
                self.assertEqual((value.effect, value.commit, value.uncertain),
                                 ("unknown", SHA_A, True))
                self.assertIn("target", value.local_state or "")

    def test_unborn_head_missing_result_is_exactly_real_git_exit_shape(self):
        valid = self.result(stderr="fatal", exit_code=128)
        self.assertTrue(project_git.ProjectGit._exact_missing_head(valid))
        malformed = (
            {**valid, "exit_code": True}, {**valid, "exit_code": "128"},
            {**valid, "exit_code": 1}, {**valid, "exit_code": 129},
            {**valid, "stdout": "unexpected\n"}, {**valid, "uncertain": True},
            {**valid, "stdout_truncated": True}, {**valid, "stderr_truncated": True},
            {key: value for key, value in valid.items() if key != "stdout_truncated"},
            {key: value for key, value in valid.items() if key != "stderr_truncated"},
        )
        for result in malformed:
            with self.subTest(result=result):
                self.assertFalse(project_git.ProjectGit._exact_missing_head(result))

    def test_checkout_default_dirty_rejects_before_fetch_or_push(self):
        (self.worktree / "src" / "modified.txt").write_text("dirty\n")
        token_calls = []
        commands = []
        real = self.real_runner
        def runner(argv, **kwargs):
            commands.append(list(argv[5:]))
            return real(argv, **kwargs)
        self.gateway.process_runner = runner
        self.gateway.token_reader = lambda request: token_calls.append(request)
        with self.assertRaises(project_git.GitError):
            self.git.checkout_default(
                self.origin, "11", "hermes/task", self.head, self.head)
        self.assertFalse(token_calls)
        self.assertFalse(any(command[0] in {"fetch", "push"} for command in commands))

    def test_checkout_default_timeout_is_unknown(self):
        def handler(command, _kwargs):
            if command[:2] == ["rev-parse", "--verify"] \
                    and command[-1].startswith("refs/remotes/"):
                return self.result(self.head + "\n")
            if command[0] == "checkout":
                return self.result(state="timed_out", exit_code=None, uncertain=True)
            return None
        self.install_script(handler)
        value = self.git.checkout_default(
            self.origin, "11", "hermes/task", self.head, self.head)
        self.assertEqual((value.effect, value.uncertain, value.local_state),
                          ("unknown", True, "checkout_unknown"))

    def test_checkout_default_rejects_stale_or_concurrently_changed_target_before_checkout(self):
        for actual in (SHA_B, SHA_A):
            with self.subTest(actual=actual):
                checked_out = []
                def handler(command, _kwargs):
                    if command[0] == "checkout":
                        checked_out.append(command)
                        return self.result()
                    if command[:2] == ["rev-parse", "--verify"] \
                            and command[-1].startswith("refs/remotes/"):
                        return self.result(actual + "\n")
                    return None
                self.install_script(handler)
                with self.assertRaises(project_git.GitError):
                    self.git.checkout_default(
                        self.origin, "11", "hermes/task", self.head, SHA_B if actual == SHA_A else SHA_A)
                self.assertFalse(checked_out)

    def test_commit_detects_injected_untracked_drift_without_ref_or_index_change(self):
        (self.worktree / "src" / "modified.txt").write_text("candidate\n")
        index_before = (self.gitdir / "index").read_bytes()
        mode_before = (self.gitdir / "index").stat().st_mode & 0o777
        real = self.real_runner
        injected = False
        def runner(argv, **kwargs):
            nonlocal injected
            value = real(argv, **kwargs)
            command = list(argv[5:])
            if command[:2] == ["add", "-A"] and not injected:
                (self.worktree / "src" / "raced.txt").write_text("race\n")
                injected = True
            return value
        self.gateway.process_runner = runner
        with self.assertRaises(project_git.GitError):
            self.git.commit(self.origin, "11", ["src"], "candidate", self.head, "hermes/task")
        current = subprocess.run([*self.git_argv, "rev-parse", "HEAD"], check=True,
                                 text=True, capture_output=True).stdout.strip()
        self.assertEqual(current, self.head)
        self.assertEqual((self.gitdir / "index").read_bytes(), index_before)
        self.assertEqual((self.gitdir / "index").stat().st_mode & 0o777, mode_before)

    def test_truncated_path_observations_block_direct_commit_before_publication(self):
        (self.worktree / "src" / "modified.txt").write_text("candidate\n")
        real = self.real_runner
        token_calls = []
        transmitted = []

        def runner(argv, **kwargs):
            command = list(argv[5:])
            if command[0] == "diff" and "--name-only" in command:
                value = self.result("src/modified.txt\0")
                value["stdout_truncated"] = True
                value["stdout_omitted_bytes"] = 1
                return value
            if command[0] in {"ls-remote", "push"}:
                transmitted.append(command)
            return real(argv, **kwargs)

        self.gateway.process_runner = runner
        self.gateway.token_reader = lambda request: token_calls.append(request)
        with self.assertRaises(project_git.GitError):
            self.git.commit(self.origin, "11", ["src/modified.txt"],
                            "candidate", self.head, "hermes/task")
        self.assertFalse(token_calls)
        self.assertFalse(transmitted)

    def test_commit_detects_requested_tracked_change_after_candidate_stage(self):
        (self.worktree / "src" / "modified.txt").write_text("candidate\n")
        real = self.real_runner
        injected = False

        def runner(argv, **kwargs):
            nonlocal injected
            value = real(argv, **kwargs)
            if list(argv[5:])[:2] == ["add", "-A"] and not injected:
                (self.worktree / "src" / "modified.txt").write_text("changed again\n")
                injected = True
            return value

        self.gateway.process_runner = runner
        with self.assertRaises(project_git.GitError):
            self.git.commit(self.origin, "11", ["src"], "candidate",
                            self.head, "hermes/task")
        self.assertTrue(injected)
        self.assertEqual(subprocess.run(
            [*self.git_argv, "rev-parse", "HEAD"], check=True, text=True,
            capture_output=True).stdout.strip(), self.head)

    def test_commit_rejects_unrelated_staged_path_and_preserves_exact_shared_index(self):
        outside = self.worktree / "outside.txt"
        outside.write_text("staged elsewhere\n")
        subprocess.run([*self.git_argv, "add", "--", "outside.txt"], check=True,
                       capture_output=True)
        (self.worktree / "src" / "modified.txt").write_text("candidate\n")
        index_before = (self.gitdir / "index").read_bytes()
        mode_before = self.gitdir.joinpath("index").stat().st_mode & 0o777
        with self.assertRaises(project_git.GitError):
            self.git.commit(self.origin, "11", ["src"], "candidate",
                            self.head, "hermes/task")
        self.assertEqual((self.gitdir / "index").read_bytes(), index_before)
        self.assertEqual(self.gitdir.joinpath("index").stat().st_mode & 0o777, mode_before)
        self.assertEqual(subprocess.run(
            [*self.git_argv, "rev-parse", "HEAD"], check=True, text=True,
            capture_output=True).stdout.strip(), self.head)

    def test_existing_index_lock_rejects_without_clobber_or_ref_movement(self):
        (self.worktree / "src" / "modified.txt").write_text("candidate\n")
        lock = self.gitdir / "index.lock"
        lock.write_bytes(b"foreign lock")
        with self.assertRaises(project_git.GitError):
            self.git.commit(self.origin, "11", ["src"], "candidate",
                            self.head, "hermes/task")
        self.assertEqual(lock.read_bytes(), b"foreign lock")
        self.assertEqual(subprocess.run(
            [*self.git_argv, "rev-parse", "HEAD"], check=True, text=True,
            capture_output=True).stdout.strip(), self.head)

    def test_shared_index_replacement_rejects_without_clobber_or_ref_movement(self):
        (self.worktree / "src" / "modified.txt").write_text("candidate\n")
        real = self.real_runner
        replaced = False

        def runner(argv, **kwargs):
            nonlocal replaced
            value = real(argv, **kwargs)
            command = list(argv[5:])
            if command[:2] == ["diff", "--name-only"] and "--" in command and not replaced:
                replacement = self.gitdir / "foreign-index"
                replacement.write_bytes((self.gitdir / "index").read_bytes())
                replacement.replace(self.gitdir / "index")
                replaced = True
            return value

        self.gateway.process_runner = runner
        with self.assertRaises(project_git.GitError):
            self.git.commit(self.origin, "11", ["src"], "candidate",
                            self.head, "hermes/task")
        self.assertTrue(replaced)
        self.assertFalse((self.gitdir / "index.lock").exists())
        self.assertEqual(subprocess.run(
            [*self.git_argv, "rev-parse", "HEAD"], check=True, text=True,
            capture_output=True).stdout.strip(), self.head)

    def test_update_ref_uncertainty_after_actual_application_reports_committed(self):
        (self.worktree / "src" / "modified.txt").write_text("candidate\n")
        real = self.real_runner

        def runner(argv, **kwargs):
            command = list(argv[5:])
            if command[0] == "update-ref":
                applied = real(argv, **kwargs)
                self.assertEqual(applied["exit_code"], 0)
                return self.result(state="timed_out", exit_code=None, uncertain=True)
            return real(argv, **kwargs)

        self.gateway.process_runner = runner
        value = self.git.commit(self.origin, "11", ["src"], "candidate",
                                self.head, "hermes/task")
        self.assertEqual((value.effect, value.uncertain, value.local_state),
                         ("committed", False, "index_published"))
        self.assertNotEqual(value.commit, self.head)

    def test_update_ref_uncertainty_before_application_with_old_ref_reports_no_effect(self):
        (self.worktree / "src" / "modified.txt").write_text("candidate\n")
        real = self.real_runner

        def runner(argv, **kwargs):
            if list(argv[5:])[0] == "update-ref":
                return self.result(state="timed_out", exit_code=None, uncertain=True)
            return real(argv, **kwargs)

        self.gateway.process_runner = runner
        value = self.git.commit(self.origin, "11", ["src"], "candidate",
                                self.head, "hermes/task")
        self.assertEqual((value.effect, value.uncertain, value.local_state),
                         ("no_effect", False, "old"))
        self.assertEqual(subprocess.run(
            [*self.git_argv, "rev-parse", "HEAD"], check=True, text=True,
            capture_output=True).stdout.strip(), self.head)

    def test_update_ref_uncertainty_with_ambiguous_read_reports_unknown(self):
        (self.worktree / "src" / "modified.txt").write_text("candidate\n")
        real = self.real_runner

        def runner(argv, **kwargs):
            command = list(argv[5:])
            if command[0] == "update-ref" or (
                    command[:2] == ["rev-parse", "--verify"]
                    and command[-1] == "refs/heads/hermes/task"):
                return self.result(state="timed_out", exit_code=None, uncertain=True)
            return real(argv, **kwargs)

        self.gateway.process_runner = runner
        value = self.git.commit(self.origin, "11", ["src"], "candidate",
                                self.head, "hermes/task")
        self.assertEqual((value.effect, value.uncertain, value.local_state),
                         ("unknown", True, "unreadable"))

    def test_private_environment_cannot_override_sterile_routing(self):
        descriptor = self.git._descriptor(self.facts)
        anchor = self.git._open(descriptor)
        try:
            called = False
            def runner(*_args, **_kwargs):
                nonlocal called
                called = True
                return self.result()
            self.gateway.process_runner = runner
            value = self.git._process(descriptor, ["status"], anchor,
                                      env_extra={"HOME": "/tmp/attacker"})
            self.assertEqual(value["state"], "spawn_failed")
            self.assertFalse(called)
        finally:
            self.git._close_anchor(anchor)

    def test_process_rejects_both_transport_half_pairs_before_runner(self):
        descriptor = self.git._descriptor(self.facts)
        anchor = self.git._open(descriptor)
        calls = []
        self.gateway.process_runner = lambda *args, **kwargs: calls.append(args)
        try:
            with self.assertRaises(project_git.GitError):
                self.git._process(descriptor, ["status"], anchor, token="opaque")
            with self.assertRaises(project_git.GitError):
                self.git._process(
                    descriptor, ["status"], anchor,
                    url="https://github.com/owner/repo.git")
            self.assertFalse(calls)
        finally:
            self.git._close_anchor(anchor)

    def test_every_remote_public_method_validates_before_effect(self):
        with self.assertRaises(project_git.GitError):
            self.git.remote_ref(self.origin, "11", "-unsafe")
        with self.assertRaises(project_git.GitError):
            self.git.push(self.origin, "11", "hermes/task", "bad", self.head)
        with self.assertRaises(project_git.GitError):
            self.git.delete_remote_branch(self.origin, "11", "hermes/task", "bad")
        with self.assertRaises(project_git.GitError):
            self.git.checkout_default(self.origin, "11", "hermes/task", "bad", SHA_A)


if __name__ == "__main__":
    unittest.main()
