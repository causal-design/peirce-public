# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

import base64
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from _package import project, registry


class ProfileIsolationTests(unittest.TestCase):
    def fixture(self, *, profile=True):
        temporary = tempfile.TemporaryDirectory(dir="/private/tmp")
        root = Path(temporary.name)
        root.chmod(0o700)
        workspace, state, live, database = (
            root / "workspace", root / "state", root / "live", root / "database")
        for path in (workspace, state, database):
            path.mkdir(mode=0o700)
        if profile:
            live.mkdir(mode=0o700)
        store = registry.ProjectRegistry(database / "projects.db", workspace_root=workspace,
                                         state_root=state)
        fixed = project.build_peirce_isolated_projects(
            store, "W1", "C-source", "101", "C-admin", "202", "303")
        gateway = project.ProjectGateway(
            store, lambda candidate: project.ProviderObservation(
                candidate.repository_id, "303", candidate.owner, candidate.name,
                f"https://github.com/{candidate.owner}/{candidate.name}.git", "main"),
            fixed, protected_profile_root=live,
        )
        return temporary, store, live, fixed, gateway

    def test_fixed_routes_are_isolated_and_do_not_create_database(self):
        temporary, store, _, (source, admin), gateway = self.fixture()
        with temporary:
            self.assertEqual(source.repository.worktree, str(store.workspace_root / "peirce"))
            self.assertEqual(source.repository.trusted_gitdir,
                             str(store.state_root / "reserved" / "peirce.git"))
            self.assertEqual(admin.repository.worktree,
                             str(store.workspace_root / "peirce-admin"))
            self.assertEqual(admin.repository.trusted_gitdir,
                             str(store.state_root / "reserved" / "peirce-admin.git"))
            self.assertTrue(gateway.show(source.origin).fixed)
            self.assertTrue(gateway.show(admin.origin).fixed)
            self.assertFalse(store.db_path.exists())
            with self.assertRaises(project.FixedProjectError):
                gateway.set(project.TrustedOrigin("W1", "ordinary"),
                            project.CanonicalCandidate("peirce-example", "peirce", "101"))
            self.assertFalse(store.db_path.exists())

    def test_only_exact_production_facts_are_workspace_capable(self):
        temporary, _, _, (source, admin), gateway = self.fixture()
        with temporary:
            self.assertEqual(gateway.inspect_workspace(source.repository).state, "absent")
            self.assertEqual(gateway.inspect_workspace(admin.repository).state, "absent")
            malformed = replace(source.repository, worktree=admin.repository.worktree)
            with self.assertRaises(project.FixedProjectError):
                gateway.inspect_workspace(malformed)

    def test_prepare_source_admin_and_candidate_use_only_isolated_fixed_facts(self):
        temporary, store, live, (source, admin), _ = self.fixture()
        with temporary:
            memories = live / "memories"
            memories.mkdir(mode=0o700)
            memory = memories / "MEMORY.md"
            memory.write_bytes(b"live profile remains immutable\n")
            memory.chmod(0o600)

            candidate_observation = project.ProviderObservation(
                "404", "303", "peirce-example", "candidate-b",
                "https://github.com/peirce-example/candidate-b.git", "main")
            observations = {
                ("peirce-example", "peirce"): project.ProviderObservation(
                    "101", "303", "peirce-example", "peirce",
                    "https://github.com/peirce-example/peirce.git", "main"),
                ("peirce-example", "peirce-admin"): project.ProviderObservation(
                    "202", "303", "peirce-example", "peirce-admin",
                    "https://github.com/peirce-example/peirce-admin.git", "main"),
                ("peirce-example", "candidate-b"): candidate_observation,
            }
            process_calls = []
            token_calls = []

            def access(locator):
                return observations[(locator.owner, locator.name)]

            facts_by_worktree = {}

            def runner(argv, **kwargs):
                process_calls.append((list(argv), dict(kwargs.get("env", {}))))
                if "init" in argv:
                    self.assertIn("--bare", argv)
                    self.assertFalse(any(item.startswith("--work-tree=") for item in argv))
                    return project.cli_runner.run_argv(argv, **kwargs)
                worktree = next(item.split("=", 1)[1] for item in argv
                                if item.startswith("--work-tree="))
                facts = facts_by_worktree[worktree]
                command = list(argv[5:])
                if command[:2] == ["config", "--local"] and "--null" not in command:
                    return project.cli_runner.run_argv(argv, **kwargs)
                stdout = ""
                if command[:4] == ["config", "--local", "--null", "--list"]:
                    stdout = "\0".join((
                        "core.repositoryformatversion\n0",
                        "core.filemode\ntrue",
                        "core.bare\ntrue",
                        "core.logallrefupdates\ntrue",
                        "core.hookspath\n/dev/null",
                        "init.defaultbranch\nmain",
                        "user.name\nPeirce",
                        "user.email\npeirce@example.invalid",
                        f"remote.origin.url\n{facts.url}",
                        "remote.origin.fetch\n+refs/heads/*:refs/remotes/origin/*",
                        "branch.main.remote\norigin",
                        "branch.main.merge\nrefs/heads/main",
                        "",
                    ))
                elif command[:3] == ["symbolic-ref", "--quiet", "HEAD"]:
                    stdout = "refs/heads/main\n"
                elif command[:4] == ["symbolic-ref", "--quiet", "--short", "HEAD"]:
                    stdout = "main\n"
                elif command[:3] in (["rev-parse", "--verify", "HEAD"],
                                     ["rev-parse", "--verify", "HEAD^{commit}"]):
                    stdout = "a" * 40 + "\n"
                elif command[:3] == ["rev-parse", "--abbrev-ref", "--symbolic-full-name"]:
                    stdout = "origin/main\n"
                elif command[:3] == ["rev-list", "--left-right", "--count"]:
                    stdout = "0 0\n"
                return {"state": "exited", "exit_code": 0, "stdout": stdout,
                        "stderr": "", "uncertain": False}

            def token(request):
                token_calls.append(dict(request))
                facts = next(item for item in facts_by_worktree.values()
                             if item.repository_id == str(request["repository_ids"][0]))
                return {
                    "token": f"token-{facts.repository_id}",
                    "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat(),
                    "permissions": request["permissions"],
                    "repository_selection": "selected",
                    "repositories": [{"id": int(facts.repository_id), "name": facts.name,
                                      "full_name": f"{facts.owner}/{facts.name}"}],
                }

            gateway = project.ProjectGateway(
                store, lambda value: observations[(value.owner, value.name)], (source, admin),
                protected_profile_root=live, token_reader=token,
                process_runner=runner)
            candidate = gateway._transient_facts(candidate_observation)
            for facts in (source.repository, admin.repository, candidate):
                descriptor = gateway._workspace_descriptor(facts)
                facts_by_worktree[str(descriptor.worktree)] = facts
                self.assertEqual((descriptor.owner, descriptor.name), (facts.owner, facts.name))

            snapshot_before = gateway.learning_snapshot(source.origin)
            for facts in (source.repository, admin.repository, candidate):
                initialized = gateway.initialize_workspace(facts)
                self.assertEqual(initialized.effect, "initialized")
                effect = gateway.fetch_workspace(facts)
                self.assertEqual(effect.effect, "fetched")
                self.assertEqual(effect.inspection.worktree, facts.worktree)
                self.assertEqual(effect.inspection.trusted_gitdir, facts.trusted_gitdir)
            self.assertEqual(Path(source.repository.worktree), store.workspace_root / "peirce")
            self.assertEqual(Path(admin.repository.worktree), store.workspace_root / "peirce-admin")
            self.assertEqual(Path(candidate.worktree), store.workspace_root / "404")
            self.assertEqual(gateway.learning_snapshot(source.origin), snapshot_before)
            self.assertEqual(memory.read_bytes(), b"live profile remains immutable\n")
            self.assertEqual({str(call["repository_ids"][0]) for call in token_calls},
                             {"101", "202", "404"})
            self.assertNotIn(str(live), repr(process_calls))

            malformed = replace(source.repository, worktree=candidate.worktree)
            before_calls = len(process_calls)
            with self.assertRaises(project.FixedProjectError):
                gateway.initialize_workspace(malformed)
            self.assertEqual(len(process_calls), before_calls)

    def test_profile_overlap_is_rejected(self):
        temporary, store, live, fixed, _ = self.fixture()
        with temporary:
            source, admin = fixed
            overlapping = replace(source, repository=replace(source.repository,
                                  worktree=str(live / "source")))
            with self.assertRaises((project.FixedProjectError, project.WorkspaceError)):
                project.ProjectGateway(store, lambda value: None, (overlapping, admin),
                                       protected_profile_root=live)

    def test_detached_source_inspection_preserves_live_profile(self):
        temporary, _, live, (source, _), gateway = self.fixture()
        with temporary:
            sentinel = live / "profile-sentinel"
            sentinel.write_bytes(b"live profile unchanged\n")
            sentinel.chmod(0o600)
            gateway.process_runner = project.cli_runner.run_argv
            self.assertEqual(gateway.initialize_workspace(source.repository).effect, "initialized")
            gitdir = Path(source.repository.trusted_gitdir)
            worktree = Path(source.repository.worktree)
            git = ["/usr/bin/git", f"--git-dir={gitdir}", f"--work-tree={worktree}"]
            tracked = worktree / "tracked.txt"
            tracked.write_text("tracked\n", encoding="utf-8")
            subprocess.run([*git, "add", "--", "tracked.txt"], check=True,
                           capture_output=True)
            subprocess.run([*git, "commit", "-m", "tracked"], check=True,
                           capture_output=True)
            sha = subprocess.run([*git, "rev-parse", "HEAD"], check=True, text=True,
                                 capture_output=True).stdout.strip()
            subprocess.run([*git, "checkout", sha], check=True, capture_output=True)

            inspected = gateway.inspect_workspace(source.repository)
            self.assertEqual((inspected.state, inspected.branch, inspected.head),
                             ("present", None, sha))
            self.assertEqual(sentinel.read_bytes(), b"live profile unchanged\n")

    def test_snapshot_reads_only_exact_allowlist_bytes(self):
        temporary, _, live, (source, _), gateway = self.fixture()
        with temporary:
            memories = live / "memories"
            skill = live / "skills" / "learned" / "assets"
            memories.mkdir(mode=0o700)
            skill.mkdir(parents=True, mode=0o700)
            for directory in (live / "skills", live / "skills" / "learned", skill):
                directory.chmod(0o700)
            values = {
                memories / "MEMORY.md": b"memory\n",
                memories / "USER.md": b"user\x00bytes",
                live / "skills" / "learned" / "SKILL.md": b"skill source\n",
            }
            excluded_asset = skill / "blob.bin"
            excluded_asset.write_bytes(bytes(range(256)))
            excluded_asset.chmod(0o600)
            for path, content in values.items():
                path.write_bytes(content)
                path.chmod(0o600)
            (live / "credentials.json").write_bytes(b"secret")
            (live / "credentials.json").chmod(0o600)
            for excluded in ("config", "plugins", "credentials", "locks", "caches", "telemetry"):
                directory = live / excluded
                directory.mkdir(mode=0o700)
                hidden = directory / "hidden"
                hidden.write_bytes(excluded.encode())
                hidden.chmod(0o600)
            bundled = live.parent / "bundled-hermes-skills"
            bundled.mkdir(mode=0o700)
            (bundled / "SKILL.md").write_bytes(b"bundled, not learned")

            snapshot = gateway.learning_snapshot(source.origin)
            self.assertEqual(snapshot.state, "supported")
            self.assertEqual(snapshot.evidence_source, "live_profile")
            self.assertEqual(snapshot.authorized_source_repository_id, "101")
            observed = {item.relative_path: item for item in snapshot.entries}
            expected = {str(path.relative_to(live)): content for path, content in values.items()}
            self.assertEqual(set(observed), set(expected))
            for relative, content in expected.items():
                self.assertEqual(base64.b64decode(observed[relative].content_base64), content)
                self.assertEqual(observed[relative].sha256, hashlib.sha256(content).hexdigest())
                self.assertEqual(observed[relative].mode, 0o600)
            self.assertEqual((live / "credentials.json").read_bytes(), b"secret")
            self.assertNotIn("skills/learned/assets/blob.bin", observed)
            self.assertNotIn("bundled", b"".join(
                base64.b64decode(item.content_base64) for item in snapshot.entries).decode(
                    "latin1"))
            self.assertEqual((live / "locks" / "hidden").read_bytes(), b"locks")

    def test_overlapping_source_and_live_skill_versions_remain_independently_visible(self):
        temporary, _, live, (source, _), gateway = self.fixture()
        with temporary:
            source_skill = Path(source.repository.worktree) / "skills" / "learned" / "SKILL.md"
            live_skill = live / "skills" / "learned" / "SKILL.md"
            source_skill.parent.mkdir(parents=True, mode=0o700)
            live_skill.parent.mkdir(parents=True, mode=0o700)
            for directory in (live / "skills", live_skill.parent):
                directory.chmod(0o700)
            source_bytes = b"reviewed source version\n"
            live_bytes = b"new runtime learning\n"
            source_skill.write_bytes(source_bytes)
            live_skill.write_bytes(live_bytes)
            live_skill.chmod(0o600)

            snapshot = gateway.learning_snapshot(source.origin)

            self.assertEqual(snapshot.state, "supported")
            self.assertEqual(source_skill.read_bytes(), source_bytes)
            self.assertEqual(live_skill.read_bytes(), live_bytes)
            self.assertEqual(len(snapshot.entries), 1)
            observed = snapshot.entries[0]
            self.assertEqual(observed.relative_path, "skills/learned/SKILL.md")
            self.assertEqual(base64.b64decode(observed.content_base64), live_bytes)
            self.assertEqual(observed.sha256, hashlib.sha256(live_bytes).hexdigest())
            self.assertNotEqual(observed.sha256, hashlib.sha256(source_bytes).hexdigest())

    def test_snapshot_rejects_hardlink_without_reading_protected_bytes(self):
        temporary, _, live, (source, _), gateway = self.fixture()
        with temporary:
            (live / "skills").mkdir(mode=0o700)
            credential = live / "credentials.json"
            credential.write_bytes(b"never expose")
            credential.chmod(0o600)
            skill = live / "skills" / "learned"
            skill.mkdir(mode=0o700)
            os.link(credential, skill / "SKILL.md")
            result = gateway.learning_snapshot(source.origin)
            self.assertEqual((result.state, result.uncertain), ("error", True))
            self.assertEqual(result.entries, ())
            self.assertEqual(credential.read_bytes(), b"never expose")

    def test_snapshot_ignores_unrelated_directories_nested_under_skills(self):
        for name in ("runtime-config", "cache", "telemetry", "auth", "password",
                     "session", "api-key", "cookies", "client-keystore"):
            with self.subTest(name=name):
                temporary, _, live, (source, _), gateway = self.fixture()
                with temporary:
                    nested = live / "skills" / "learned" / "assets"
                    nested.mkdir(parents=True, mode=0o700)
                    for directory in (live / "skills", live / "skills" / "learned", nested):
                        directory.chmod(0o700)
                    target = nested / name
                    target.mkdir(mode=0o700)
                    result = gateway.learning_snapshot(source.origin)
                    self.assertEqual((result.state, result.uncertain), ("empty", False))
                    self.assertEqual(result.entries, ())

    def test_snapshot_ignores_non_definition_files_regardless_of_plausible_secret_name(self):
        temporary, _, live, (source, _), gateway = self.fixture()
        with temporary:
            skill = live / "skills" / "learned"
            skill.mkdir(parents=True, mode=0o700)
            for directory in (live / "skills", skill):
                directory.chmod(0o700)
            definition = skill / "SKILL.md"
            definition.write_bytes(b"reviewed definition")
            definition.chmod(0o600)
            for name in ("password.txt", "api-key.json", "auth.json", "session.sqlite",
                         "cookies.json", "client.keystore", "private.ppk"):
                value = skill / name
                value.write_bytes(b"never export")
                value.chmod(0o600)
            snapshot = gateway.learning_snapshot(source.origin)
            self.assertEqual(snapshot.state, "supported")
            self.assertEqual([entry.relative_path for entry in snapshot.entries],
                             ["skills/learned/SKILL.md"])

    def test_snapshot_ignores_excluded_entries_and_bounds_skill_directories(self):
        temporary, _, live, (source, _), gateway = self.fixture()
        with temporary:
            for index in range(project.MAX_LEARNING_ENTRIES + 1):
                path = live / f"excluded-{index}"
                path.write_bytes(b"")
                path.chmod(0o600)
            self.assertEqual(gateway.learning_snapshot(source.origin).state, "empty")

        temporary, _, live, (source, _), gateway = self.fixture()
        with temporary:
            skills = live / "skills"
            skills.mkdir(mode=0o700)
            for index in range(project.MAX_LEARNING_DIRECTORIES):
                (skills / f"empty-{index}").mkdir(mode=0o700)
            self.assertEqual(gateway.learning_snapshot(source.origin).state, "error")

        temporary, _, live, (source, _), gateway = self.fixture()
        with temporary:
            skill = live / "skills" / "learned"
            skill.mkdir(parents=True, mode=0o700)
            for directory in (live / "skills", skill):
                directory.chmod(0o700)
            for index in range(project.MAX_LEARNING_ENTRIES + 1):
                path = skill / f"excluded-{index}"
                path.write_bytes(b"")
                path.chmod(0o600)
            self.assertEqual(gateway.learning_snapshot(source.origin).state, "empty")

    def test_snapshot_states_and_unsafe_entries(self):
        temporary, _, live, (source, admin), gateway = self.fixture()
        with temporary:
            self.assertEqual(gateway.learning_snapshot(source.origin).state, "empty")
            with self.assertRaises(project.FixedProjectError):
                gateway.learning_snapshot(admin.origin)
            (live / "skills").symlink_to(live / "memories", target_is_directory=True)
            result = gateway.learning_snapshot(source.origin)
            self.assertEqual((result.state, result.uncertain), ("error", True))

        temporary, store, live, fixed, _ = self.fixture(profile=False)
        with temporary:
            absent = project.ProjectGateway(store, lambda value: None, fixed,
                                            protected_profile_root=live)
            self.assertEqual(absent.learning_snapshot(fixed[0].origin).state, "absent")
            unsupported = project.ProjectGateway(store, lambda value: None, fixed)
            self.assertEqual(unsupported.learning_snapshot(fixed[0].origin).state,
                             "unsupported")

    def test_snapshot_fails_closed_for_unsafe_first_level_skill_directory(self):
        temporary, _, live, (source, _), gateway = self.fixture()
        with temporary:
            skills = live / "skills"
            skills.mkdir(mode=0o700)
            target = live / "outside"
            target.mkdir(mode=0o700)
            (skills / "learned").symlink_to(target, target_is_directory=True)
            result = gateway.learning_snapshot(source.origin)
            self.assertEqual((result.state, result.uncertain), ("error", True))

    def test_snapshot_rejects_file_change_during_read(self):
        temporary, _, live, (source, _), gateway = self.fixture()
        with temporary:
            skill = live / "skills" / "learned"
            skill.mkdir(parents=True, mode=0o700)
            for directory in (live / "skills", skill):
                directory.chmod(0o700)
            definition = skill / "SKILL.md"
            definition.write_bytes(b"original")
            definition.chmod(0o600)
            real_read = project.os.read
            reads = 0

            def raced_read(fd, size):
                nonlocal reads
                value = real_read(fd, size)
                reads += 1
                if reads == 1:
                    definition.write_bytes(b"changed!")
                return value

            with mock.patch.object(project.os, "read", side_effect=raced_read):
                result = gateway.learning_snapshot(source.origin)
            self.assertEqual((result.state, result.uncertain), ("error", True))
            self.assertEqual(result.entries, ())

    def test_snapshot_revalidates_earlier_files_after_complete_traversal(self):
        temporary, _, live, (source, _), gateway = self.fixture()
        with temporary:
            memories = live / "memories"
            memories.mkdir(mode=0o700)
            memory = memories / "MEMORY.md"
            user = memories / "USER.md"
            for path, content in ((memory, b"old"), (user, b"user")):
                path.write_bytes(content)
                path.chmod(0o600)
            real_read = project.os.read
            reads = 0

            def raced_read(fd, size):
                nonlocal reads
                value = real_read(fd, size)
                reads += 1
                if reads == 3:
                    memory.write_bytes(b"new")
                return value

            with mock.patch.object(project.os, "read", side_effect=raced_read):
                result = gateway.learning_snapshot(source.origin)
            self.assertEqual((result.state, result.uncertain), ("error", True))
            self.assertEqual(result.entries, ())


if __name__ == "__main__":
    unittest.main()
