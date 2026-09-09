# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import os
import tempfile
import threading
import unittest
from types import SimpleNamespace
from unittest import mock

from _package import host_boundary as host


def descriptor(root: Path) -> host.RepositoryDescriptor:
    worktree = root / "worktree"
    worktree.mkdir(mode=0o700)
    git_parent = root / "state" / "git"
    git_parent.mkdir(mode=0o700, parents=True)
    gitdir = git_parent / "42"
    gitdir.mkdir(mode=0o700)
    return host.RepositoryDescriptor("42", worktree, gitdir, root, git_parent, "owner", "repo")


class HostBoundaryTests(unittest.TestCase):
    @staticmethod
    def _pem_stat(**changes):
        values = dict(st_dev=1, st_ino=2, st_mode=0o100640, st_uid=0,
                      st_gid=os.getegid(), st_nlink=1, st_size=3)
        values.update(changes)
        return SimpleNamespace(**values)

    def test_private_key_accepts_only_exact_root_group_descriptor_contract(self):
        broker = host.EnvironmentBroker({"GITHUB_APP_PRIVATE_KEY_PATH": "/secure/app.pem"})
        item = self._pem_stat()
        with mock.patch.object(os, "open", return_value=9) as opened, \
                mock.patch.object(os, "fstat", side_effect=[item, item]), \
                mock.patch.object(os, "read", side_effect=[b"pem", b""]), \
                mock.patch.object(os, "close"):
            self.assertEqual(broker._private_key(), b"pem")
        flags = opened.call_args.args[1]
        self.assertTrue(flags & os.O_NOFOLLOW)

    def test_private_key_rejects_owner_group_mode_link_type_and_size_matrix(self):
        broker = host.EnvironmentBroker({"GITHUB_APP_PRIVATE_KEY_PATH": "/secure/app.pem"})
        cases = {
            "service-owned-0600": self._pem_stat(st_uid=os.getuid(), st_mode=0o100600),
            "wrong-owner": self._pem_stat(st_uid=1),
            "wrong-group": self._pem_stat(st_gid=os.getegid() + 1),
            "wrong-mode": self._pem_stat(st_mode=0o100600),
            "hard-link": self._pem_stat(st_nlink=2),
            "directory": self._pem_stat(st_mode=0o040640),
            "empty": self._pem_stat(st_size=0),
            "oversize": self._pem_stat(st_size=1024 * 1024 + 1),
        }
        for label, item in cases.items():
            with self.subTest(label=label), mock.patch.object(os, "open", return_value=9), \
                    mock.patch.object(os, "fstat", return_value=item), \
                    mock.patch.object(os, "close"), self.assertRaises(host.BoundaryError):
                broker._private_key()

    def test_private_key_rejects_relative_symlink_open_failure_short_read_and_race(self):
        with self.assertRaises(host.BoundaryError):
            host.EnvironmentBroker({"GITHUB_APP_PRIVATE_KEY_PATH": "app.pem"})._private_key()
        broker = host.EnvironmentBroker({"GITHUB_APP_PRIVATE_KEY_PATH": "/secure/app.pem"})
        with mock.patch.object(os, "open", side_effect=OSError("nofollow")), \
                self.assertRaises(host.BoundaryError):
                broker._private_key()
        item = self._pem_stat()
        with mock.patch.object(os, "open", return_value=9), \
                mock.patch.object(os, "fstat", return_value=item), \
                mock.patch.object(os, "read", return_value=b""), \
                mock.patch.object(os, "close"), self.assertRaises(host.BoundaryError):
            broker._private_key()
        changed = self._pem_stat(st_ino=3)
        with mock.patch.object(os, "open", return_value=9), \
                mock.patch.object(os, "fstat", side_effect=[item, changed]), \
                mock.patch.object(os, "read", side_effect=[b"pem", b""]), \
                mock.patch.object(os, "close"), self.assertRaises(host.BoundaryError):
            broker._private_key()

    def test_private_key_rejects_trailing_growth_byte_read_from_descriptor(self):
        broker = host.EnvironmentBroker({"GITHUB_APP_PRIVATE_KEY_PATH": "/secure/app.pem"})
        item = self._pem_stat()
        with mock.patch.object(os, "open", return_value=9), \
                mock.patch.object(os, "fstat", side_effect=[item, item]), \
                mock.patch.object(os, "read", side_effect=[b"pem", b"x"]), \
                mock.patch.object(os, "close"), self.assertRaises(host.BoundaryError):
            broker._private_key()

    def test_external_metadata_is_anchored_and_both_fd_paths_are_used(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as tmp:
            root = Path(tmp)
            spec = descriptor(root)
            host.validate_external_git_metadata(spec)
            with host.DescriptorAnchor(spec) as anchor:
                self.assertEqual(len(anchor.pass_fds), 4)
                argv = host.sterile_git_argv(spec, ["status"], anchor=anchor)
                self.assertIn(anchor.worktree_fdpath, argv)
                self.assertTrue(any(anchor.gitdir_fdpath in item for item in argv))

    def test_sterile_environments_split_local_denial_from_https_transport(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as tmp:
            root = Path(tmp)
            root.chmod(0o700)
            local = host.sterile_local_git_environment(state_root=root)
            transport = host.sterile_git_environment(
                "opaque", state_root=root,
                repository_url="https://github.com/owner/repo.git")
            self.assertEqual(local["GIT_NO_REPLACE_OBJECTS"], "1")
            self.assertEqual(local["GIT_ALLOW_PROTOCOL"], "")
            self.assertNotIn("Authorization", repr(local))
            self.assertEqual(transport["GIT_ALLOW_PROTOCOL"], "https")
            self.assertIn("Authorization", repr(transport))
            for env in (local, transport):
                self.assertEqual(env["GIT_EDITOR"], "/usr/bin/false")
                self.assertEqual(env["GIT_SEQUENCE_EDITOR"], "/usr/bin/false")
                self.assertEqual(env["GIT_MERGE_AUTOEDIT"], "no")
                self.assertEqual(env["GIT_CONFIG_KEY_7"], "rerere.enabled")
                self.assertEqual(env["GIT_CONFIG_VALUE_7"], "false")

    def test_transport_environment_rejects_both_credential_url_half_pairs(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as tmp:
            root = Path(tmp)
            root.chmod(0o700)
            with self.assertRaises(host.BoundaryError):
                host.sterile_git_environment("opaque", state_root=root, repository_url=None)
            with self.assertRaises(host.BoundaryError):
                host.sterile_git_environment(
                    None, state_root=root,
                    repository_url="https://github.com/owner/repo.git")

    def test_gitdir_tree_rejects_hardlinked_and_writable_regular_files(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as tmp:
            spec = descriptor(Path(tmp))
            logs = spec.trusted_gitdir / "logs"
            logs.mkdir()
            entry = logs / "HEAD"
            entry.write_text("log\n")
            external = Path(tmp) / "external"
            os.link(entry, external)
            with self.assertRaises(host.BoundaryError):
                with host.DescriptorAnchor(spec):
                    pass
            external.unlink()
            entry.chmod(0o620)
            with self.assertRaises(host.BoundaryError):
                with host.DescriptorAnchor(spec):
                    pass

    def test_grafts_and_replace_refs_are_rejected(self):
        for relative in (Path("info/grafts"), Path("refs/replace/old")):
            with self.subTest(relative=relative), tempfile.TemporaryDirectory(
                    dir="/private/tmp") as tmp:
                spec = descriptor(Path(tmp))
                target = spec.trusted_gitdir / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text("unsafe\n")
                with self.assertRaises(host.BoundaryError):
                    with host.DescriptorAnchor(spec):
                        pass

    def test_embedded_git_mode_is_rejected(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as tmp:
            root = Path(tmp)
            spec = descriptor(root)
            (spec.worktree / ".git").mkdir(mode=0o700)
            with self.assertRaises(host.BoundaryError):
                host.validate_descriptor_path(spec)

    def test_external_metadata_inside_worktree_is_rejected(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as tmp:
            root = Path(tmp)
            worktree = root / "worktree"
            worktree.mkdir(mode=0o700)
            gitdir = worktree / "external-git"
            gitdir.mkdir(mode=0o700)
            spec = host.RepositoryDescriptor("42", worktree, gitdir, root, worktree,
                                              "owner", "repo")
            with self.assertRaises(host.BoundaryError):
                host.validate_descriptor_path(spec)

    def test_worktree_inside_external_metadata_is_rejected(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as tmp:
            root = Path(tmp)
            gitdir = root / "external-git"
            gitdir.mkdir(mode=0o700)
            worktree = gitdir / "worktree"
            worktree.mkdir(mode=0o700)
            spec = host.RepositoryDescriptor("42", worktree, gitdir, gitdir, root,
                                              "owner", "repo")
            with self.assertRaises(host.BoundaryError):
                host.validate_descriptor_path(spec)

    def test_worktree_parent_swap_is_detected(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as tmp:
            root = Path(tmp)
            spec = descriptor(root)
            with host.DescriptorAnchor(spec) as anchor:
                old = root.with_name(root.name + "-old")
                replacement = root.with_name(root.name + "-replacement")
                root.rename(old)
                replacement.mkdir(mode=0o700)
                replacement.rename(root)
                with self.assertRaises(host.BoundaryError):
                    anchor.verify()
                root.rename(root.with_name(root.name + "-bad"))
                old.rename(root)

    def test_gitdir_parent_swap_is_detected(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as tmp:
            root = Path(tmp)
            spec = descriptor(root)
            with host.DescriptorAnchor(spec) as anchor:
                old = spec.gitdir_parent.with_name("git-old")
                replacement = spec.gitdir_parent.with_name("git-replacement")
                spec.gitdir_parent.rename(old)
                replacement.mkdir(mode=0o700)
                replacement.rename(spec.gitdir_parent)
                with self.assertRaises(host.BoundaryError):
                    anchor.verify()
                spec.gitdir_parent.rename(spec.gitdir_parent.with_name("git-bad"))
                old.rename(spec.gitdir_parent)

    def test_sterile_argv_requires_anchor(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as tmp:
            spec = descriptor(Path(tmp))
            with self.assertRaises(host.BoundaryError):
                host.sterile_git_argv(spec, ["status"])

    def test_named_token_profiles_reject_arbitrary_permissions_and_missing_id(self):
        with self.assertRaises(host.BoundaryError):
            host.narrow_token_request("42", {"contents": "write"})
        with self.assertRaises(host.BoundaryError):
            host.narrow_token_request("42", "arbitrary")
        with tempfile.TemporaryDirectory(dir="/private/tmp") as tmp:
            root = Path(tmp)
            spec = descriptor(root)
            missing = host.RepositoryDescriptor("", spec.worktree, spec.trusted_gitdir,
                                                spec.worktree_parent, spec.gitdir_parent, "owner", "repo")
            with self.assertRaises(host.BoundaryError):
                host.validate_token_response({}, missing, "observe")

    def test_token_expiry_and_wrong_repository_are_rejected(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as tmp:
            spec = descriptor(Path(tmp))
            response = {
                **host.narrow_token_request("42", "github_collaboration"),
                "token": "opaque",
                "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
                "repository_selection": "selected",
                "repositories": [{"id": 42, "name": "repo", "full_name": "owner/repo"}],
            }
            self.assertEqual(host.validate_token_response(response, spec, "github_collaboration"), "opaque")
            response["expires_at"] = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
            with self.assertRaises(host.BoundaryError):
                host.validate_token_response(response, spec, "github_collaboration")
            response["expires_at"] = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()
            response["repositories"] = [{"id": 99, "name": "repo", "full_name": "owner/repo"}]
            with self.assertRaises(host.BoundaryError):
                host.validate_token_response(response, spec, "github_collaboration")

    def test_pathless_repository_token_response_exact_profiles_and_rejections(self):
        def response(profile):
            return {**host.narrow_token_request("42", profile), "token": "opaque",
                "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
                "repository_selection": "selected",
                "repositories": [{"id": 42, "name": "repo", "full_name": "owner/repo"}]}

        for profile in ("risk_report", "github_collaboration"):
            with self.subTest(profile=profile):
                value = response(profile)
                self.assertEqual(host.validate_repository_token_response(
                    value, "42", "owner", "repo", profile), "opaque")
                self.assertFalse(any("path" in key or "workspace" in key for key in value))

        failures = []
        expired = response("risk_report")
        expired["expires_at"] = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
        failures.append(("expired", expired, "risk_report"))
        wrong_permissions = response("risk_report")
        wrong_permissions["permissions"] = {"metadata": "read"}
        failures.append(("wrong permissions", wrong_permissions, "risk_report"))
        broad_permissions = response("risk_report")
        broad_permissions["permissions"]["contents"] = "write"
        failures.append(("broad permissions", broad_permissions, "risk_report"))
        multiple = response("github_collaboration")
        multiple["repositories"].append(dict(multiple["repositories"][0]))
        failures.append(("multiple repositories", multiple, "github_collaboration"))
        for field, value in (("id", 99), ("name", "other"), ("full_name", "owner/other")):
            wrong = response("github_collaboration")
            wrong["repositories"][0][field] = value
            failures.append((f"wrong {field}", wrong, "github_collaboration"))
        for label, value, profile in failures:
            with self.subTest(label=label), self.assertRaises(host.BoundaryError):
                host.validate_repository_token_response(value, "42", "owner", "repo", profile)

    def test_literal_credentials_are_redacted_from_both_process_streams(self):
        secret = "ghs_literal_u1_credential"
        rendered = host.redact_process(
            {"stdout": f"stdout before {secret} stdout after",
             "stderr": f"stderr before {secret} stderr after"},
            (secret,),
        )
        self.assertNotIn(secret, rendered["stdout"])
        self.assertNotIn(secret, rendered["stderr"])
        self.assertEqual(rendered["stdout"].count("[REDACTED]"), 1)
        self.assertEqual(rendered["stderr"].count("[REDACTED]"), 1)

    def test_lock_symlink_is_rejected_and_ordered_locks_work(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as tmp:
            root = Path(tmp)
            root.chmod(0o700)
            lock_root = root / "locks"
            lock_root.mkdir(mode=0o700)
            lock = lock_root / "repository-42.lock"
            target = root / "target"
            target.write_text("")
            lock.symlink_to(target)
            with self.assertRaises(host.BoundaryError):
                with host.repository_lock("42", state_root=root):
                    pass
            lock.unlink()
            with host.ordered_locks("W1", "C1", "42", state_root=root):
                pass
            self.assertEqual(lock.stat().st_mode & 0o777, 0o600)

    def test_concurrent_first_locks_share_secure_directory_creation(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as tmp:
            root = Path(tmp)
            root.chmod(0o700)
            barrier = threading.Barrier(2)
            outcomes = []

            def acquire(channel_id):
                barrier.wait()
                with host.channel_lock("W1", channel_id, state_root=root):
                    outcomes.append(channel_id)

            threads = [threading.Thread(target=acquire, args=(channel,)) for channel in ("C1", "C2")]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(2)
            self.assertEqual(sorted(outcomes), ["C1", "C2"])


if __name__ == "__main__":
    unittest.main()
