# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

from pathlib import Path
from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import base64
import os
import subprocess
import tempfile
import threading
import time
import unittest
from types import SimpleNamespace

from _package import project, project_git, registry


def candidate(repository_id: str, owner: str = "owner", name: str = "repo") -> project.CanonicalCandidate:
    return project.CanonicalCandidate(owner, name, repository_id)


def observation(repository_id: str, owner: str = "owner", name: str = "repo", **changes):
    values = dict(repository_id=repository_id, installation_id="7", owner=owner, name=name,
                  url=f"https://github.com/{owner}/{name}.git", default_branch="main")
    values.update(changes)
    return project.ProviderObservation(**values)


def fixed_facts(repository_id: str, owner: str = "owner", name: str = "repo"):
    observed = observation(repository_id, owner, name)
    return registry.RepositoryFacts(
        repository_id, f"fixed-{repository_id}", observed.installation_id, owner, name,
        f"/srv/hermes/project-state/fixed/{repository_id}", observed.url, observed.default_branch,
        f"/srv/hermes/project-state/fixed-git/{repository_id}",
    )


def set_association(db, workspace_id, channel_id, observed, expected_repository_id=None):
    return db._set_association(
        workspace_id, channel_id, observed.repository_id, observed.installation_id,
        observed.owner, observed.name, observed.url, observed.default_branch,
        expected_repository_id,
    )


def successful_git_result(argv, *, config=None):
    command = " ".join(argv)
    config = config or (
        "core.repositoryformatversion\n0\0core.filemode\ntrue\0core.bare\ntrue\0"
        "core.logallrefupdates\ntrue\0core.hookspath\n/dev/null\0"
        "remote.origin.url\nhttps://github.com/owner/repo.git\0"
        "remote.origin.fetch\n+refs/heads/*:refs/remotes/origin/*\0"
        "init.defaultbranch\nmain\0user.name\nPeirce\0"
        "user.email\npeirce@example.invalid\0"
        "branch.main.remote\norigin\0branch.main.merge\nrefs/heads/main\0"
    )
    stdout = (config if "--null --list" in command
              else "refs/heads/main\n" if "symbolic-ref --quiet HEAD" in command
              else "main\n" if "symbolic-ref" in command
              else "a" * 40 + "\n" if "--verify HEAD" in command
              else "origin/main\n" if "@{upstream}" in command and "rev-list" not in command
              else "2 3\n" if "rev-list" in command else " M changed\n")
    if "for-each-ref --format=%(refname)" in command:
        stdout = ""
    return {"state": "exited", "exit_code": 0, "stdout": stdout,
            "stderr": "", "uncertain": False}


def create_workspace_pair(facts, *, worktree=True, gitdir=True, initialized=True):
    for child, present in ((Path(facts.worktree), worktree),
                           (Path(facts.trusted_gitdir), gitdir)):
        child.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        child.parent.chmod(0o700)
        if present:
            child.mkdir(mode=0o700)
    Path(facts.trusted_gitdir).parent.parent.chmod(0o700)
    if gitdir and initialized:
        root = Path(facts.trusted_gitdir)
        (root / "config").write_text("[core]\n\tbare = true\n", encoding="utf-8")
        (root / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
        (root / "objects").mkdir()
        (root / "refs").mkdir()


class ProjectGatewayTests(unittest.TestCase):
    def make_gateway(self, fixed=()):
        tmp = tempfile.TemporaryDirectory(dir="/private/tmp")
        root = Path(tmp.name)
        root.chmod(0o700)
        db = registry.ProjectRegistry(
            root / "projects.db", workspace_root=root / "workspaces", state_root=root)
        seen = []

        def observe(value):
            seen.append(value)
            return observation(value.repository_id, value.owner, value.name)

        return tmp, root, db, project.ProjectGateway(db, observe, fixed, state_root=root), seen

    def make_u3_gateway(self, *, slack_failure=False, access_reader=None, provider_reader=None,
                        token_reader=None, process_runner=None, bookmark_transport=None, fixed=()):
        tmp = tempfile.TemporaryDirectory(dir="/private/tmp")
        root = Path(tmp.name)
        root.chmod(0o700)
        db = registry.ProjectRegistry(root / "projects.db", workspace_root=root / "worktrees",
                                     state_root=root / "state")
        calls, bookmarks = [], []

        def access(locator):
            calls.append(("access", locator))
            if access_reader is not None:
                return access_reader(locator)
            return observation("11", locator.owner, locator.name)

        def token(request):
            calls.append(("token", dict(request)))
            if token_reader is not None:
                return token_reader(request)
            repository_id = request["repository_ids"][0]
            return {
                **request, "token": "u3-secret-token",
                "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
                "repository_selection": "selected",
                "repositories": [{"id": repository_id, "name": "repo",
                                  "full_name": "owner/repo"}],
            }

        def runner(argv, **kwargs):
            calls.append((tuple(argv), kwargs))
            if process_runner is not None:
                return process_runner(argv, **kwargs)
            command = list(argv[5:])
            if ("init" in argv or command and (
                            command[:2] == ["config", "--local"] and
                            "--null" not in command)):
                return project.cli_runner.run_argv(argv, **kwargs)
            return successful_git_result(argv)

        def slack(operation, payload):
            calls.append((operation, dict(payload)))
            if bookmark_transport is not None:
                return bookmark_transport(operation, payload)
            if slack_failure:
                raise OSError("offline")
            if operation == "list":
                return {"ok": True, "bookmarks": list(bookmarks)}
            if operation == "add":
                item = {"id": f"B{len(bookmarks) + 1}", "title": payload["title"],
                        "type": "link", "link": payload["link"],
                        "channel_id": payload["channel_id"], "date_created": 123}
                bookmarks.append(item)
                return {"ok": True, "bookmark": item}
            for index, item in enumerate(bookmarks):
                if item["id"] == payload["bookmark_id"]:
                    bookmarks.pop(index)
                    return {"ok": True, "deleted": True, "bookmark_id": item["id"]}
            return {"ok": True, "deleted": False, "bookmark_id": payload["bookmark_id"]}

        def provider(value):
            calls.append(("provider", value))
            if provider_reader is not None:
                return provider_reader(value)
            return observation(value.repository_id, value.owner, value.name)

        gateway = project.ProjectGateway(
            db, provider, fixed, state_root=root / "state", token_reader=token,
            process_runner=runner,
        )

        def candidate_access(locator):
            observed = project._observation(access(locator))
            if (observed.owner, observed.name) != (locator.owner, locator.name):
                raise project.ObservationMismatch("provider observation does not match request")
            facts = gateway._transient_facts(observed)
            registry.ProjectRegistry.validate_repository_facts(facts)
            gateway._workspace_descriptor(facts)
            return SimpleNamespace(
                observation=observed, repository=facts,
                candidate=project.CanonicalCandidate(
                    observed.owner, observed.name, observed.repository_id),
            )

        capabilities = SimpleNamespace(
            access=candidate_access,
            bookmarks=project.ChannelBookmarks(slack),
        )
        return tmp, root, db, gateway, calls, capabilities

    def test_dynamic_set_replay_replace_and_clear(self):
        tmp, root, db, gateway, _ = self.make_gateway()
        with tmp:
            origin = project.TrustedOrigin("W1", "C1")
            a, b = candidate("11"), candidate("22")
            first = gateway.set(origin, a, expected_repository_id=None)
            self.assertEqual(first.repository_id, "11")
            replay = gateway.set(origin, a, expected_repository_id=None)
            self.assertEqual(replay.repository_id, "11")
            with self.assertRaises(registry.AssociationConflict):
                gateway.set(origin, b, expected_repository_id=None)
            changed = gateway.set(origin, b, expected_repository_id="11")
            self.assertEqual(changed.repository_id, "22")
            gateway.clear(origin, expected_repository_id="22")
            self.assertIsNone(gateway.show(origin))
            gateway.clear(origin, expected_repository_id=None)

    def test_gateway_allows_same_id_rename_and_transfer_from_stale_candidate_names(self):
        tmp, root, db, _, seen = self.make_gateway()
        with tmp:
            def observe(value):
                seen.append(value)
                return observation(value.repository_id, "new-owner", "new-name", installation_id="8")

            gateway = project.ProjectGateway(db, observe, state_root=root)
            origin = project.TrustedOrigin("W1", "C1")
            route = gateway.set(origin, candidate("11", "old-owner", "old-name"))
            self.assertEqual((route.repository.owner, route.repository.name), ("new-owner", "new-name"))

    def test_recreated_name_with_changed_observed_id_rejects_without_state_change(self):
        tmp, root, db, _, seen = self.make_gateway()
        with tmp:
            gateway = project.ProjectGateway(
                db, lambda value: observation("99", value.owner, value.name), state_root=root
            )
            origin = project.TrustedOrigin("W1", "C1")
            with self.assertRaises(project.ObservationMismatch):
                gateway.set(origin, candidate("11"))
            self.assertFalse(db.db_path.exists())
            self.assertEqual(seen, [])

    def test_fixed_facts_are_explicit_and_validation_matches_dynamic_rows(self):
        origin = project.TrustedOrigin("W1", "fixed")
        facts = fixed_facts("99")
        fixed = project.FixedProject(origin, facts)
        tmp, root, db, gateway, _ = self.make_gateway((fixed,))
        with tmp:
            route = gateway.show(origin)
            self.assertIsInstance(route, project.CurrentProjectRoute)
            self.assertIs(route.repository, facts)
            self.assertEqual(route.repository.worktree, facts.worktree)
            invalid = registry.RepositoryFacts(
                "100", "bad", "7", "owner", "repo", "relative", "https://example/repo.git",
                "main", "/srv/hermes/project-state/fixed-git/100"
            )
            with self.assertRaises(project.FixedProjectError):
                project.ProjectGateway(db, lambda value: observation(value.repository_id),
                                       (project.FixedProject(origin, invalid),), state_root=root)

    def test_gateway_defaults_to_registry_lock_root(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as tmp:
            root = Path(tmp)
            db = registry.ProjectRegistry(
                root / "projects.db", workspace_root=root / "workspaces",
                state_root=root / "retained-state")
            gateway = project.ProjectGateway(
                db, lambda value: observation(value.repository_id, value.owner, value.name)
            )
            self.assertEqual(gateway.state_root, db.state_root)

    def test_fixed_route_is_active_without_database_or_mutation(self):
        origin = project.TrustedOrigin("W1", "fixed")
        fixed = project.FixedProject(origin, fixed_facts("99"))
        tmp, root, db, gateway, _ = self.make_gateway((fixed,))
        with tmp:
            route = gateway.show(origin)
            self.assertTrue(route.fixed)
            self.assertEqual(route.repository_id, "99")
            self.assertFalse(db.db_path.exists())
            with self.assertRaises(project.FixedProjectError):
                gateway.set(origin, candidate("11"))
            with self.assertRaises(project.FixedProjectError):
                gateway.clear(origin)
            with self.assertRaises(project.FixedProjectError):
                gateway.set(project.TrustedOrigin("W1", "ordinary"), candidate("99"))

    def test_legacy_binding_to_reserved_fixed_id_fails_closed_before_provider_or_mutation(self):
        origin = project.TrustedOrigin("W1", "fixed")
        fixed = project.FixedProject(origin, fixed_facts("99"))
        tmp, root, db, gateway, seen = self.make_gateway((fixed,))
        with tmp:
            observed = observation("99")
            set_association(db, "W1", "ordinary", observed)
            before = db.db_path.read_bytes()
            ordinary = project.TrustedOrigin("W1", "ordinary")
            for action in (
                lambda: gateway.show(ordinary),
                lambda: gateway.set(ordinary, candidate("11")),
                lambda: gateway.clear(ordinary),
            ):
                with self.assertRaises(project.FixedProjectError):
                    action()
            self.assertEqual(seen, [])
            self.assertEqual(db.db_path.read_bytes(), before)

    def test_missing_database_stale_set_and_clear_are_no_effects(self):
        tmp, root, db, gateway, seen = self.make_gateway()
        with tmp:
            origin = project.TrustedOrigin("W1", "C1")
            self.assertIsNone(gateway.show(origin))
            self.assertIsNone(gateway.clear(origin, expected_repository_id=None))
            self.assertEqual(list(root.iterdir()), [])
            with self.assertRaises(registry.AssociationConflict):
                gateway.set(origin, candidate("11"), expected_repository_id="22")
            with self.assertRaises(registry.AssociationConflict):
                gateway.clear(origin, expected_repository_id="22")
            self.assertEqual(list(root.iterdir()), [])
            self.assertEqual(seen, [])

    def test_stale_expected_set_rejects_before_provider_callback(self):
        tmp, root, _, gateway, seen = self.make_gateway()
        with tmp:
            origin = project.TrustedOrigin("W1", "C1")
            gateway.set(origin, candidate("11"))
            seen.clear()
            with self.assertRaises(registry.AssociationConflict):
                gateway.set(origin, candidate("22"), expected_repository_id="99")
            self.assertEqual(seen, [])

    def test_locked_route_blocks_reassociation_until_transmission_finishes(self):
        tmp, root, db, gateway, _ = self.make_gateway()
        with tmp:
            origin = project.TrustedOrigin("W1", "C1")
            gateway.set(origin, candidate("11"))
            entered = threading.Event()
            release = threading.Event()
            finished = threading.Event()

            def transmit():
                with gateway.locked_current_route(origin) as route:
                    self.assertEqual(route.repository_id, "11")
                    entered.set()
                    release.wait(2)

            first = threading.Thread(target=transmit)
            first.start()
            self.assertTrue(entered.wait(2))

            def replace():
                gateway.set(origin, candidate("22"), expected_repository_id="11")
                finished.set()

            second = threading.Thread(target=replace)
            second.start()
            time.sleep(.1)
            self.assertFalse(finished.is_set())
            release.set()
            first.join(2)
            second.join(2)
            self.assertTrue(finished.is_set())
            self.assertEqual(gateway.show(origin).repository_id, "22")

    def test_locked_route_blocks_both_set_and_clear(self):
        tmp, root, db, gateway, _ = self.make_gateway()
        with tmp:
            origin = project.TrustedOrigin("W1", "C1")
            gateway.set(origin, candidate("11"))
            entered = threading.Event()
            release = threading.Event()
            with gateway.locked_current_route(origin) as route:
                self.assertEqual(route.repository_id, "11")
                entered.set()
                outcomes = []

                def replace():
                    try:
                        gateway.set(origin, candidate("22"), expected_repository_id="11")
                    except registry.AssociationConflict:
                        pass
                    outcomes.append("set")

                def clear():
                    try:
                        gateway.clear(origin, expected_repository_id="11")
                    except registry.AssociationConflict:
                        pass
                    outcomes.append("clear")

                threads = [threading.Thread(target=replace), threading.Thread(target=clear)]
                for thread in threads:
                    thread.start()
                time.sleep(.1)
                self.assertEqual(outcomes, [])
                release.set()
            for thread in threads:
                thread.join(2)
            self.assertEqual(sorted(outcomes), ["clear", "set"])

    def test_provider_callback_is_inside_channel_and_candidate_lock_boundary(self):
        tmp, root, db, _, _ = self.make_gateway()
        with tmp:
            original = project.host_boundary.ordered_locks
            inside = []
            active = False

            @contextmanager
            def wrapped(*args, **kwargs):
                nonlocal active
                with original(*args, **kwargs):
                    active = True
                    yield
                    active = False

            def observe(value):
                inside.append(active)
                return observation(value.repository_id, value.owner, value.name)

            project.host_boundary.ordered_locks = wrapped
            try:
                gateway = project.ProjectGateway(db, observe, state_root=root)
                gateway.set(project.TrustedOrigin("W1", "C1"), candidate("11"))
            finally:
                project.host_boundary.ordered_locks = original
            self.assertEqual(inside, [True])

    def test_u3_access_identity_and_url_rejections_precede_credentials_and_workspace(self):
        cases = {
            "owner mismatch": observation("11", "other", "repo"),
            "name mismatch": observation("11", "owner", "other"),
            "alternate host": observation("11", url="https://example.com/owner/repo.git"),
            "query": observation("11", url="https://github.com/owner/repo.git?token=x"),
            "fragment": observation("11", url="https://github.com/owner/repo.git#main"),
            "noncanonical": observation("11", url="https://github.com/owner/repo"),
        }
        for label, observed in cases.items():
            with self.subTest(label=label):
                tmp, root, _, gateway, calls, caps = self.make_u3_gateway(
                    access_reader=lambda locator, value=observed: value
                )
                with tmp:
                    with self.assertRaises(project.ObservationMismatch):
                        caps.access(project.RepositoryLocator("owner", "repo"))
                    self.assertEqual([call for call in calls if call[0] == "token"], [])
                    self.assertEqual([call for call in calls if isinstance(call[0], tuple)], [])
                    self.assertFalse((root / "worktrees").exists())

    def test_u3_workspace_entry_revalidates_canonical_repository_facts_before_effects(self):
        cases = {
            "forged URL": {"url": "https://attacker.test/owner/repo.git"},
            "mismatched owner and name": {
                "owner": "other", "name": "project",
                "url": "https://github.com/owner/repo.git",
            },
        }
        for label, changes in cases.items():
            with self.subTest(label=label):
                tmp, root, _, gateway, calls, caps = self.make_u3_gateway()
                with tmp:
                    access = caps.access(project.RepositoryLocator("owner", "repo"))
                    forged = replace(access.repository, **changes)
                    calls.clear()
                    before = tuple(root.iterdir())
                    with self.assertRaises(project.WorkspaceError):
                        gateway.initialize_workspace(forged)
                    self.assertEqual(calls, [])
                    self.assertEqual(tuple(root.iterdir()), before)

    def test_u3_git_metadata_redirections_reject_candidate_without_effect_on_active(self):
        attacks = ("commondir", "alternates", "http-alternates",
                   "config", "objects", "refs")
        for attack in attacks:
            with self.subTest(attack=attack):
                def access(locator):
                    return observation("22", locator.owner, locator.name)

                tmp, root, _, gateway, calls, caps = self.make_u3_gateway(access_reader=access)
                with tmp:
                    origin = project.TrustedOrigin("W1", "C1")
                    gateway.set(origin, candidate("11", "owner", "active-a"))
                    active_before = gateway.show(origin)
                    selected = caps.access(project.RepositoryLocator("owner", "repo"))
                    active_gitdir = root / "active-a-git"
                    active_gitdir.mkdir(mode=0o700)
                    (active_gitdir / "config").write_text("active config", encoding="utf-8")
                    (active_gitdir / "objects").mkdir()
                    (active_gitdir / "refs").mkdir()
                    active_before_files = {
                        path.relative_to(active_gitdir): path.read_bytes()
                        for path in active_gitdir.rglob("*") if path.is_file()
                    }
                    create_workspace_pair(selected.repository)
                    gitdir = Path(selected.repository.trusted_gitdir)
                    if attack == "commondir":
                        (gitdir / "commondir").write_text(str(active_gitdir), encoding="utf-8")
                    elif attack in {"alternates", "http-alternates"}:
                        info = gitdir / "objects" / "info"
                        info.mkdir(parents=True)
                        (info / attack).write_text(str(active_gitdir / "objects"), encoding="utf-8")
                    else:
                        target = active_gitdir / attack
                        existing = gitdir / attack
                        if existing.is_dir():
                            existing.rmdir()
                        else:
                            existing.unlink()
                        existing.symlink_to(target, target_is_directory=target.is_dir())
                    calls.clear()
                    with self.assertRaises(project.WorkspaceError):
                        gateway.initialize_workspace(selected.repository)
                    self.assertEqual(calls, [])
                    self.assertEqual(gateway.show(origin), active_before)
                    self.assertEqual({
                        path.relative_to(active_gitdir): path.read_bytes()
                        for path in active_gitdir.rglob("*") if path.is_file()
                    }, active_before_files)

    def test_u3_nested_git_metadata_symlinks_reject_before_git_or_token(self):
        attacks = (
            "refs/heads/task", "refs/remotes/origin/main", "objects/pack/pack-x.pack",
            "objects/ab/cdef", "logs/refs/heads/main", "custom/deep/redirect",
        )
        for attack in attacks:
            with self.subTest(attack=attack):
                tmp, root, _, gateway, calls, caps = self.make_u3_gateway()
                with tmp:
                    origin = project.TrustedOrigin("W1", "C1")
                    gateway.set(origin, candidate("33", "owner", "active"))
                    active_before = gateway.show(origin)
                    selected = caps.access(project.RepositoryLocator("owner", "repo"))
                    create_workspace_pair(selected.repository)
                    link = Path(selected.repository.trusted_gitdir) / attack
                    link.parent.mkdir(parents=True, exist_ok=True)
                    target = root / "candidate-a-unchanged"
                    target.write_text("unchanged", encoding="utf-8")
                    link.symlink_to(target)
                    calls.clear()
                    with self.assertRaises(project.WorkspaceError):
                        gateway.initialize_workspace(selected.repository)
                    self.assertEqual(target.read_text(encoding="utf-8"), "unchanged")
                    self.assertEqual(gateway.show(origin), active_before)
                    self.assertEqual([call for call in calls if call[0] == "token"], [])
                    self.assertEqual([call for call in calls if isinstance(call[0], tuple)], [])

    def test_u3_first_init_accepts_absent_normal_git_metadata(self):
        tmp, _, _, gateway, calls, caps = self.make_u3_gateway()
        with tmp:
            access = caps.access(project.RepositoryLocator("owner", "repo"))
            calls.clear()
            effect = gateway.initialize_workspace(access.repository)
            self.assertEqual(effect.effect, "initialized")
            self.assertTrue(any(isinstance(call[0], tuple) and " init --bare --initial-branch "
                                in f" {' '.join(call[0])} " for call in calls))

    def test_u3_existing_malicious_origin_or_unsafe_config_rejects_before_token_fetch(self):
        canonical = successful_git_result(["git", "config", "--null", "--list"])["stdout"]
        configs = {
            "malicious origin": canonical.replace(
                "https://github.com/owner/repo.git", "https://evil.test/owner/repo.git"
            ),
            "unsafe local config": canonical + "credential.helper\nstore\0",
        }
        for label, config in configs.items():
            with self.subTest(label=label):
                def runner(argv, **kwargs):
                    if "--null --list" in " ".join(argv):
                        return successful_git_result(argv, config=config)
                    return successful_git_result(argv)

                tmp, _, _, gateway, calls, caps = self.make_u3_gateway(process_runner=runner)
                with tmp:
                    access = caps.access(project.RepositoryLocator("owner", "repo"))
                    create_workspace_pair(access.repository)
                    calls.clear()
                    with self.assertRaises(project.WorkspaceError):
                        gateway.fetch_workspace(access.repository)
                    self.assertEqual([call for call in calls if call[0] == "token"], [])
                    self.assertFalse(any(" fetch " in f" {' '.join(call[0])} "
                                         for call in calls if isinstance(call[0], tuple)))

    def test_u3_workspace_credentials_are_redacted_and_exceptions_are_sanitized(self):
        token = "u3-secret-token"
        encoded = base64.b64encode(f"x-access-token:{token}".encode()).decode()

        def leaking_fetch(argv, **kwargs):
            if " fetch " in f" {' '.join(argv)} ":
                return {"state": "exited", "exit_code": 0, "stdout": token,
                        "stderr": f"Authorization: Basic {encoded}", "uncertain": False,
                        "details": {"credential": [token, encoded]}}
            return successful_git_result(argv)

        tmp, _, _, gateway, calls, caps = self.make_u3_gateway(process_runner=leaking_fetch)
        with tmp:
            access = caps.access(project.RepositoryLocator("owner", "repo"))
            create_workspace_pair(access.repository)
            effect = gateway.fetch_workspace(access.repository)
            argv = [call[0] for call in calls if isinstance(call[0], tuple)]
            credential_envs = [call[1]["env"] for call in calls if isinstance(call[0], tuple)
                               and "GIT_CONFIG_KEY_8" in call[1]["env"]]
            self.assertTrue(credential_envs)
            self.assertTrue(all(env["GIT_CONFIG_KEY_8"] ==
                                "http.https://github.com/owner/repo.git.extraHeader"
                                for env in credential_envs))
            for secret in (token, encoded):
                self.assertNotIn(secret, repr(argv))
                self.assertNotIn(secret, repr(effect))
            self.assertIn("[REDACTED]", repr(effect.process))

        exception_readers = {
            "process": (lambda request: {
                **request, "token": token,
                "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
                "repository_selection": "selected",
                "repositories": [{"id": 11, "name": "repo", "full_name": "owner/repo"}],
            }),
            "token": (lambda request: (_ for _ in ()).throw(
                RuntimeError(f"credential {token} Basic {encoded}"))),
        }
        for label, reader in exception_readers.items():
            with self.subTest(exception=label):
                def exploding_runner(argv, **kwargs):
                    if label == "process" and " fetch " in f" {' '.join(argv)} ":
                        raise RuntimeError(f"credential {token} Basic {encoded}")
                    return successful_git_result(argv)

                tmp, _, _, gateway, _, caps = self.make_u3_gateway(
                    token_reader=reader, process_runner=exploding_runner
                )
                with tmp:
                    access = caps.access(project.RepositoryLocator("owner", "repo"))
                    create_workspace_pair(access.repository)
                    with self.assertRaises(project.WorkspaceError) as caught:
                        gateway.fetch_workspace(access.repository)
                    for secret in (token, encoded):
                        self.assertNotIn(secret, str(caught.exception))
                        self.assertNotIn(secret, repr(caught.exception))

    def test_workspace_run_git_rejects_transport_half_pairs_before_child(self):
        tmp, _, _, gateway, _, caps = self.make_u3_gateway()
        with tmp:
            facts = caps.access(project.RepositoryLocator("owner", "repo")).repository
            create_workspace_pair(facts)
            descriptor = gateway._workspace_descriptor(facts)
            calls = []
            gateway.process_runner = lambda *args, **kwargs: calls.append(args)
            with project.host_boundary.DescriptorAnchor(descriptor) as anchor:
                with self.assertRaises(project.WorkspaceError):
                    gateway._run_git(descriptor, ["status"], token="opaque", anchor=anchor)
                with self.assertRaises(project.WorkspaceError):
                    gateway._run_git(
                        descriptor, ["status"],
                        repository_url="https://github.com/owner/repo.git", anchor=anchor)
            self.assertFalse(calls)

    def test_u3_failed_or_uncertain_fetch_is_one_shot_and_never_reports_success(self):
        outcomes = {
            "timeout": {"state": "timed_out", "exit_code": None, "stdout": "",
                        "stderr": "", "uncertain": True},
            "nonzero": {"state": "exited", "exit_code": 2, "stdout": "",
                        "stderr": "rejected", "uncertain": False},
            "uncertain": {"state": "exited", "exit_code": 0, "stdout": "",
                          "stderr": "", "uncertain": True},
        }
        for label, outcome in outcomes.items():
            with self.subTest(label=label):
                def runner(argv, **kwargs):
                    if " fetch " in f" {' '.join(argv)} ":
                        return dict(outcome)
                    return successful_git_result(argv)

                tmp, _, _, gateway, calls, caps = self.make_u3_gateway(process_runner=runner)
                with tmp:
                    access = caps.access(project.RepositoryLocator("owner", "repo"))
                    create_workspace_pair(access.repository)
                    calls.clear()
                    effect = gateway.fetch_workspace(access.repository)
                    fetches = [call for call in calls if isinstance(call[0], tuple)
                               and " fetch " in f" {' '.join(call[0])} "]
                    self.assertEqual(len(fetches), 1)
                    # Only the selected one-shot fetch is effect evidence.
                    self.assertEqual(len(effect.process), 1)
                    self.assertNotIn(effect.effect, {"created", "fetched"})

    def test_u3_inspection_reports_direct_dirty_divergence_and_partial_pair(self):
        tmp, root, _, gateway, _, caps = self.make_u3_gateway()
        with tmp:
            access = caps.access(project.RepositoryLocator("owner", "repo"))
            absent = gateway.inspect_workspace(access.repository)
            self.assertEqual(absent.state, "absent")
            Path(access.repository.worktree).parent.mkdir(mode=0o700)
            Path(access.repository.worktree).mkdir(mode=0o700)
            before = set((root / "worktrees").iterdir())
            with self.assertRaises(project.WorkspaceError):
                gateway.initialize_workspace(access.repository)
            self.assertEqual(set((root / "worktrees").iterdir()), before)
            self.assertEqual(gateway.inspect_workspace(access.repository).state, "partial")
            Path(access.repository.worktree).rmdir()
            gateway.initialize_workspace(access.repository)
            present = gateway.inspect_workspace(access.repository)
            self.assertEqual((present.state, present.dirty, present.ahead, present.behind),
                             ("present", True, 2, 3))

    def test_u3_current_task_branch_is_inspected_and_fetched_without_checkout(self):
        def runner(argv, **kwargs):
            command = " ".join(argv)
            config = successful_git_result(argv)["stdout"] + (
                "branch.hermes/task-1.remote\norigin\0"
                "branch.hermes/task-1.merge\nrefs/heads/hermes/task-1\0"
            )
            result = successful_git_result(argv, config=config)
            if "symbolic-ref --quiet HEAD" in command:
                result["stdout"] = "refs/heads/hermes/task-1\n"
            elif "symbolic-ref --quiet --short HEAD" in command:
                result["stdout"] = "hermes/task-1\n"
            elif "@{upstream}" in command and "rev-list" not in command:
                result["stdout"] = "origin/hermes/task-1\n"
            return result

        tmp, _, _, gateway, calls, caps = self.make_u3_gateway(process_runner=runner)
        with tmp:
            access = caps.access(project.RepositoryLocator("owner", "repo"))
            create_workspace_pair(access.repository)
            inspected = gateway.inspect_workspace(access.repository)
            self.assertEqual((inspected.state, inspected.branch, inspected.dirty,
                              inspected.ahead, inspected.behind),
                             ("present", "hermes/task-1", True, 2, 3))
            calls.clear()
            effect = gateway.fetch_workspace(access.repository)
            commands = [" ".join(call[0]) for call in calls if isinstance(call[0], tuple)]
            self.assertEqual(effect.effect, "fetched")
            self.assertTrue(any(" fetch " in f" {command} " for command in commands))
            self.assertFalse(any(" checkout " in f" {command} " for command in commands))

    def test_u3_local_branch_without_upstream_remains_present(self):
        def runner(argv, **kwargs):
            command = " ".join(argv)
            if "@{upstream}" in command:
                return {"state": "exited", "exit_code": 128, "stdout": "",
                        "stderr": "no upstream", "uncertain": False}
            return successful_git_result(argv)

        tmp, _, _, gateway, _, caps = self.make_u3_gateway(process_runner=runner)
        with tmp:
            access = caps.access(project.RepositoryLocator("owner", "repo"))
            create_workspace_pair(access.repository)
            inspected = gateway.inspect_workspace(access.repository)
            self.assertEqual((inspected.state, inspected.branch, inspected.head, inspected.dirty),
                             ("present", "main", "a" * 40, True))
            self.assertEqual((inspected.upstream, inspected.ahead, inspected.behind),
                             (None, None, None))
            self.assertEqual(set(inspected.process_failures), {"upstream", "counts"})

    def test_u3_config_and_head_timeouts_are_partial_uncertain_evidence(self):
        for target in ("config --local --null --list", "symbolic-ref --quiet HEAD"):
            with self.subTest(target=target):
                def runner(argv, **kwargs):
                    if target in " ".join(argv):
                        return {"state": "timed_out", "exit_code": None, "stdout": "",
                                "stderr": "secret-free", "uncertain": True}
                    return successful_git_result(argv)

                tmp, _, _, gateway, _, caps = self.make_u3_gateway(process_runner=runner)
                with tmp:
                    access = caps.access(project.RepositoryLocator("owner", "repo"))
                    create_workspace_pair(access.repository)
                    inspected = gateway.inspect_workspace(access.repository)
                    self.assertEqual(inspected.state, "partial")
                    self.assertTrue(inspected.process_uncertainty)
                    effect = gateway.initialize_workspace(access.repository)
                    self.assertEqual((effect.effect, effect.inspection.state), ("uncertain", "partial"))
                    self.assertTrue(effect.process)
                    self.assertNotIn("u3-secret-token", repr(effect.process))

    def test_u3_uncertain_initial_init_survives_concrete_inspection(self):
        timed_out = False
        def runner(argv, **kwargs):
            nonlocal timed_out
            if " init --bare --initial-branch " in f" {' '.join(argv)} " and not timed_out:
                # Model a real timeout after Git created only a subset of its
                # ordinary bare layout.
                gitdir = Path(next(item for item in argv if item.startswith("/proc/")
                                   or item.endswith("/state/git/11")))
                (gitdir / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
                (gitdir / "objects").mkdir(exist_ok=True)
                timed_out = True
                return {"state": "timed_out", "exit_code": None, "stdout": "",
                        "stderr": "", "uncertain": True}
            if timed_out and (" init --bare --initial-branch " in f" {' '.join(argv)} "
                              or "config --local" in " ".join(argv)):
                return project.cli_runner.run_argv(argv, **kwargs)
            return successful_git_result(argv)

        tmp, _, _, gateway, calls, caps = self.make_u3_gateway(process_runner=runner)
        with tmp:
            access = caps.access(project.RepositoryLocator("owner", "repo"))
            calls.clear()
            effect = gateway.initialize_workspace(access.repository)
            commands = [" ".join(call[0]) for call in calls if isinstance(call[0], tuple)]
            self.assertEqual(effect.effect, "uncertain")
            self.assertEqual(len(effect.process), 1)
            self.assertEqual(sum(" init --bare --initial-branch " in f" {item} " for item in commands), 1)
            self.assertFalse(any(" fetch " in f" {item} " for item in commands))
            self.assertEqual([call for call in calls if call[0] == "token"], [])
            self.assertEqual(gateway.initialize_workspace(access.repository).effect, "initialized")
            gitdir = Path(access.repository.trusted_gitdir)
            self.assertFalse((gitdir / project.INITIALIZE_MARKER).exists())
            self.assertEqual(
                subprocess.run(["/usr/bin/git", f"--git-dir={gitdir}", "config", "--get",
                                "remote.origin.url"], check=True, text=True,
                               capture_output=True).stdout.strip(), access.repository.url)

    def test_u3_uncertain_validation_retains_completed_init_evidence(self):
        validation_reads = 0

        def runner(argv, **kwargs):
            nonlocal validation_reads
            if " init --bare --initial-branch " in f" {' '.join(argv)} " \
                    or ("config --local" in " ".join(argv)
                        and "--null --list" not in " ".join(argv)):
                return project.cli_runner.run_argv(argv, **kwargs)
            if "config --local --null --list" in " ".join(argv):
                validation_reads += 1
                return {"state": "timed_out", "exit_code": None, "stdout": "",
                        "stderr": "", "uncertain": True}
            return successful_git_result(argv)

        tmp, _, _, gateway, calls, caps = self.make_u3_gateway(process_runner=runner)
        with tmp:
            access = caps.access(project.RepositoryLocator("owner", "repo"))
            calls.clear()
            effect = gateway.initialize_workspace(access.repository)
            commands = [" ".join(call[0]) for call in calls if isinstance(call[0], tuple)]
            self.assertEqual((effect.effect, validation_reads), ("uncertain", 1))
            self.assertTrue(effect.process)
            self.assertFalse(any(" fetch " in f" {item} " for item in commands))
            self.assertEqual([call for call in calls if call[0] == "token"], [])

    def test_u3_same_id_rename_uses_fresh_identity_for_token_and_fetch(self):
        old_url = "https://github.com/old-owner/old-name.git"
        fresh_url = "https://github.com/new-owner/new-name.git"
        def provider(candidate):
            return observation("11", "new-owner", "new-name")

        def runner(argv, **kwargs):
            command = " ".join(argv)
            config = successful_git_result(argv)["stdout"].replace(
                "https://github.com/owner/repo.git", old_url)
            return successful_git_result(argv, config=config)

        def token(request):
            return {
                **request, "token": "u3-secret-token",
                "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
                "repository_selection": "selected",
                "repositories": [{"id": 11, "name": "new-name",
                                  "full_name": "new-owner/new-name"}],
            }

        tmp, _, _, gateway, calls, caps = self.make_u3_gateway(
            provider_reader=provider, token_reader=token, process_runner=runner)
        with tmp:
            selected = caps.access(project.RepositoryLocator("old-owner", "old-name"))
            create_workspace_pair(selected.repository)
            gateway.initialize_workspace(selected.repository)
            calls.clear()
            effect = gateway.fetch_workspace(selected.repository)
            commands = [" ".join(call[0]) for call in calls if isinstance(call[0], tuple)]
            self.assertEqual(effect.effect, "fetched")
            fetch = next(index for index, item in enumerate(commands) if " fetch " in f" {item} ")
            self.assertIn(f"fetch --prune {fresh_url}", commands[fetch])
            self.assertNotIn(old_url, commands[fetch])

    def test_u3_fixed_workspace_fetch_uses_id_observed_renamed_repository(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            workspace, state = root / "worktrees", root / "state"
            store = registry.ProjectRegistry(root / "projects.db", workspace_root=workspace,
                                             state_root=state)
            origin = project.TrustedOrigin("W1", "C1")
            facts = registry.RepositoryFacts(
                "11", "peirce", "7", "peirce-example", "peirce", str(workspace / "peirce"),
                "https://github.com/peirce-example/peirce.git", "main",
                str(state / "reserved" / "peirce.git"))
            admin_origin = project.TrustedOrigin("W1", "C2")
            admin = registry.RepositoryFacts(
                "22", "peirce-admin", "7", "peirce-example", "peirce-admin",
                str(workspace / "peirce-admin"), "https://github.com/peirce-example/peirce-admin.git",
                "main", str(state / "reserved" / "peirce-admin.git"))
            fresh = observation("11", "new-owner", "new-name")
            commands = []

            def token(request):
                return {
                    **request, "token": "u3-secret-token",
                    "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
                    "repository_selection": "selected",
                    "repositories": [{"id": 11, "name": "new-name",
                                      "full_name": "new-owner/new-name"}],
                }

            def runner(argv, **kwargs):
                commands.append(" ".join(argv))
                result = successful_git_result(argv)
                if "config --local --null --list" in " ".join(argv):
                    result = successful_git_result(
                        argv, config=result["stdout"].replace(
                            "https://github.com/owner/repo.git", facts.url))
                return result

            gateway = project.ProjectGateway(
                store, lambda candidate: fresh,
                (project.FixedProject(origin, facts, "source"),
                 project.FixedProject(admin_origin, admin, "admin")), state_root=state,
                token_reader=token, process_runner=runner)
            create_workspace_pair(facts)
            gateway.initialize_workspace(facts)
            commands.clear()
            effect = gateway.fetch_workspace(facts)
            self.assertEqual(effect.effect, "fetched")
            fetch = next(command for command in commands if " fetch " in f" {command} ")
            self.assertIn(f"fetch --prune {fresh.url}", fetch)
            self.assertNotIn(facts.url, fetch)

    def test_u3_same_id_rename_still_rejects_unsafe_stale_origin(self):
        unsafe = successful_git_result(["git", "config", "--null", "--list"])["stdout"].replace(
            "https://github.com/owner/repo.git",
            "https://github.com/old-owner/old-name.git?credential=x")

        def runner(argv, **kwargs):
            return successful_git_result(argv, config=unsafe)

        tmp, _, _, gateway, calls, caps = self.make_u3_gateway(process_runner=runner)
        with tmp:
            access = caps.access(project.RepositoryLocator("owner", "repo"))
            create_workspace_pair(access.repository)
            calls.clear()
            with self.assertRaises(project.WorkspaceError):
                gateway.initialize_workspace(access.repository)
            self.assertEqual([call for call in calls if call[0] == "token"], [])

    def test_u3_reverse_partial_pair_fails_without_cleanup(self):
        tmp, _, _, gateway, calls, caps = self.make_u3_gateway()
        with tmp:
            access = caps.access(project.RepositoryLocator("owner", "repo"))
            create_workspace_pair(access.repository, worktree=False, gitdir=True)
            gitdir = Path(access.repository.trusted_gitdir)
            before = tuple(sorted(path.name for path in gitdir.iterdir()))
            calls.clear()
            with self.assertRaises(project.WorkspaceError):
                gateway.initialize_workspace(access.repository)
            self.assertFalse(Path(access.repository.worktree).exists())
            self.assertTrue(gitdir.is_dir())
            self.assertEqual(tuple(sorted(path.name for path in gitdir.iterdir())), before)
            self.assertEqual(gateway.inspect_workspace(access.repository).state, "partial")
            self.assertEqual([call for call in calls if call[0] == "token"], [])

    def test_u3_initialize_is_uncredentialed_and_never_fetches_or_checks_out(self):
        tmp, _, _, gateway, calls, caps = self.make_u3_gateway()
        with tmp:
            facts = caps.access(project.RepositoryLocator("owner", "repo")).repository
            calls.clear()
            effect = gateway.initialize_workspace(facts)
            commands = [" ".join(call[0]) for call in calls if isinstance(call[0], tuple)]
            self.assertEqual(effect.effect, "initialized")
            self.assertEqual([call for call in calls if call[0] in {"access", "token"}], [])
            self.assertTrue(any(" init --bare --initial-branch " in f" {item} " for item in commands))
            self.assertFalse(any(" fetch " in f" {item} " or " checkout " in f" {item} "
                                 for item in commands))

    def test_u3_real_initializer_is_noninterfering_repairs_stale_origin_and_supports_worktree_git(self):
        tmp, _, _, gateway, _, caps = self.make_u3_gateway()
        with tmp:
            facts = caps.access(project.RepositoryLocator("owner", "repo")).repository
            gateway.process_runner = project.cli_runner.run_argv
            repaired_effect = gateway.initialize_workspace(facts)
            self.assertEqual(repaired_effect.effect, "initialized", repr(repaired_effect))
            gitdir, worktree = Path(facts.trusted_gitdir), Path(facts.worktree)
            config_before = (gitdir / "config").read_bytes()
            tree_before = sorted(str(path.relative_to(gitdir)) for path in gitdir.rglob("*"))
            self.assertEqual(gateway.initialize_workspace(facts).effect, "initialized")
            self.assertEqual((gitdir / "config").read_bytes(), config_before)
            self.assertEqual(sorted(str(path.relative_to(gitdir)) for path in gitdir.rglob("*")),
                             tree_before)

            argv = ["/usr/bin/git", f"--git-dir={gitdir}", f"--work-tree={worktree}"]
            env = dict(os.environ, GIT_AUTHOR_NAME="Test", GIT_AUTHOR_EMAIL="test@example.invalid",
                       GIT_COMMITTER_NAME="Test", GIT_COMMITTER_EMAIL="test@example.invalid")
            (worktree / "ordinary.txt").write_text("ordinary\n", encoding="utf-8")
            subprocess.run([*argv, "add", "--", "ordinary.txt"], check=True,
                           capture_output=True, env=env)
            subprocess.run([*argv, "commit", "-m", "ordinary"], check=True,
                           capture_output=True, env=env)
            subprocess.run([*argv, "switch", "-c", "hermes/task"], check=True,
                           capture_output=True)
            subprocess.run([*argv, "checkout", "main"], check=True, capture_output=True)

            subprocess.run([*argv, "config", "remote.origin.url",
                            "https://github.com/old-owner/old-repo.git"], check=True,
                           capture_output=True)
            repaired_effect = gateway.initialize_workspace(facts)
            self.assertEqual(repaired_effect.effect, "initialized", repr(repaired_effect))
            repaired = subprocess.run([*argv, "config", "--get", "remote.origin.url"],
                                      check=True, text=True, capture_output=True).stdout.strip()
            self.assertEqual(repaired, facts.url)

    def test_u3_initialize_fetch_then_checkout_materializes_canonical_unborn_default(self):
        tmp, root, _, gateway, _, caps = self.make_u3_gateway()
        with tmp:
            source = root / "source"
            subprocess.run(["/usr/bin/git", "init", "--initial-branch", "main", str(source)],
                           check=True, capture_output=True)
            (source / "exact.bin").write_bytes(b"exact fetched bytes\x00\n")
            env = dict(os.environ, GIT_AUTHOR_NAME="Test", GIT_AUTHOR_EMAIL="test@example.invalid",
                       GIT_COMMITTER_NAME="Test", GIT_COMMITTER_EMAIL="test@example.invalid")
            subprocess.run(["/usr/bin/git", "-C", str(source), "add", "--", "exact.bin"],
                           check=True, capture_output=True, env=env)
            subprocess.run(["/usr/bin/git", "-C", str(source), "commit", "-m", "source"],
                           check=True, capture_output=True, env=env)
            target = subprocess.run(
                ["/usr/bin/git", "-C", str(source), "rev-parse", "HEAD"], check=True,
                text=True, capture_output=True).stdout.strip()

            origin = project.TrustedOrigin("W1", "C1")
            facts = caps.access(project.RepositoryLocator("owner", "repo")).repository
            real_runner = project.cli_runner.run_argv
            fetches = []

            def runner(argv, **kwargs):
                command = list(argv[5:])
                if command and command[0] == "fetch":
                    fetches.append(command)
                    materialized = subprocess.run([
                        "/usr/bin/git", f"--git-dir={facts.trusted_gitdir}",
                        f"--work-tree={facts.worktree}", "fetch", "--prune", str(source),
                        "+refs/heads/*:refs/remotes/origin/*",
                    ], text=True, capture_output=True)
                    return {"state": "exited", "exit_code": materialized.returncode,
                            "stdout": materialized.stdout, "stderr": materialized.stderr,
                            "uncertain": False}
                return real_runner(argv, **kwargs)

            gateway.process_runner = runner
            initialized = gateway.initialize_workspace(facts)
            self.assertEqual(initialized.effect, "initialized", repr(initialized))
            gateway.set(origin, project.CanonicalCandidate("owner", "repo", "11"))
            fetched = gateway.fetch_workspace(facts)
            self.assertEqual(fetched.effect, "fetched", repr(fetched))
            self.assertEqual(len(fetches), 1)
            inspected = gateway.inspect_workspace(facts)
            self.assertEqual((inspected.state, inspected.branch, inspected.head),
                             ("invalid", "main", None))

            value = project_git.ProjectGit(gateway).checkout_default(
                origin, "11", "main", None, target)
            self.assertEqual((value.effect, value.branch, value.commit, value.uncertain),
                             ("checked_out", "main", target, False), repr(value))
            git = ["/usr/bin/git", f"--git-dir={facts.trusted_gitdir}",
                   f"--work-tree={facts.worktree}"]
            self.assertEqual(subprocess.run(
                [*git, "branch", "--show-current"], check=True, text=True,
                capture_output=True).stdout.strip(), "main")
            self.assertEqual(subprocess.run(
                [*git, "rev-parse", "HEAD"], check=True, text=True,
                capture_output=True).stdout.strip(), target)
            self.assertEqual(subprocess.run(
                [*git, "rev-parse", "--abbrev-ref", "@{upstream}"], check=True, text=True,
                capture_output=True).stdout.strip(), "origin/main")
            self.assertEqual(subprocess.run(
                [*git, "status", "--porcelain=v1"], check=True, text=True,
                capture_output=True).stdout, "")
            self.assertEqual((Path(facts.worktree) / "exact.bin").read_bytes(),
                             b"exact fetched bytes\x00\n")

    def test_u3_full_sha_checkout_remains_present_fetchable_and_locally_recoverable(self):
        tmp, root, _, gateway, calls, caps = self.make_u3_gateway()
        with tmp:
            origin = project.TrustedOrigin("W1", "C1")
            facts = caps.access(project.RepositoryLocator("owner", "repo")).repository
            real_runner = project.cli_runner.run_argv
            child_environments = []

            def runner(argv, **kwargs):
                child_environments.append((list(argv), dict(kwargs.get("env", {}))))
                if " fetch --prune " in f" {' '.join(argv)} ":
                    return {"state": "exited", "exit_code": 0, "stdout": "",
                            "stderr": "", "uncertain": False}
                return real_runner(argv, **kwargs)

            gateway.process_runner = runner
            self.assertEqual(gateway.initialize_workspace(facts).effect, "initialized")
            self.assertTrue(child_environments)
            self.assertTrue(all(env.get("GIT_ALLOW_PROTOCOL") == ""
                                for _, env in child_environments))
            another_project = root / "another-project-sentinel"
            another_project.write_text("unchanged\n", encoding="utf-8")
            gitdir, worktree = Path(facts.trusted_gitdir), Path(facts.worktree)
            git = ["/usr/bin/git", f"--git-dir={gitdir}", f"--work-tree={worktree}"]
            (worktree / "ordinary.txt").write_text("ordinary\n", encoding="utf-8")
            subprocess.run([*git, "add", "--", "ordinary.txt"], check=True,
                           capture_output=True)
            subprocess.run([*git, "commit", "-m", "ordinary"], check=True,
                           capture_output=True)
            subprocess.run([*git, "switch", "-c", "hermes/recover"], check=True,
                           capture_output=True)
            subprocess.run([*git, "config", "branch.hermes/recover.remote", "origin"],
                           check=True, capture_output=True)
            subprocess.run([*git, "config", "branch.hermes/recover.merge",
                            "refs/heads/hermes/recover"], check=True, capture_output=True)
            sha = subprocess.run([*git, "rev-parse", "HEAD"], check=True, text=True,
                                 capture_output=True).stdout.strip()
            self.assertRegex(sha, r"^[0-9a-f]{40}$")
            gateway.set(origin, project.CanonicalCandidate("owner", "repo", "11"))

            detached = project_git.ProjectGit(gateway).run(origin, "11", ["checkout", sha])
            self.assertEqual(detached.effect, "applied", repr(detached))
            inspected = gateway.inspect_workspace(facts)
            self.assertEqual((inspected.state, inspected.branch, inspected.head),
                             ("present", None, sha))
            self.assertNotIn("branch", inspected.process_failures)

            calls.clear()
            fetched = gateway.fetch_workspace(facts)
            self.assertEqual(fetched.effect, "fetched", repr(fetched))
            fetch_env = next(env for argv, env in child_environments
                             if "fetch" in argv)
            self.assertEqual(fetch_env["GIT_ALLOW_PROTOCOL"], "https")
            self.assertIn("Authorization", repr(fetch_env))
            after_fetch = gateway.inspect_workspace(facts)
            self.assertEqual((after_fetch.state, after_fetch.branch, after_fetch.head),
                             ("present", None, sha))
            status = project_git.ProjectGit(gateway).run(origin, "11", ["status", "--short"])
            self.assertEqual(status.state, "observed", repr(status))

            reattached = project_git.ProjectGit(gateway).run(
                origin, "11", ["checkout", "hermes/recover"])
            self.assertEqual(reattached.effect, "applied", repr(reattached))
            inspected = gateway.inspect_workspace(facts)
            self.assertEqual((inspected.state, inspected.branch, inspected.head),
                             ("present", "hermes/recover", sha))
            self.assertEqual(another_project.read_text(encoding="utf-8"), "unchanged\n")

    def test_u3_detached_head_requires_one_exact_existing_commit(self):
        outcomes = {
            "malformed symbolic ref": (128, "a" * 40 + "\n", "invalid"),
            "missing commit": (1, "", "invalid"),
            "invalid commit output": (1, "A" * 40 + "\n", "invalid"),
            "uncertain symbolic ref": (None, "", "partial"),
        }
        for label, (symbolic_exit, detached_stdout, expected) in outcomes.items():
            with self.subTest(label=label):
                calls = []

                def runner(argv, **kwargs):
                    command = " ".join(argv)
                    if "symbolic-ref --quiet" in command:
                        if symbolic_exit is None:
                            return {"state": "timed_out", "exit_code": None, "stdout": "",
                                    "stderr": "", "uncertain": True}
                        return {"state": "exited", "exit_code": symbolic_exit, "stdout": "",
                                "stderr": "invalid", "uncertain": False}
                    if "rev-parse --verify HEAD^{commit}" in command:
                        return {"state": "exited", "exit_code": 0 if detached_stdout else 128,
                                "stdout": detached_stdout, "stderr": "", "uncertain": False}
                    return successful_git_result(argv)

                tmp, _, _, gateway, calls, caps = self.make_u3_gateway(process_runner=runner)
                with tmp:
                    facts = caps.access(project.RepositoryLocator("owner", "repo")).repository
                    create_workspace_pair(facts)
                    calls.clear()
                    self.assertEqual(gateway.inspect_workspace(facts).state, expected)
                    if expected == "partial":
                        effect = gateway.fetch_workspace(facts)
                        self.assertEqual((effect.effect, effect.inspection.state),
                                         ("uncertain", "partial"))
                    else:
                        with self.assertRaises(project.WorkspaceError):
                            gateway.fetch_workspace(facts)
                    self.assertEqual([call for call in calls if call[0] in {"provider", "token"}], [])

    def test_u3_detached_commit_resolution_timeout_is_partial_and_fetch_uncertain(self):
        def runner(argv, **kwargs):
            command = " ".join(argv)
            if "symbolic-ref --quiet" in command:
                return {"state": "exited", "exit_code": 1, "stdout": "",
                        "stderr": "", "uncertain": False}
            if "rev-parse --verify HEAD^{commit}" in command:
                return {"state": "timed_out", "exit_code": None, "stdout": "",
                        "stderr": "", "uncertain": True}
            return successful_git_result(argv)

        tmp, _, _, gateway, calls, caps = self.make_u3_gateway(process_runner=runner)
        with tmp:
            facts = caps.access(project.RepositoryLocator("owner", "repo")).repository
            create_workspace_pair(facts)
            calls.clear()
            self.assertEqual(gateway.inspect_workspace(facts).state, "partial")
            effect = gateway.fetch_workspace(facts)
            self.assertEqual((effect.effect, effect.inspection.state), ("uncertain", "partial"))
            self.assertEqual([call for call in calls if call[0] in {"provider", "token"}], [])

    def test_u3_unborn_target_must_be_exactly_absent_and_well_formed(self):
        tmp, _, _, gateway, _, caps = self.make_u3_gateway()
        with tmp:
            facts = caps.access(project.RepositoryLocator("owner", "repo")).repository
            gateway.process_runner = project.cli_runner.run_argv
            initialized = gateway.initialize_workspace(facts)
            self.assertEqual(initialized.effect, "initialized", repr(initialized))
            gitdir = Path(facts.trusted_gitdir)
            branch_ref = gitdir / "refs" / "heads" / "main"
            branch_ref.parent.mkdir(parents=True, exist_ok=True)
            tokens = []
            gateway.token_reader = lambda request: tokens.append(request)

            for label, value in (("malformed", "not-a-sha\n"),
                                 ("missing object", "f" * 40 + "\n")):
                with self.subTest(label=label):
                    branch_ref.write_text(value)
                    self.assertEqual(gateway.inspect_workspace(facts).state, "invalid")
                    with self.assertRaises(project.WorkspaceError):
                        gateway.initialize_workspace(facts)
                    with self.assertRaises(project.WorkspaceError):
                        gateway.fetch_workspace(facts)
                    self.assertFalse(tokens)
                    branch_ref.unlink()

    def test_u3_uncertain_unborn_ref_observation_is_partial(self):
        def runner(argv, **kwargs):
            command = " ".join(argv)
            if "rev-parse --verify HEAD" in command:
                return {"state": "exited", "exit_code": 128, "stdout": "",
                        "stderr": "missing", "uncertain": False}
            if "for-each-ref --format=%(refname)" in command:
                return {"state": "timed_out", "exit_code": None, "stdout": "",
                        "stderr": "", "uncertain": True}
            return successful_git_result(argv)

        tmp, _, _, gateway, calls, caps = self.make_u3_gateway(process_runner=runner)
        with tmp:
            facts = caps.access(project.RepositoryLocator("owner", "repo")).repository
            create_workspace_pair(facts)
            calls.clear()
            self.assertEqual(gateway.inspect_workspace(facts).state, "partial")
            effect = gateway.fetch_workspace(facts)
            self.assertEqual((effect.effect, effect.inspection.state), ("uncertain", "partial"))
            self.assertEqual([call for call in calls if call[0] in {"provider", "token"}], [])

    def test_u3_objects_and_refs_are_mandatory_real_directories(self):
        tmp, _, _, gateway, _, caps = self.make_u3_gateway()
        with tmp:
            facts = caps.access(project.RepositoryLocator("owner", "repo")).repository
            gateway.process_runner = project.cli_runner.run_argv
            gateway.initialize_workspace(facts)
            gitdir = Path(facts.trusted_gitdir)
            for name in ("objects", "refs"):
                with self.subTest(name=name):
                    original, moved = gitdir / name, gitdir / f"{name}.moved"
                    original.rename(moved)
                    try:
                        self.assertEqual(gateway.inspect_workspace(facts).state, "invalid")
                        with self.assertRaises(project.WorkspaceError):
                            gateway.initialize_workspace(facts)
                    finally:
                        moved.rename(original)

    def test_u3_fetch_is_exactly_one_effect_without_init_config_or_checkout(self):
        tmp, _, _, gateway, calls, caps = self.make_u3_gateway()
        with tmp:
            facts = caps.access(project.RepositoryLocator("owner", "repo")).repository
            create_workspace_pair(facts)
            calls.clear()
            effect = gateway.fetch_workspace(facts)
            commands = [" ".join(call[0]) for call in calls if isinstance(call[0], tuple)]
            self.assertEqual(effect.effect, "fetched")
            self.assertEqual(len([call for call in calls if call[0] == "provider"]), 1)
            self.assertEqual(len([call for call in calls if call[0] == "token"]), 1)
            self.assertEqual(sum(" fetch " in f" {item} " for item in commands), 1)
            self.assertFalse(any(" init " in f" {item} " or "replace-all" in item
                                 or " checkout " in f" {item} " for item in commands))

    def test_u3_initialize_execute_then_descriptor_swap_preserves_effect_uncertainty(self):
        tmp, _, _, gateway, _, caps = self.make_u3_gateway()
        with tmp:
            facts = caps.access(project.RepositoryLocator("owner", "repo")).repository
            real = project.cli_runner.run_argv
            swapped = False
            def runner(argv, **kwargs):
                nonlocal swapped
                result = real(argv, **kwargs)
                if not swapped and " init --bare --initial-branch " in f" {' '.join(argv)} ":
                    worktree = Path(facts.worktree)
                    worktree.rename(worktree.with_name("11-executed"))
                    worktree.mkdir(mode=0o700)
                    swapped = True
                return result
            gateway.process_runner = runner
            effect = gateway.initialize_workspace(facts)
            self.assertTrue(swapped)
            self.assertEqual(effect.effect, "uncertain")
            self.assertIn("descriptor_anchor", effect.inspection.process_uncertainty)
            self.assertTrue(any("Initialized empty Git repository" in str(item.get("stdout", ""))
                                for item in effect.process))

    def test_u3_fetch_execute_then_descriptor_swap_preserves_process_evidence(self):
        tmp, _, _, gateway, _, caps = self.make_u3_gateway()
        with tmp:
            facts = caps.access(project.RepositoryLocator("owner", "repo")).repository
            create_workspace_pair(facts)
            swapped = False
            def runner(argv, **kwargs):
                nonlocal swapped
                result = successful_git_result(argv)
                if not swapped and " fetch --prune " in f" {' '.join(argv)} ":
                    worktree = Path(facts.worktree)
                    worktree.rename(worktree.with_name("11-executed"))
                    worktree.mkdir(mode=0o700)
                    swapped = True
                    result["stdout"] = "fetch process executed"
                return result
            gateway.process_runner = runner
            effect = gateway.fetch_workspace(facts)
            self.assertTrue(swapped)
            self.assertEqual(effect.effect, "uncertain")
            self.assertIn("descriptor_anchor", effect.inspection.process_uncertainty)
            self.assertEqual(effect.process[0]["stdout"], "fetch process executed")

    def test_u3_truncated_config_observation_blocks_fetch_before_provider_and_token(self):
        def runner(argv, **kwargs):
            result = successful_git_result(argv)
            if "config --local --null --list" in " ".join(argv):
                result["stdout_truncated"] = True
            return result

        tmp, _, _, gateway, calls, caps = self.make_u3_gateway(process_runner=runner)
        with tmp:
            facts = caps.access(project.RepositoryLocator("owner", "repo")).repository
            create_workspace_pair(facts)
            calls.clear()
            effect = gateway.fetch_workspace(facts)
            self.assertEqual((effect.effect, effect.inspection.process_uncertainty),
                             ("uncertain", ("config",)))
            self.assertFalse(any(call[0] in {"provider", "token"} for call in calls))

    def test_u3_real_initialization_retries_unicode_dotted_default_branch(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            state = root / "state"
            store = registry.ProjectRegistry(root / "projects.db",
                                             workspace_root=root / "worktrees",
                                             state_root=state)
            observed = observation("11", default_branch="release/réléase.1")
            first_init = True

            def runner(argv, **kwargs):
                nonlocal first_init
                result = project.cli_runner.run_argv(argv, **kwargs)
                if first_init and " init --bare --initial-branch " in f" {' '.join(argv)} ":
                    first_init = False
                    return {"state": "timed_out", "exit_code": None, "stdout": "",
                            "stderr": "", "uncertain": True}
                return result

            gateway = project.ProjectGateway(
                store, lambda _: observed, state_root=state, process_runner=runner)
            facts = gateway._transient_facts(observed)
            self.assertEqual(gateway.initialize_workspace(facts).effect, "uncertain")
            effect = gateway.initialize_workspace(facts)
            self.assertEqual(effect.effect, "initialized", repr(effect))
            descriptor = gateway._workspace_descriptor(facts)
            project.host_boundary.validate_external_git_metadata(descriptor)
            self.assertFalse((Path(facts.worktree) / ".git").exists())
            origin = project.TrustedOrigin("W1", "C1")
            gateway.set(origin, candidate("11"), expected_repository_id=None)
            result = project_git.ProjectGit(gateway).run(origin, "11", ["status", "--short"])
            self.assertEqual(result.state, "observed", repr(result))

    def test_u3_alternate_safe_sequences_reach_equivalent_facts(self):
        outcomes = []
        for order in (("workspace", "association", "bookmark"),
                      ("association", "workspace", "bookmark"),
                      ("bookmark", "workspace", "association")):
            with self.subTest(order=order):
                tmp, _, _, gateway, _, caps = self.make_u3_gateway()
                with tmp:
                    origin = project.TrustedOrigin("W1", "C1")
                    access = caps.access(project.RepositoryLocator("owner", "repo"))
                    for action in order:
                        if action == "workspace":
                            gateway.initialize_workspace(access.repository)
                            gateway.fetch_workspace(access.repository)
                        elif action == "association":
                            gateway.set(origin, candidate("11"), expected_repository_id=None)
                        else:
                            caps.bookmarks.add_bookmark(origin, "Project", "https://github.com/owner/repo")
                    route = gateway.show(origin)
                    inspection = gateway.inspect_workspace(access.repository)
                    bookmarks = caps.bookmarks.list_bookmarks(origin)
                    outcomes.append((route.repository_id, inspection.state,
                                     tuple((item.title, item.url)
                                           for item in bookmarks.bookmarks)))
        self.assertEqual(outcomes, [outcomes[0]] * 3)

    def test_u3_dirty_workspace_does_not_block_missing_bookmark_repair(self):
        tmp, _, _, gateway, _, caps = self.make_u3_gateway()
        with tmp:
            origin = project.TrustedOrigin("W1", "C1")
            access = caps.access(project.RepositoryLocator("owner", "repo"))
            gateway.initialize_workspace(access.repository)
            dirty = Path(access.repository.worktree) / "dirty.txt"
            dirty.write_text("local work\n")
            result = caps.bookmarks.add_bookmark(
                origin, "Project", "https://github.com/owner/repo")
            self.assertEqual(result.effect, "added")
            self.assertEqual(dirty.read_text(), "local work\n")

    def test_u3_failed_initialize_stops_and_explicit_reinvocation_is_caller_controlled(self):
        attempts = 0

        def runner(argv, **kwargs):
            nonlocal attempts
            if " init --bare --initial-branch " in f" {' '.join(argv)} ":
                attempts += 1
                if attempts == 1:
                    return {"state": "exited", "exit_code": 1, "stdout": "",
                            "stderr": "failed", "uncertain": False}
                return project.cli_runner.run_argv(argv, **kwargs)
            if "config --local" in " ".join(argv) and "--null --list" not in " ".join(argv):
                return project.cli_runner.run_argv(argv, **kwargs)
            return successful_git_result(argv)

        tmp, _, _, gateway, calls, caps = self.make_u3_gateway(process_runner=runner)
        with tmp:
            facts = caps.access(project.RepositoryLocator("owner", "repo")).repository
            calls.clear()
            first = gateway.initialize_workspace(facts)
            first_commands = [" ".join(call[0]) for call in calls if isinstance(call[0], tuple)]
            self.assertEqual((first.effect, attempts, len(first_commands)), ("failed", 1, 1))
            self.assertEqual([call for call in calls if call[0] == "token"], [])
            second = gateway.initialize_workspace(facts)
            self.assertEqual((second.effect, attempts), ("initialized", 2))

    def test_u3_preparing_candidate_does_not_change_active_snapshot_and_fixed_stays_rejected(self):
        fixed_origin = project.TrustedOrigin("W1", "CFIXED")
        fixed = project.FixedProject(fixed_origin, fixed_facts("99"))

        def access(locator):
            repository_id = "22" if locator.name == "repo" else "99"
            return observation(repository_id, locator.owner, locator.name)

        tmp, _, _, gateway, calls, caps = self.make_u3_gateway(access_reader=access, fixed=(fixed,))
        with tmp:
            origin = project.TrustedOrigin("W1", "C1")
            active = gateway.set(origin, candidate("11", "owner", "active-a"))
            snapshot = gateway.show(origin)
            self.assertEqual(snapshot, active)
            candidate_b = caps.access(project.RepositoryLocator("owner", "repo"))
            gateway.initialize_workspace(candidate_b.repository)
            self.assertEqual(gateway.show(origin), snapshot)
            calls.clear()
            with self.assertRaises(project.FixedProjectError):
                caps.access(project.RepositoryLocator("owner", "fixed"))
            with self.assertRaises(project.FixedProjectError):
                gateway.initialize_workspace(fixed.repository)
            self.assertEqual(gateway.show(origin), snapshot)
            self.assertEqual([call for call in calls if call[0] == "token"], [])
            self.assertEqual([call for call in calls if isinstance(call[0], tuple)], [])

    def test_u3_bookmarks_preserve_duplicates_and_use_exact_current_channel_id(self):
        tmp, _, _, gateway, calls, caps = self.make_u3_gateway()
        with tmp:
            origin = project.TrustedOrigin("W1", "C1")
            url = "https://example.test/same"
            first = caps.bookmarks.add_bookmark(origin, "One", url)
            second = caps.bookmarks.add_bookmark(origin, "Two", url)
            listed = caps.bookmarks.list_bookmarks(origin)
            self.assertEqual([item.url for item in listed.bookmarks], [url, url])
            self.assertNotEqual(first.bookmark_id, second.bookmark_id)
            deleted = caps.bookmarks.delete_bookmark(origin, second.bookmark_id)
            self.assertEqual(deleted.bookmark_id, second.bookmark_id)
            self.assertIn(("delete", {"channel_id": "C1", "bookmark_id": second.bookmark_id}), calls)

    def test_u3_slack_extra_fields_wrong_channel_not_found_and_one_shot_uncertainty(self):
        mode = "extras"

        def slack(operation, payload):
            item = {"id": "B1", "title": payload.get("title", "Repository"), "type": "link",
                    "link": payload.get("link", "https://example.test/repo"),
                    "channel_id": "OTHER" if mode == "wrong_channel" else payload["channel_id"],
                    "date_created": 123, "date_updated": 456, "emoji": ":books:",
                    "icon_url": "https://example.test/icon.png", "entity_id": "E1"}
            if operation == "list":
                return {"ok": True, "bookmarks": [item], "response_metadata": {"next_cursor": ""}}
            if operation == "add":
                return {"ok": True, "bookmark": item, "warning": "accepted_extra_field"}
            return {"ok": False, "error": "not_found", "needed": "bookmarks:write"}

        tmp, _, _, gateway, _, caps = self.make_u3_gateway(bookmark_transport=slack)
        with tmp:
            origin = project.TrustedOrigin("W1", "C1")
            listed = caps.bookmarks.list_bookmarks(origin)
            added = caps.bookmarks.add_bookmark(origin, "Repository", "https://example.test/repo")
            missing = caps.bookmarks.delete_bookmark(origin, "B404")
            self.assertEqual((listed.uncertain, listed.bookmarks[0].bookmark_id), (False, "B1"))
            self.assertEqual((added.effect, added.uncertain), ("added", False))
            self.assertEqual((missing.effect, missing.error, missing.uncertain),
                             ("no_effect", "not_found", False))
            mode = "wrong_channel"
            self.assertTrue(caps.bookmarks.list_bookmarks(origin).uncertain)
            rejected = caps.bookmarks.add_bookmark(origin, "Repository", "https://example.test/repo")
            self.assertEqual((rejected.effect, rejected.uncertain), ("uncertain", True))

        for operation in ("list", "add", "delete"):
            with self.subTest(uncertain_operation=operation):
                attempts = []

                def offline(actual, payload):
                    attempts.append((actual, dict(payload)))
                    raise OSError("offline")

                tmp, _, _, gateway, _, caps = self.make_u3_gateway(bookmark_transport=offline)
                with tmp:
                    origin = project.TrustedOrigin("W1", "C1")
                    if operation == "list":
                        result = caps.bookmarks.list_bookmarks(origin)
                    elif operation == "add":
                        result = caps.bookmarks.add_bookmark(origin, "X", "https://example.test/x")
                    else:
                        result = caps.bookmarks.delete_bookmark(origin, "B1")
                    self.assertTrue(result.uncertain)
                    self.assertEqual(len(attempts), 1)

    def test_u3_slack_false_observations_and_internal_errors_preserve_uncertainty(self):
        responses = {
            "list": {"ok": False, "error": "invalid_auth"},
            "add": {"ok": False, "error": "internal_error"},
            "delete": {"ok": False, "error": "fatal_error"},
        }
        attempts = []

        def slack(operation, payload):
            attempts.append(operation)
            return responses[operation]

        tmp, _, _, gateway, _, caps = self.make_u3_gateway(bookmark_transport=slack)
        with tmp:
            origin = project.TrustedOrigin("W1", "C1")
            self.assertTrue(caps.bookmarks.list_bookmarks(origin).uncertain)
            self.assertEqual(caps.bookmarks.add_bookmark(
                origin, "X", "https://example.test/x").effect, "uncertain")
            self.assertEqual(caps.bookmarks.delete_bookmark(origin, "B1").effect, "uncertain")
            responses["delete"] = {"ok": False, "error": "not_found"}
            missing = caps.bookmarks.delete_bookmark(origin, "B1")
            self.assertEqual((missing.effect, missing.uncertain), ("no_effect", False))
            self.assertEqual(attempts, ["list", "add", "delete", "delete"])

    def test_u3_slack_outage_and_missing_bookmark_do_not_block_repository_effects_or_clear(self):
        tmp, _, db, gateway, _, caps = self.make_u3_gateway(slack_failure=True)
        with tmp:
            origin = project.TrustedOrigin("W1", "C1")
            access = caps.access(project.RepositoryLocator("owner", "repo"))
            self.assertTrue(caps.bookmarks.add_bookmark(origin, "X", "https://example.test/x").uncertain)
            gateway.initialize_workspace(access.repository)
            gateway.set(origin, access.candidate)
            gateway.clear(origin, expected_repository_id="11")
            self.assertIsNone(gateway.show(origin))
            self.assertEqual(gateway.inspect_workspace(access.repository).state, "present")


if __name__ == "__main__":
    unittest.main()
