# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

from pathlib import Path
import os
import sqlite3
import tempfile
import threading
import unittest

from _package import project, registry


def insert_repository(cx: sqlite3.Connection, repository_id: str = "12345", **changes):
    values = dict(alias="causal-discovery", installation_id="67890", owner="peirce-example",
                  name="causal-discovery", worktree="/srv/hermes/project-state/projects/causal-discovery-12345",
                  url="https://github.com/peirce-example/causal-discovery.git", default_branch="main",
                  direct_commit_paths='["*", "**/*"]', task_branch_prefix="hermes/")
    values.update(changes)
    cx.execute(
        "INSERT INTO research_github_repositories VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (repository_id, values["alias"], values["installation_id"], values["owner"], values["name"],
         values["worktree"], values["url"], values["default_branch"], values["direct_commit_paths"],
         values["task_branch_prefix"]),
    )


def set_association(db, workspace_id, channel_id, observed, expected_repository_id=None):
    return db._set_association(
        workspace_id, channel_id, observed.repository_id, observed.installation_id,
        observed.owner, observed.name, observed.url, observed.default_branch,
        expected_repository_id,
    )


def clear_association(db, workspace_id, channel_id, expected_repository_id=None):
    return db._clear_association(workspace_id, channel_id, expected_repository_id)


def repository_row(db, repository_id):
    connection = sqlite3.connect(db.db_path)
    try:
        return connection.execute(
            "SELECT * FROM research_github_repositories WHERE repository_id = ?",
            (repository_id,),
        ).fetchone()
    finally:
        connection.close()


class RegistryTests(unittest.TestCase):
    def make_db(self):
        tmp = tempfile.TemporaryDirectory(dir="/private/tmp")
        root = Path(tmp.name) / "state"
        root.mkdir(mode=0o700)
        db = registry.ProjectRegistry(
            root / "projects.db", workspace_root=Path(tmp.name) / "workspaces",
            state_root=root)
        return tmp, db

    def test_missing_reads_do_not_create_database(self):
        tmp, db = self.make_db()
        with tmp:
            self.assertIsNone(db.active_binding_for_channel("W1", "C1"))
            self.assertEqual(list(db.db_path.parent.iterdir()), [])
            self.assertFalse(hasattr(db, "resolve"))

    def test_explicit_roots_are_bound_once_and_dynamic_paths_are_id_derived(self):
        tmp, db = self.make_db()
        with tmp:
            bound = registry.ProjectRegistry(
                db.db_path, workspace_root="/first/workspaces", state_root="/first/state")
            result = set_association(bound, "W1", "C1", self.observation())
            self.assertEqual(result.repository.worktree, "/first/workspaces/12345")
            self.assertEqual(result.repository.trusted_gitdir, "/first/state/git/12345")

    def test_read_only_uri_escapes_path_metacharacters(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as tmp:
            root = Path(tmp) / "state"
            root.mkdir(mode=0o700)
            for name in ("projects?.db", "projects#.db", "projects%.db"):
                with self.subTest(name=name):
                    db = registry.ProjectRegistry(
                        root / name, workspace_root=Path(tmp) / "workspaces", state_root=root)
                    db._mutation().close()
                    self.assertIsNone(db.active_binding_for_channel("W1", "C1"))
            self.assertEqual({path.name for path in root.iterdir()},
                             {name for name in (
                                 "projects?.db", "projects#.db", "projects%.db",
                                 ".projects?.db.init.lock", ".projects#.db.init.lock",
                                 ".projects%.db.init.lock",
                             )})

    def test_only_new_file_is_initialized(self):
        tmp, db = self.make_db()
        with tmp:
            cx = db._mutation()
            cx.close()
            self.assertEqual(db.db_path.stat().st_mode & 0o777, 0o600)
            self.assertIsNone(db.active_binding_for_channel("W1", "C1"))

    def test_invalid_mutation_leaves_existing_database_byte_identical(self):
        tmp, db = self.make_db()
        with tmp:
            db.db_path.write_bytes(b"not sqlite")
            os.chmod(db.db_path, 0o600)
            before = db.db_path.read_bytes()
            with self.assertRaises(registry.RegistryError):
                db._mutation()
            self.assertEqual(db.db_path.read_bytes(), before)

    def test_unsafe_database_leaf_mode_is_rejected(self):
        tmp, db = self.make_db()
        with tmp:
            db.db_path.write_bytes(b"not sqlite")
            os.chmod(db.db_path, 0o640)
            with self.assertRaises(registry.RegistryUnavailable):
                db.active_binding_for_channel("W1", "C1")

    def test_database_symlink_is_rejected(self):
        tmp, db = self.make_db()
        with tmp:
            target = db.db_path.with_name("real-projects.db")
            target.write_bytes(b"not sqlite")
            os.chmod(target, 0o600)
            db.db_path.symlink_to(target)
            with self.assertRaises(registry.RegistryUnavailable):
                db.active_binding_for_channel("W1", "C1")

    def test_foreign_owned_writable_traversal_ancestor_is_rejected(self):
        foreign_uid = os.getuid() + 1
        item = type("ForeignWritableDirectory", (), {
            "st_mode": registry.stat.S_IFDIR | 0o777,
            "st_uid": foreign_uid,
        })()
        with self.assertRaises(registry.RegistryUnavailable):
            registry.ProjectRegistry._validate_traversal_ancestor(
                Path("/foreign-writable"), item
            )

    def test_foreign_owned_nonwritable_traversal_ancestor_is_rejected(self):
        foreign_uid = os.geteuid() + 1
        item = type("ForeignNonwritableDirectory", (), {
            "st_mode": registry.stat.S_IFDIR | 0o755,
            "st_uid": foreign_uid,
        })()
        with self.assertRaises(registry.RegistryUnavailable):
            registry.ProjectRegistry._validate_traversal_ancestor(
                Path("/foreign-nonwritable"), item
            )

    def test_hardlinked_database_is_rejected(self):
        tmp, db = self.make_db()
        with tmp:
            db.db_path.write_bytes(b"not sqlite")
            os.chmod(db.db_path, 0o600)
            os.link(db.db_path, db.db_path.with_name("projects-copy.db"))
            with self.assertRaises(registry.RegistryUnavailable):
                db.active_binding_for_channel("W1", "C1")

    def test_hardlinked_wal_and_shm_are_rejected(self):
        for suffix in ("-wal", "-shm"):
            with self.subTest(suffix=suffix):
                tmp, db = self.make_db()
                with tmp:
                    db._mutation().close()
                    sidecar = Path(f"{db.db_path}{suffix}")
                    sidecar.write_bytes(b"sidecar")
                    os.chmod(sidecar, 0o600)
                    os.link(sidecar, sidecar.with_name(f"copy{suffix}"))
                    with self.assertRaises(registry.RegistryUnavailable):
                        db.active_binding_for_channel("W1", "C1")

    def test_symlink_and_dangling_sidecars_are_rejected(self):
        for suffix, dangling in (("-wal", False), ("-shm", True)):
            with self.subTest(suffix=suffix, dangling=dangling):
                tmp, db = self.make_db()
                with tmp:
                    db._mutation().close()
                    target = db.db_path.with_name("sidecar-target")
                    if not dangling:
                        target.write_bytes(b"sidecar")
                        os.chmod(target, 0o600)
                    Path(f"{db.db_path}{suffix}").symlink_to(target)
                    with self.assertRaises(registry.RegistryUnavailable):
                        db.active_binding_for_channel("W1", "C1")

    def test_orphan_sidecars_are_rejected(self):
        for suffix in ("-wal", "-shm"):
            with self.subTest(suffix=suffix):
                tmp, db = self.make_db()
                with tmp:
                    sidecar = Path(f"{db.db_path}{suffix}")
                    sidecar.write_bytes(b"sidecar")
                    os.chmod(sidecar, 0o600)
                    with self.assertRaises(registry.RegistryUnavailable):
                        db.active_binding_for_channel("W1", "C1")

    def test_wrong_sidecar_mode_is_rejected(self):
        tmp, db = self.make_db()
        with tmp:
            db._mutation().close()
            sidecar = Path(f"{db.db_path}-wal")
            sidecar.write_bytes(b"sidecar")
            os.chmod(sidecar, 0o640)
            with self.assertRaises(registry.RegistryUnavailable):
                db.active_binding_for_channel("W1", "C1")

    @unittest.skipUnless(os.geteuid() == 0, "changing file owner requires root")
    def test_wrong_sidecar_owner_is_rejected_where_portable(self):
        tmp, db = self.make_db()
        with tmp:
            db._mutation().close()
            sidecar = Path(f"{db.db_path}-wal")
            sidecar.write_bytes(b"sidecar")
            os.chmod(sidecar, 0o600)
            os.chown(sidecar, 1, os.getegid())
            with self.assertRaises(registry.RegistryUnavailable):
                db.active_binding_for_channel("W1", "C1")

    def test_normal_wal_operation_uses_safe_sidecars(self):
        tmp, db = self.make_db()
        with tmp:
            writer = db._mutation()
            try:
                self.assertEqual(writer.execute("PRAGMA journal_mode=WAL").fetchone()[0], "wal")
                insert_repository(writer)
                writer.commit()
                for suffix in ("-wal", "-shm"):
                    item = os.lstat(Path(f"{db.db_path}{suffix}"))
                    self.assertTrue(registry.stat.S_ISREG(item.st_mode))
                    self.assertEqual(item.st_nlink, 1)
                    self.assertEqual(item.st_uid, os.getuid())
                    self.assertEqual(registry.stat.S_IMODE(item.st_mode), 0o600)
                self.assertIsNone(db.active_binding_for_channel("W1", "C1"))
            finally:
                writer.close()

    def test_normal_wal_accepts_sidecars_with_a_different_gid_where_portable(self):
        tmp, db = self.make_db()
        with tmp:
            writer = db._mutation()
            writer.close()
            parent_gid = db.db_path.parent.stat().st_gid
            alternate_gids = [gid for gid in {os.getegid(), *os.getgroups()} if gid != parent_gid]
            for gid in alternate_gids:
                try:
                    os.chown(db.db_path, -1, gid)
                except PermissionError:
                    continue
                break
            else:
                self.skipTest("no permitted group differs from the state directory group")

            writer = db._mutation()
            try:
                self.assertEqual(writer.execute("PRAGMA journal_mode=WAL").fetchone()[0], "wal")
                insert_repository(writer)
                writer.commit()
                sidecars = [os.lstat(Path(f"{db.db_path}{suffix}")) for suffix in ("-wal", "-shm")]
                if any(item.st_gid == db.db_path.stat().st_gid for item in sidecars):
                    self.skipTest("SQLite created sidecars with the main database group")
                self.assertIsNone(db.active_binding_for_channel("W1", "C1"))
            finally:
                writer.close()

    def test_partial_unique_indexes_are_rejected(self):
        tmp, db = self.make_db()
        with tmp:
            cx = db._mutation()
            cx.execute("CREATE UNIQUE INDEX partial_alias ON research_github_repositories(alias) WHERE alias <> ''")
            cx.commit()
            cx.close()
            with self.assertRaises(registry.RegistryError):
                db.active_binding_for_channel("W1", "C1")

    def test_schema_constraints_remain_one_to_one(self):
        tmp, db = self.make_db()
        with tmp:
            cx = db._mutation()
            insert_repository(cx)
            with self.assertRaises(sqlite3.IntegrityError):
                insert_repository(cx, "99999")
            cx.execute("INSERT INTO research_github_bindings VALUES ('W1', 'C1', '12345')")
            with self.assertRaises(sqlite3.IntegrityError):
                cx.execute("INSERT INTO research_github_bindings VALUES ('W2', 'C2', '12345')")
            cx.commit()
            cx.close()

    def test_mutable_provider_facts_are_not_repository_identity(self):
        tmp, db = self.make_db()
        with tmp:
            cx = db._mutation()
            insert_repository(cx)
            cx.commit()
            cx.execute("UPDATE research_github_repositories SET owner = ?, name = ?, url = ? WHERE repository_id = ?",
                       ("renamed-owner", "renamed", "https://example.invalid/renamed.git", "12345"))
            cx.commit()
            cx.close()
            row = repository_row(db, "12345")
            self.assertEqual(row[0], "12345")
            self.assertEqual((row[3], row[4]), ("renamed-owner", "renamed"))

    @staticmethod
    def observation(repository_id="12345", owner="peirce-example", name="causal-discovery", **changes):
        value = dict(repository_id=repository_id, installation_id="67890", owner=owner, name=name,
                     url=f"https://github.com/{owner}/{name}.git", default_branch="main")
        value.update(changes)
        return project.ProviderObservation(**value)

    @staticmethod
    def candidate(repository_id="12345", owner="peirce-example", name="causal-discovery"):
        return project.CanonicalCandidate(owner, name, repository_id)

    def test_compare_and_set_replay_replacement_clear_and_refresh(self):
        tmp, db = self.make_db()
        with tmp:
            first = set_association(db, "W1", "C1", self.observation())
            alias, worktree = first.repository.alias, first.repository.worktree
            replay = set_association(db, "W1", "C1", self.observation(), None)
            self.assertEqual(replay.repository.repository_id, "12345")
            with self.assertRaises(registry.AssociationConflict):
                set_association(db, "W1", "C1", self.observation("12345"), "99999")
            renamed = set_association(
                db, "W1", "C1",
                self.observation("12345", "transferred", "renamed", installation_id="77777"),
                "12345",
            )
            self.assertEqual((renamed.repository.owner, renamed.repository.name), ("transferred", "renamed"))
            self.assertEqual((renamed.repository.alias, renamed.repository.worktree), (alias, worktree))
            clear_association(db, "W1", "C1", "12345")
            self.assertIsNone(db.active_binding_for_channel("W1", "C1"))
            self.assertEqual(repository_row(db, "12345")[5], worktree)

    def test_provider_refreshes_only_provider_facts_and_keeps_local_paths(self):
        tmp, db = self.make_db()
        with tmp:
            first = set_association(db, "W1", "C1", self.observation())
            local = (first.repository.alias, first.repository.worktree,
                     first.repository.trusted_gitdir)
            renamed = set_association(
                db, "W1", "C1",
                self.observation(owner="new-owner", name="new-name", installation_id="77777"),
                "12345",
            )
            self.assertEqual((renamed.repository.owner, renamed.repository.name),
                             ("new-owner", "new-name"))
            self.assertEqual((renamed.repository.alias, renamed.repository.worktree,
                              renamed.repository.trusted_gitdir), local)

    def test_stale_expected_id_leaves_state_unchanged(self):
        tmp, db = self.make_db()
        with tmp:
            set_association(db, "W1", "C1", self.observation())
            before = db.db_path.read_bytes()
            with self.assertRaises(registry.AssociationConflict):
                set_association(db, "W1", "C1", self.observation("99999"), "99999")
            self.assertEqual(db.db_path.read_bytes(), before)

    def test_new_immutable_id_gets_distinct_local_facts_and_repository_uniqueness(self):
        tmp, db = self.make_db()
        with tmp:
            one = set_association(db, "W1", "C1", self.observation())
            two = set_association(db, "W1", "C1", self.observation("99999"), "12345")
            self.assertNotEqual(one.repository.alias, two.repository.alias)
            self.assertNotEqual(one.repository.worktree, two.repository.worktree)
            with self.assertRaises(registry.AssociationConflict):
                set_association(db, "W2", "C2", self.observation("99999"), None)

    def test_concurrent_repository_collision_is_compare_and_set_safe(self):
        tmp, db = self.make_db()
        with tmp:
            db._mutation().close()
            barrier = threading.Barrier(2)
            results = []

            def bind(channel):
                local = registry.ProjectRegistry(
                    db.db_path, workspace_root=db.workspace_root, state_root=db.state_root)
                barrier.wait()
                try:
                    set_association(local, "W1", channel, self.observation(), None)
                    results.append("bound")
                except registry.AssociationConflict:
                    results.append("conflict")

            threads = [threading.Thread(target=bind, args=(f"C{number}",)) for number in (1, 2)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(2)
            self.assertEqual(sorted(results), ["bound", "conflict"])

    def test_concurrent_first_sets_on_distinct_channels_initialize_once(self):
        tmp, db = self.make_db()
        with tmp:
            barrier = threading.Barrier(2)
            results = []

            def bind(channel, repository_id):
                local = registry.ProjectRegistry(
                    db.db_path, workspace_root=db.workspace_root, state_root=db.state_root)
                barrier.wait()
                try:
                    set_association(local, "W1", channel, self.observation(repository_id), None)
                    results.append("bound")
                except Exception as exc:  # pragma: no cover - failure is reported below
                    results.append(type(exc).__name__)

            threads = [threading.Thread(target=bind, args=(f"C{number}", repository_id))
                       for number, repository_id in ((1, "11111"), (2, "22222"))]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(2)
            self.assertEqual(sorted(results), ["bound", "bound"])

    def test_reader_rechecks_when_initializer_starts_after_absent_lock_observation(self):
        tmp, db = self.make_db()
        with tmp:
            schema_entered = threading.Event()
            release_schema = threading.Event()
            start_writer = threading.Event()
            original_create = db._create_schema
            original_lstat = registry.os.lstat
            reader_ident = None
            intercepted = False

            def slow_create(connection):
                schema_entered.set()
                release_schema.wait(2)
                original_create(connection)

            def hooked_lstat(path):
                nonlocal intercepted
                if (threading.get_ident() == reader_ident
                        and Path(path) == db._initialization_lock_path() and not intercepted):
                    intercepted = True
                    start_writer.set()
                    self.assertTrue(schema_entered.wait(2))
                    raise FileNotFoundError(path)
                return original_lstat(path)

            db._create_schema = slow_create
            registry.os.lstat = hooked_lstat
            writer_result = []
            reader_result = []

            def writer():
                self.assertTrue(start_writer.wait(2))
                connection = db._mutation()
                connection.close()
                writer_result.append("done")

            def reader():
                nonlocal reader_ident
                reader_ident = threading.get_ident()
                reader_result.append(db.active_binding_for_channel("W1", "C1"))

            writer_thread = threading.Thread(target=writer)
            reader_thread = threading.Thread(target=reader)
            writer_thread.start()
            reader_thread.start()
            self.assertTrue(schema_entered.wait(2))
            self.assertEqual(reader_result, [])
            release_schema.set()
            writer_thread.join(2)
            reader_thread.join(2)
            registry.os.lstat = original_lstat
            db._create_schema = original_create
            self.assertEqual(writer_result, ["done"])
            self.assertEqual(reader_result, [None])


if __name__ == "__main__":
    unittest.main()
