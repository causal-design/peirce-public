# SPDX-License-Identifier: AGPL-3.0-only
"""Lazy schema-v2 project facts and compare-and-set association registry.

Provider-owned columns remain observations; ``repository_id`` is the only
immutable repository identity.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import re
import sqlite3
import stat
from contextlib import contextmanager
import fcntl
SCHEMA_VERSION = "2"
IDENTITY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
REPO_ID = re.compile(r"^[0-9]+$")
REPO_PART = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")
STICKY_SYSTEM_TEMP_ANCHORS = frozenset({
    Path("/tmp"), Path("/var/tmp"), Path("/private/tmp"), Path("/private/var/tmp"),
})


class RegistryError(Exception):
    """The registry contains invalid facts or cannot answer a read."""


class RegistryUnavailable(RegistryError):
    """The configured database cannot safely be opened."""


class AssociationConflict(RegistryError):
    """A compare-and-set association did not observe its expected identity."""


@dataclass(frozen=True)
class RepositoryFacts:
    """One repository row; provider facts are observations, not identity."""

    repository_id: str
    alias: str
    installation_id: str
    owner: str
    name: str
    worktree: str
    url: str
    default_branch: str
    trusted_gitdir: str


@dataclass(frozen=True)
class BindingFacts:
    """An optional channel association, separate from repository facts."""

    workspace_id: str
    channel_id: str
    repository_id: str


@dataclass(frozen=True)
class RepositoryRead:
    """Repository facts plus an optional, independently decoded binding."""

    repository: RepositoryFacts
    binding: BindingFacts | None = None


class ProjectRegistry:
    """Validate schema-v2 state and provide reads and atomic associations.

    Only a database created by this implementation may receive schema
    initialization. An existing file, including an invalid one, is never
    repaired or populated.
    """

    def __init__(
        self,
        db_path: Path | str,
        *,
        workspace_root: Path | str,
        state_root: Path | str,
    ) -> None:
        self.db_path = Path(db_path)
        self.workspace_root = Path(workspace_root)
        self.state_root = Path(state_root)
        if not self.workspace_root.is_absolute() or not self.state_root.is_absolute():
            raise RegistryUnavailable("project roots must be absolute")

    def _trusted_gitdir(self, repository_id: str) -> str:
        return str(self.state_root / "git" / repository_id)

    @staticmethod
    def _validate_traversal_ancestor(path: Path, item: os.stat_result) -> None:
        if stat.S_ISLNK(item.st_mode) and path in {Path("/tmp"), Path("/var")}:
            try:
                item = os.stat(path)
            except OSError as exc:
                raise RegistryUnavailable("database parent is unavailable") from exc
        if stat.S_ISLNK(item.st_mode) or not stat.S_ISDIR(item.st_mode):
            raise RegistryUnavailable("database parent is unsafe")
        if item.st_uid not in (0, os.geteuid()):
            raise RegistryUnavailable("database parent owner is unsafe")
        mode = stat.S_IMODE(item.st_mode)
        sticky = (path in STICKY_SYSTEM_TEMP_ANCHORS and item.st_uid == 0
                  and bool(item.st_mode & stat.S_ISVTX))
        if mode & 0o022 and not (sticky and bool(mode & 0o002)):
            raise RegistryUnavailable("database parent is not secure")

    @staticmethod
    def _validate_boundary(boundary: os.stat_result) -> None:
        if (not stat.S_ISDIR(boundary.st_mode) or stat.S_ISLNK(boundary.st_mode)
                or boundary.st_uid != os.getuid()
                or stat.S_IMODE(boundary.st_mode) != 0o700):
            raise RegistryUnavailable("database state boundary is unsafe")

    @staticmethod
    def _validate_leaf(leaf: os.stat_result) -> None:
        if (not stat.S_ISREG(leaf.st_mode) or leaf.st_uid != os.getuid()
                or stat.S_IMODE(leaf.st_mode) != 0o600 or leaf.st_nlink != 1):
            raise RegistryUnavailable("database path or mode is unsafe")

    @staticmethod
    def _validate_sidecar(leaf: os.stat_result) -> None:
        if (not stat.S_ISREG(leaf.st_mode) or leaf.st_uid != os.getuid()
                or stat.S_IMODE(leaf.st_mode) != 0o600 or leaf.st_nlink != 1):
            raise RegistryUnavailable("database sidecar is unsafe")

    def _sidecar_paths(self) -> tuple[Path, Path]:
        return (Path(f"{self.db_path}-wal"), Path(f"{self.db_path}-shm"))

    def _validate_db_path(self, *, allow_missing: bool) -> None:
        path = self.db_path
        if not path.is_absolute():
            raise RegistryUnavailable("database path is unsafe")
        current = Path(path.anchor)
        for part in path.parts[1:-1]:
            current /= part
            try:
                item = os.lstat(current)
            except FileNotFoundError:
                continue
            except OSError as exc:
                raise RegistryUnavailable("database parent is unavailable") from exc
            self._validate_traversal_ancestor(current, item)
        try:
            boundary = os.lstat(path.parent)
        except OSError as exc:
            raise RegistryUnavailable("database state boundary is unavailable") from exc
        self._validate_boundary(boundary)
        try:
            leaf = os.lstat(path)
        except FileNotFoundError:
            leaf = None
        except OSError as exc:
            raise RegistryUnavailable("database is unavailable") from exc
        if leaf is not None:
            self._validate_leaf(leaf)
        sidecars_present = False
        for sidecar in self._sidecar_paths():
            try:
                sidecar_leaf = os.lstat(sidecar)
            except FileNotFoundError:
                continue
            except OSError as exc:
                raise RegistryUnavailable("database sidecar is unavailable") from exc
            self._validate_sidecar(sidecar_leaf)
            sidecars_present = True
        if leaf is None:
            if sidecars_present:
                raise RegistryUnavailable("database sidecar is orphaned")
            if not allow_missing:
                raise RegistryUnavailable("database is unavailable")
            return

    def _open_main_descriptor(self, *, writable: bool) -> tuple[int, os.stat_result]:
        """Bracket sqlite3.connect with no-follow inode checks.

        Python sqlite3 cannot bind its WAL-capable connection to this fd, so
        trusted parents must not have a hostile same-UID namespace swapper.
        """
        try:
            fd = os.open(
                self.db_path,
                (os.O_RDWR if writable else os.O_RDONLY) | os.O_NOFOLLOW,
            )
            item = os.fstat(fd)
            named = os.lstat(self.db_path)
            self._validate_leaf(item)
            self._validate_leaf(named)
            if (named.st_dev, named.st_ino) != (item.st_dev, item.st_ino):
                raise RegistryUnavailable("database path changed while opening")
            return fd, item
        except RegistryError:
            if 'fd' in locals():
                os.close(fd)
            raise
        except OSError as exc:
            if 'fd' in locals():
                os.close(fd)
            raise RegistryUnavailable("database is unavailable") from exc

    def _revalidate_open_main(self, pinned: os.stat_result) -> None:
        self._validate_db_path(allow_missing=False)
        named = os.lstat(self.db_path)
        if (named.st_dev, named.st_ino) != (pinned.st_dev, pinned.st_ino):
            raise RegistryUnavailable("database path changed while opening")

    def _read_connection_unlocked(self) -> sqlite3.Connection | None:
        self._validate_db_path(allow_missing=True)
        try:
            leaf = os.lstat(self.db_path)
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise RegistryUnavailable("database is unavailable") from exc
        self._validate_leaf(leaf)
        connection: sqlite3.Connection | None = None
        fd: int | None = None
        try:
            fd, pinned = self._open_main_descriptor(writable=False)
            connection = sqlite3.connect(
                f"{self.db_path.absolute().as_uri()}?mode=ro", uri=True, timeout=5.0
            )
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            self._revalidate_open_main(pinned)
            self._validate_schema(connection)
            self._revalidate_open_main(pinned)
            return connection
        except RegistryError:
            if connection is not None:
                connection.close()
            raise
        except (OSError, sqlite3.Error) as exc:
            if connection is not None:
                connection.close()
            raise RegistryUnavailable("database is unavailable") from exc
        finally:
            if fd is not None:
                os.close(fd)

    def _read_connection(self) -> sqlite3.Connection | None:
        """Read without creating either a database or an initialization lock."""
        self._validate_db_path(allow_missing=True)
        lock_path = self._initialization_lock_path()
        while True:
            try:
                os.lstat(lock_path)
            except FileNotFoundError:
                try:
                    os.lstat(self.db_path)
                except FileNotFoundError:
                    # Recheck the lock after the missing-DB observation. If a
                    # writer started in between, wait for its schema instead of
                    # opening the newly visible empty file.
                    try:
                        os.lstat(lock_path)
                    except FileNotFoundError:
                        try:
                            os.lstat(self.db_path)
                        except FileNotFoundError:
                            return None
                        except OSError as exc:
                            raise RegistryUnavailable("database is unavailable") from exc
                        continue
                    except OSError as exc:
                        raise RegistryUnavailable("database initialization lock is unavailable") from exc
                    continue
                except OSError as exc:
                    raise RegistryUnavailable("database is unavailable") from exc
                # A first-use writer creates the initialization lock before the
                # database file. Recheck after seeing the database so a reader
                # cannot open the file between creation and schema commit.
                try:
                    os.lstat(lock_path)
                except FileNotFoundError:
                    return self._read_connection_unlocked()
                except OSError as exc:
                    raise RegistryUnavailable("database initialization lock is unavailable") from exc
                continue
            except OSError as exc:
                raise RegistryUnavailable("database initialization lock is unavailable") from exc
            with self._initialization_lock(create=False):
                return self._read_connection_unlocked()

    def _initialization_lock_path(self) -> Path:
        return self.db_path.with_name(f".{self.db_path.name}.init.lock")

    @contextmanager
    def _initialization_lock(self, *, create: bool = True):
        """Serialize first-use creation and keep readers out of half a schema."""
        self._validate_db_path(allow_missing=True)
        path = self._initialization_lock_path()
        fd: int | None = None
        try:
            flags = os.O_RDWR | os.O_NOFOLLOW
            if create:
                flags |= os.O_CREAT
            try:
                fd = os.open(path, flags, 0o600)
            except FileNotFoundError:
                if not create:
                    yield
                    return
                raise
            item = os.fstat(fd)
            named = os.lstat(path)
            if (not stat.S_ISREG(item.st_mode) or item.st_uid != os.getuid()
                    or stat.S_IMODE(item.st_mode) != 0o600
                    or stat.S_ISLNK(named.st_mode)
                    or (named.st_dev, named.st_ino) != (item.st_dev, item.st_ino)):
                raise RegistryUnavailable("database initialization lock is unsafe")
            with os.fdopen(fd, "a+") as handle:
                fd = None
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
                try:
                    self._validate_db_path(allow_missing=True)
                    yield
                finally:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        except RegistryError:
            raise
        except (OSError, ValueError) as exc:
            raise RegistryUnavailable("database initialization lock is unavailable") from exc
        finally:
            if fd is not None:
                os.close(fd)

    def _mutation(self) -> sqlite3.Connection:
        """Open the future mutation seam without repairing existing files."""
        with self._initialization_lock():
            connection: sqlite3.Connection | None = None
            fd: int | None = None
            created = False
            try:
                self._validate_db_path(allow_missing=True)
                try:
                    os.lstat(self.db_path)
                except FileNotFoundError:
                    fd = os.open(self.db_path, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                    created = True
                if fd is None:
                    fd, pinned = self._open_main_descriptor(writable=True)
                else:
                    pinned = os.fstat(fd)
                    self._validate_leaf(pinned)
                connection = sqlite3.connect(self.db_path, timeout=5.0)
                connection.row_factory = sqlite3.Row
                connection.execute("PRAGMA foreign_keys = ON")
                self._revalidate_open_main(pinned)
                if created:
                    self._create_schema(connection)
                    connection.commit()
                self._validate_schema(connection)
                self._revalidate_open_main(pinned)
                return connection
            except RegistryError:
                if connection is not None:
                    connection.close()
                raise
            except (OSError, sqlite3.Error) as exc:
                if connection is not None:
                    connection.close()
                raise RegistryUnavailable("database is unavailable") from exc
            finally:
                if fd is not None:
                    os.close(fd)

    @staticmethod
    def _create_schema(connection: sqlite3.Connection) -> None:
        connection.executescript(
            """
            CREATE TABLE research_github_meta (
                key TEXT PRIMARY KEY, value TEXT NOT NULL
            );
            INSERT INTO research_github_meta(key, value)
                VALUES ('schema_version', '2');
            CREATE TABLE research_github_repositories (
                repository_id TEXT PRIMARY KEY, alias TEXT NOT NULL UNIQUE,
                installation_id TEXT NOT NULL, owner TEXT NOT NULL, name TEXT NOT NULL,
                worktree TEXT NOT NULL, url TEXT NOT NULL, default_branch TEXT NOT NULL,
                direct_commit_paths TEXT NOT NULL, task_branch_prefix TEXT NOT NULL
            );
            CREATE TABLE research_github_bindings (
                workspace_id TEXT NOT NULL, channel_id TEXT NOT NULL,
                repository_id TEXT NOT NULL,
                PRIMARY KEY (workspace_id, channel_id), UNIQUE (repository_id),
                FOREIGN KEY (repository_id) REFERENCES research_github_repositories(repository_id)
                    ON UPDATE NO ACTION ON DELETE NO ACTION
            );
            """
        )

    @staticmethod
    def _validate_schema(connection: sqlite3.Connection, *, expected_version: str = SCHEMA_VERSION) -> None:
        expected_columns = {
            "research_github_meta": [("key", "TEXT", 0, None, 1), ("value", "TEXT", 1, None, 0)],
            "research_github_repositories": [
                ("repository_id", "TEXT", 0, None, 1), ("alias", "TEXT", 1, None, 0),
                ("installation_id", "TEXT", 1, None, 0), ("owner", "TEXT", 1, None, 0),
                ("name", "TEXT", 1, None, 0), ("worktree", "TEXT", 1, None, 0),
                ("url", "TEXT", 1, None, 0), ("default_branch", "TEXT", 1, None, 0),
                ("direct_commit_paths", "TEXT", 1, None, 0), ("task_branch_prefix", "TEXT", 1, None, 0),
            ],
            "research_github_bindings": [
                ("workspace_id", "TEXT", 1, None, 1), ("channel_id", "TEXT", 1, None, 2),
                ("repository_id", "TEXT", 1, None, 0),
            ],
        }
        try:
            tables = {row[0] for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )}
            if tables != set(expected_columns):
                raise RegistryError("registry schema is incomplete")
            version = connection.execute(
                "SELECT value FROM research_github_meta WHERE key = 'schema_version'"
            ).fetchone()
            if version is None or version[0] != expected_version:
                raise RegistryError("registry schema version is unsupported")
            for table, expected in expected_columns.items():
                actual = [(row[1], row[2], row[3], row[4], row[5])
                          for row in connection.execute(f"PRAGMA table_info({table})")]
                if actual != expected:
                    raise RegistryError("registry schema is invalid")
            if connection.execute("PRAGMA foreign_keys").fetchone()[0] != 1:
                raise RegistryError("registry foreign keys are disabled")
            foreign = list(connection.execute("PRAGMA foreign_key_list(research_github_bindings)"))
            if len(foreign) != 1 or tuple(foreign[0][2:]) != (
                    "research_github_repositories", "repository_id", "repository_id",
                    "NO ACTION", "NO ACTION", "NONE"):
                raise RegistryError("registry foreign-key constraints are missing")
            for table, expected in {
                "research_github_meta": ["key"],
                "research_github_repositories": ["repository_id"],
                "research_github_bindings": ["workspace_id", "channel_id"],
            }.items():
                info = [row[1:6] for row in connection.execute(f"PRAGMA table_info({table})") if row[5] > 0]
                if [row[0] for row in sorted(info, key=lambda row: row[4])] != expected:
                    raise RegistryError("registry primary keys are invalid")

            def unique_indexes(table: str) -> list[tuple[list[str], int, str]]:
                indexes = []
                for row in connection.execute(f"PRAGMA index_list({table})"):
                    if row[2] and row[3] != "pk":
                        indexes.append((
                            [column[2] for column in connection.execute(f"PRAGMA index_info('{row[1]}')")],
                            row[4], row[3],
                        ))
                return indexes

            binding_indexes = unique_indexes("research_github_bindings")
            repository_indexes = unique_indexes("research_github_repositories")
            if binding_indexes != [(["repository_id"], 0, "u")]:
                raise RegistryError("registry binding uniqueness is missing or partial")
            if repository_indexes != [(["alias"], 0, "u")]:
                raise RegistryError("registry repository uniqueness is missing or partial")
            if connection.execute(
                    "SELECT repository_id FROM research_github_bindings "
                    "GROUP BY repository_id HAVING COUNT(*) > 1").fetchone():
                raise RegistryError("registry binding uniqueness is invalid")
        except RegistryError:
            raise
        except sqlite3.Error as exc:
            raise RegistryError("registry schema is invalid") from exc

    @staticmethod
    def _validate_identity(value: str, *, numeric: bool = False) -> None:
        if not isinstance(value, str) or not (REPO_ID if numeric else IDENTITY).fullmatch(value):
            raise RegistryError("registry identity is invalid")

    def _facts(self, row: sqlite3.Row) -> RepositoryFacts:
        try:
            self._validate_identity(row["repository_id"], numeric=True)
            self._validate_identity(row["installation_id"], numeric=True)
            facts = RepositoryFacts(
                row["repository_id"], row["alias"], row["installation_id"], row["owner"],
                row["name"], row["worktree"], row["url"], row["default_branch"],
                self._trusted_gitdir(row["repository_id"]),
            )
            self.validate_repository_facts(facts)
            return facts
        except (KeyError, TypeError, ValueError, RegistryError) as exc:
            if isinstance(exc, RegistryError):
                raise
            raise RegistryError("registry repository facts are invalid") from exc

    @classmethod
    def validate_repository_facts(cls, facts: RepositoryFacts) -> RepositoryFacts:
        """Apply the same closed local-facts validation to every route."""
        if not isinstance(facts, RepositoryFacts):
            raise RegistryError("registry repository facts are invalid")
        try:
            cls._validate_identity(facts.repository_id, numeric=True)
            cls._validate_identity(facts.installation_id, numeric=True)
            if (not isinstance(facts.alias, str) or not IDENTITY.fullmatch(facts.alias)
                    or not REPO_PART.fullmatch(facts.owner)
                    or not REPO_PART.fullmatch(facts.name)
                    or not isinstance(facts.worktree, str)
                    or not Path(facts.worktree).is_absolute()
                    or not isinstance(facts.trusted_gitdir, str)
                     or not Path(facts.trusted_gitdir).is_absolute()
                     or not isinstance(facts.url, str) or not facts.url
                     or not isinstance(facts.default_branch, str) or not facts.default_branch):
                raise ValueError
        except (TypeError, ValueError, RegistryError) as exc:
            if isinstance(exc, RegistryError):
                raise
            raise RegistryError("registry repository facts are invalid") from exc
        return facts

    @staticmethod
    def _select_repository(connection: sqlite3.Connection, repository_id: str) -> sqlite3.Row | None:
        return connection.execute(
            "SELECT * FROM research_github_repositories WHERE repository_id = ?", (repository_id,)
        ).fetchone()

    def active_binding_for_channel(self, workspace_id: str, channel_id: str) -> RepositoryRead | None:
        self._validate_identity(workspace_id)
        self._validate_identity(channel_id)
        connection = self._read_connection()
        if connection is None:
            return None
        try:
            row = connection.execute(
                "SELECT r.*, b.workspace_id AS binding_workspace_id, "
                "b.channel_id AS binding_channel_id, b.repository_id AS binding_repository_id "
                "FROM research_github_repositories r JOIN research_github_bindings b "
                "ON b.repository_id = r.repository_id WHERE b.workspace_id = ? AND b.channel_id = ?",
                (workspace_id, channel_id),
            ).fetchone()
            if row is None:
                return None
            facts = self._facts(row)
            binding = BindingFacts(
                row["binding_workspace_id"], row["binding_channel_id"], row["binding_repository_id"]
            )
            self._validate_identity(binding.workspace_id)
            self._validate_identity(binding.channel_id)
            self._validate_identity(binding.repository_id, numeric=True)
            return RepositoryRead(facts, binding)
        except RegistryError:
            raise
        except sqlite3.Error as exc:
            raise RegistryError("channel binding lookup failed") from exc
        finally:
            connection.close()

    @staticmethod
    def _mutation_facts(
        repository_id: str,
        installation_id: str,
        owner: str,
        name: str,
        url: str,
        default_branch: str,
    ) -> dict[str, str]:
        if (not REPO_ID.fullmatch(repository_id)
                or not REPO_ID.fullmatch(installation_id)
                or not REPO_PART.fullmatch(owner)
                or not REPO_PART.fullmatch(name)
                or not url or not default_branch):
            raise RegistryError("provider observation is invalid")
        return {
            "repository_id": repository_id, "installation_id": installation_id,
            "owner": owner, "name": name, "url": url, "default_branch": default_branch,
        }

    def _stable_local_facts(self, repository_id: str) -> tuple[str, str, str]:
        alias = f"repository-{repository_id}"
        return alias, str(self.workspace_root / repository_id), self._trusted_gitdir(repository_id)

    @staticmethod
    def _expected_id(expected_repository_id: str | None) -> str | None:
        if expected_repository_id is not None:
            ProjectRegistry._validate_identity(expected_repository_id, numeric=True)
        return expected_repository_id

    def _missing_database_conflict(self, expected_repository_id: str | None) -> None:
        """Keep stale compare-and-set calls read-only on first use."""
        self._validate_db_path(allow_missing=True)
        if not self.db_path.exists() and expected_repository_id is not None:
            raise AssociationConflict("association has changed")

    def _set_association(
        self,
        workspace_id: str,
        channel_id: str,
        repository_id: str,
        installation_id: str,
        owner: str,
        name: str,
        url: str,
        default_branch: str,
        expected_repository_id: str | None = None,
    ) -> RepositoryRead:
        """Compare-and-set one channel association and refresh one repository.

        This is deliberately the only SQLite transaction used by the gateway's
        association ``set`` operation.  Provider facts are refreshed in that
        transaction; ID-derived local facts are only chosen on first insert.
        """
        self._validate_identity(workspace_id)
        self._validate_identity(channel_id)
        expected_repository_id = self._expected_id(expected_repository_id)
        facts = self._mutation_facts(
            repository_id, installation_id, owner, name, url, default_branch
        )
        repository_id = facts["repository_id"]
        self._missing_database_conflict(expected_repository_id)
        connection = self._mutation()
        try:
            connection.execute("BEGIN IMMEDIATE")
            current = connection.execute(
                "SELECT repository_id FROM research_github_bindings "
                "WHERE workspace_id = ? AND channel_id = ?", (workspace_id, channel_id)
            ).fetchone()
            current_id = current[0] if current is not None else None
            if current_id != expected_repository_id and current_id != repository_id:
                raise AssociationConflict("association has changed")
            # A current candidate is an exact replay only when the expected
            # identity is absent or names that same candidate.  Otherwise the
            # caller is stale even though the candidate happens to be current.
            if current_id == repository_id and expected_repository_id not in (None, repository_id):
                raise AssociationConflict("association has changed")

            existing = self._select_repository(connection, repository_id)
            if existing is None:
                alias, worktree, _ = self._stable_local_facts(repository_id)
                connection.execute(
                    "INSERT INTO research_github_repositories "
                    "(repository_id, alias, installation_id, owner, name, worktree, url, "
                    "default_branch, direct_commit_paths, task_branch_prefix) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (repository_id, alias, facts["installation_id"], facts["owner"], facts["name"],
                      worktree, facts["url"], facts["default_branch"], "[]", "hermes/"),
                )
            else:
                # Only provider-owned observations change on re-observation.
                connection.execute(
                    "UPDATE research_github_repositories SET installation_id = ?, owner = ?, name = ?, "
                    "url = ?, default_branch = ? "
                    "WHERE repository_id = ?",
                    (facts["installation_id"], facts["owner"], facts["name"], facts["url"],
                      facts["default_branch"], repository_id),
                )
            if current_id != repository_id:
                connection.execute(
                    "INSERT INTO research_github_bindings(workspace_id, channel_id, repository_id) "
                    "VALUES (?, ?, ?) ON CONFLICT(workspace_id, channel_id) DO UPDATE SET repository_id = excluded.repository_id",
                    (workspace_id, channel_id, repository_id),
                )
            connection.commit()
            row = connection.execute(
                "SELECT r.*, b.workspace_id AS binding_workspace_id, "
                "b.channel_id AS binding_channel_id, b.repository_id AS binding_repository_id "
                "FROM research_github_repositories r JOIN research_github_bindings b "
                "ON b.repository_id = r.repository_id WHERE b.workspace_id = ? AND b.channel_id = ?",
                (workspace_id, channel_id),
            ).fetchone()
            if row is None:
                raise RegistryError("association result is missing")
            return RepositoryRead(
                self._facts(row),
                BindingFacts(workspace_id, channel_id, repository_id),
            )
        except AssociationConflict:
            connection.rollback()
            raise
        except sqlite3.IntegrityError as exc:
            connection.rollback()
            raise AssociationConflict("association uniqueness conflict") from exc
        except (RegistryError, sqlite3.Error):
            connection.rollback()
            raise
        finally:
            connection.close()

    def _clear_association(
        self,
        workspace_id: str,
        channel_id: str,
        expected_repository_id: str | None = None,
    ) -> BindingFacts | None:
        """Compare-and-set delete of a binding; repository facts are retained."""
        self._validate_identity(workspace_id)
        self._validate_identity(channel_id)
        expected_repository_id = self._expected_id(expected_repository_id)
        self._validate_db_path(allow_missing=True)
        if not self.db_path.exists():
            if expected_repository_id is None:
                return None
            raise AssociationConflict("association has changed")
        connection = self._mutation()
        try:
            connection.execute("BEGIN IMMEDIATE")
            current = connection.execute(
                "SELECT repository_id FROM research_github_bindings "
                "WHERE workspace_id = ? AND channel_id = ?", (workspace_id, channel_id)
            ).fetchone()
            current_id = current[0] if current is not None else None
            if current_id != expected_repository_id:
                raise AssociationConflict("association has changed")
            if current_id is not None:
                connection.execute(
                    "DELETE FROM research_github_bindings WHERE workspace_id = ? AND channel_id = ?",
                    (workspace_id, channel_id),
                )
            connection.commit()
            return BindingFacts(workspace_id, channel_id, current_id) if current_id else None
        except AssociationConflict:
            connection.rollback()
            raise
        except sqlite3.Error:
            connection.rollback()
            raise
        finally:
            connection.close()


__all__ = [
    "ProjectRegistry", "RegistryError", "RegistryUnavailable", "AssociationConflict", "RepositoryFacts",
    "BindingFacts", "RepositoryRead", "SCHEMA_VERSION",
]
