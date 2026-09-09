# SPDX-License-Identifier: AGPL-3.0-only
"""Host-owned boundaries for independent project-gateway capabilities.

U1 supports one layout only: a real worktree and a real external Git
directory, each directly beneath a configured, gateway-owned parent.  The
module publishes no provider effects and contains no workflow state.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
import base64
import fcntl
import hashlib
import os
from pathlib import Path
import re
import stat
import json
import time
from typing import Any, Callable, Iterator, Mapping, Sequence
from urllib.parse import urlparse


GIT_BIN = "/usr/bin/git"
FIXED_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"
REPOSITORY_ID = re.compile(r"^[0-9]+$")
IDENTITY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
GITHUB_REPO_PART = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")
SYSTEM_TEMP_ALIASES = frozenset({Path("/tmp"), Path("/var")})


class BoundaryError(ValueError):
    """A categorical identity, path, credential, or process boundary failed."""


def is_canonical_github_origin(value: Any) -> bool:
    """Recognize an uncredentialed canonical GitHub clone URL."""
    if not isinstance(value, str):
        return False
    parsed = urlparse(value)
    parts = parsed.path.removeprefix("/").split("/")
    if len(parts) != 2 or not parts[1].endswith(".git"):
        return False
    owner, name = parts[0], parts[1][:-4]
    return (parsed.scheme == "https" and parsed.hostname == "github.com"
            and parsed.port is None and not parsed.username and not parsed.password
            and not parsed.params and not parsed.query and not parsed.fragment
            and parsed.path == f"/{owner}/{name}.git"
            and bool(GITHUB_REPO_PART.fullmatch(owner))
            and bool(GITHUB_REPO_PART.fullmatch(name)))


@dataclass(frozen=True)
class RepositoryDescriptor:
    """Immutable repository ID and the approved external-metadata path pair."""

    repository_id: str
    worktree: Path
    trusted_gitdir: Path
    worktree_parent: Path
    gitdir_parent: Path
    owner: str = ""
    name: str = ""


def _identity(value: str, *, numeric: bool = False) -> None:
    if not isinstance(value, str) or not (REPOSITORY_ID if numeric else IDENTITY).fullmatch(value):
        raise BoundaryError("identity is invalid")


def path_is_contaminated(path: Path) -> bool:
    return path.is_symlink() or path.exists()


def assert_real_owned_parent(path: Path, *, create: bool = False) -> None:
    """Reject symlink traversal and secure a gateway-owned directory boundary."""
    path = Path(path)
    if not path.is_absolute():
        raise BoundaryError("trusted path must be absolute")
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        try:
            item = os.lstat(current)
        except FileNotFoundError:
            if not create:
                raise BoundaryError("trusted path is unavailable")
            try:
                current.mkdir(mode=0o700)
                os.chmod(current, 0o700)
            except FileExistsError:
                # Another first-use operation may have created the same secure
                # boundary after our lstat. Validate its result below.
                pass
            item = os.lstat(current)
        except OSError as exc:
            raise BoundaryError("trusted path is unavailable") from exc
        if stat.S_ISLNK(item.st_mode) and current in SYSTEM_TEMP_ALIASES:
            try:
                item = os.stat(current)
            except OSError as exc:
                raise BoundaryError("trusted path is unavailable") from exc
        if stat.S_ISLNK(item.st_mode) or not stat.S_ISDIR(item.st_mode):
            raise BoundaryError("trusted path contains unsafe traversal")
        if current == path and (item.st_uid != os.getuid() or stat.S_IMODE(item.st_mode) != 0o700):
            raise BoundaryError("trusted path is not gateway-owned")


def _validate_configured_parent(path: Path) -> os.stat_result:
    try:
        item = os.lstat(path)
    except OSError as exc:
        raise BoundaryError("configured parent is unavailable") from exc
    if (stat.S_ISLNK(item.st_mode) or not stat.S_ISDIR(item.st_mode)
            or item.st_uid != os.getuid() or stat.S_IMODE(item.st_mode) != 0o700):
        raise BoundaryError("configured parent is unsafe")
    return item


def validate_descriptor_path(descriptor: RepositoryDescriptor) -> None:
    """Validate the external-metadata layout without following replacements."""
    if not isinstance(descriptor, RepositoryDescriptor):
        raise BoundaryError("repository descriptor is invalid")
    _identity(descriptor.repository_id, numeric=True)
    if any(not isinstance(value, (str, Path)) for value in (
            descriptor.worktree, descriptor.trusted_gitdir,
            descriptor.worktree_parent, descriptor.gitdir_parent)):
        raise BoundaryError("repository descriptor paths are invalid")
    worktree = Path(descriptor.worktree)
    gitdir = Path(descriptor.trusted_gitdir)
    worktree_parent = Path(descriptor.worktree_parent)
    gitdir_parent = Path(descriptor.gitdir_parent)
    if (not worktree.is_absolute() or worktree_parent != worktree.parent
            or worktree.is_symlink() or not worktree.is_dir()):
        raise BoundaryError("worktree path is unsafe")
    if (not gitdir.is_absolute() or gitdir_parent != gitdir.parent
            or gitdir.is_symlink() or not gitdir.is_dir()):
        raise BoundaryError("external Git metadata is unavailable")
    _validate_configured_parent(worktree_parent)
    _validate_configured_parent(gitdir_parent)
    if path_is_contaminated(worktree / ".git"):
        raise BoundaryError("embedded Git metadata is not supported")
    assert_real_owned_parent(worktree_parent)
    assert_real_owned_parent(gitdir_parent)
    assert_real_owned_parent(worktree)
    assert_real_owned_parent(gitdir)
    worktree_resolved = worktree.resolve()
    gitdir_resolved = gitdir.resolve()
    if worktree_resolved == gitdir_resolved:
        raise BoundaryError("external Git metadata overlaps worktree")
    for outer, inner, message in (
        (worktree_resolved, gitdir_resolved, "external Git metadata is inside worktree"),
        (gitdir_resolved, worktree_resolved, "worktree is inside external Git metadata"),
    ):
        try:
            inner.relative_to(outer)
        except ValueError:
            continue
        raise BoundaryError(message)


def validate_external_git_metadata(descriptor: RepositoryDescriptor) -> None:
    """Validate the sole supported external Git metadata layout."""
    validate_descriptor_path(descriptor)


class DescriptorAnchor:
    """Pin configured parents and children and verify their names and metadata.

    On macOS Git cannot consume inherited directory descriptors, so the gateway
    uses verified names while retaining nofollow descriptors and checking before
    and after execution. Hostile concurrent execution as the gateway UID is
    outside this local-first threat model; this does not prevent swap-and-restore.
    """

    def __init__(self, descriptor: RepositoryDescriptor) -> None:
        self.descriptor = descriptor
        self.worktree_parent_fd: int | None = None
        self.worktree_fd: int | None = None
        self.gitdir_parent_fd: int | None = None
        self.gitdir_fd: int | None = None
        self.worktree_fdpath: str | None = None
        self.gitdir_fdpath: str | None = None
        self._uses_procfs_paths = False
        self._identities: dict[str, tuple[int, int]] = {}

    @staticmethod
    def _proc_fdpath(fd: int) -> str | None:
        """Return Git's supported inherited-directory path, never /dev/fd."""
        candidate = f"/proc/self/fd/{fd}"
        return candidate if Path(candidate).is_dir() else None

    def __enter__(self) -> "DescriptorAnchor":
        validate_external_git_metadata(self.descriptor)
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        try:
            self.worktree_parent_fd = os.open(self.descriptor.worktree_parent, flags)
            self.worktree_fd = os.open(self.descriptor.worktree.name, flags, dir_fd=self.worktree_parent_fd)
            self.gitdir_parent_fd = os.open(self.descriptor.gitdir_parent, flags)
            self.gitdir_fd = os.open(self.descriptor.trusted_gitdir.name, flags, dir_fd=self.gitdir_parent_fd)
            for key, fd in {
                "worktree_parent": self.worktree_parent_fd, "worktree": self.worktree_fd,
                "gitdir_parent": self.gitdir_parent_fd, "gitdir": self.gitdir_fd,
            }.items():
                assert fd is not None
                item = os.fstat(fd)
                self._identities[key] = (item.st_dev, item.st_ino)
            worktree_fdpath = self._proc_fdpath(self.worktree_fd)
            gitdir_fdpath = self._proc_fdpath(self.gitdir_fd)
            if (worktree_fdpath is None) != (gitdir_fdpath is None):
                raise BoundaryError("descriptor FD paths are inconsistent")
            self._uses_procfs_paths = worktree_fdpath is not None
            self.worktree_fdpath = worktree_fdpath or str(self.descriptor.worktree)
            self.gitdir_fdpath = gitdir_fdpath or str(self.descriptor.trusted_gitdir)
            self.verify()
            return self
        except BaseException:
            self.close()
            raise

    @staticmethod
    def _same_path(path: Path, expected: tuple[int, int]) -> bool:
        item = os.lstat(path)
        return (item.st_dev, item.st_ino) == expected and stat.S_ISDIR(item.st_mode)

    def verify(self) -> None:
        if any(fd is None for fd in (
                self.worktree_parent_fd, self.worktree_fd, self.gitdir_parent_fd, self.gitdir_fd)):
            raise BoundaryError("descriptor anchor is not open")
        try:
            paths = {
                "worktree_parent": self.descriptor.worktree_parent,
                "worktree": self.descriptor.worktree,
                "gitdir_parent": self.descriptor.gitdir_parent,
                "gitdir": self.descriptor.trusted_gitdir,
            }
            fds = {
                "worktree_parent": self.worktree_parent_fd, "worktree": self.worktree_fd,
                "gitdir_parent": self.gitdir_parent_fd, "gitdir": self.gitdir_fd,
            }
            for key, fd in fds.items():
                assert fd is not None
                item = os.fstat(fd)
                if ((item.st_dev, item.st_ino) != self._identities[key]
                        or not stat.S_ISDIR(item.st_mode)
                        or not self._same_path(paths[key], self._identities[key])):
                    raise BoundaryError("descriptor path changed")
            worktree_entry = os.stat(self.descriptor.worktree.name, dir_fd=self.worktree_parent_fd,
                                     follow_symlinks=False)
            gitdir_entry = os.stat(self.descriptor.trusted_gitdir.name, dir_fd=self.gitdir_parent_fd,
                                   follow_symlinks=False)
            if ((worktree_entry.st_dev, worktree_entry.st_ino) != self._identities["worktree"]
                    or (gitdir_entry.st_dev, gitdir_entry.st_ino) != self._identities["gitdir"]):
                raise BoundaryError("descriptor path changed")
            self._verify_git_metadata()
        except OSError as exc:
            raise BoundaryError("descriptor path changed") from exc

    @staticmethod
    def _entry(fd: int, name: str) -> os.stat_result | None:
        try:
            return os.stat(name, dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            return None

    @staticmethod
    def _open_directory(fd: int, name: str) -> int:
        return os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)

    def _verify_git_metadata(self) -> None:
        """Reject Git metadata capable of redirecting effects outside the pinned gitdir."""
        assert self.gitdir_fd is not None
        self._verify_gitdir_tree(self.gitdir_fd)
        if self._entry(self.gitdir_fd, "commondir") is not None:
            raise BoundaryError("external Git metadata redirection is unsafe")
        info = self._entry(self.gitdir_fd, "info")
        if info is not None:
            if not stat.S_ISDIR(info.st_mode):
                raise BoundaryError("external Git metadata entry is unsafe")
            info_fd = self._open_directory(self.gitdir_fd, "info")
            try:
                if self._entry(info_fd, "grafts") is not None:
                    raise BoundaryError("Git graft metadata is unsafe")
            finally:
                os.close(info_fd)
        for name, expected in (("config", stat.S_ISREG), ("HEAD", stat.S_ISREG),
                               ("objects", stat.S_ISDIR), ("refs", stat.S_ISDIR)):
            item = self._entry(self.gitdir_fd, name)
            if item is not None and not expected(item.st_mode):
                raise BoundaryError("external Git metadata entry is unsafe")
        refs = self._entry(self.gitdir_fd, "refs")
        if refs is not None:
            refs_fd = self._open_directory(self.gitdir_fd, "refs")
            try:
                if self._entry(refs_fd, "replace") is not None:
                    raise BoundaryError("Git replacement metadata is unsafe")
            finally:
                os.close(refs_fd)

        objects = self._entry(self.gitdir_fd, "objects")
        if objects is None:
            return
        objects_fd = self._open_directory(self.gitdir_fd, "objects")
        try:
            info = self._entry(objects_fd, "info")
            if info is None:
                return
            if not stat.S_ISDIR(info.st_mode):
                raise BoundaryError("external Git metadata entry is unsafe")
            info_fd = self._open_directory(objects_fd, "info")
            try:
                if any(self._entry(info_fd, name) is not None
                       for name in ("alternates", "http-alternates")):
                    raise BoundaryError("external Git metadata redirection is unsafe")
            finally:
                os.close(info_fd)
        finally:
            os.close(objects_fd)

    @classmethod
    def _verify_gitdir_tree(cls, root_fd: int, *, max_depth: int = 64,
                            max_entries: int = 100_000) -> None:
        """Walk the pinned gitdir without following any directory entry."""
        seen = 0

        def walk(fd: int, depth: int) -> None:
            nonlocal seen
            if depth > max_depth:
                raise BoundaryError("external Git metadata tree is too deep")
            try:
                names = os.listdir(fd)
            except OSError as exc:
                raise BoundaryError("external Git metadata tree is unreadable") from exc
            for name in names:
                seen += 1
                if seen > max_entries:
                    raise BoundaryError("external Git metadata tree is too large")
                try:
                    item = os.stat(name, dir_fd=fd, follow_symlinks=False)
                except OSError as exc:
                    raise BoundaryError("external Git metadata entry changed") from exc
                if stat.S_ISLNK(item.st_mode):
                    raise BoundaryError("external Git metadata symlink is unsafe")
                if stat.S_ISREG(item.st_mode):
                    if (item.st_uid != os.getuid() or item.st_mode & 0o022
                            or item.st_nlink != 1):
                        raise BoundaryError("external Git metadata file is unsafe")
                    continue
                if not stat.S_ISDIR(item.st_mode):
                    raise BoundaryError("external Git metadata entry is unsafe")
                try:
                    child_fd = cls._open_directory(fd, name)
                except OSError as exc:
                    raise BoundaryError("external Git metadata entry changed") from exc
                try:
                    walk(child_fd, depth + 1)
                finally:
                    os.close(child_fd)

        walk(root_fd, 0)

    @property
    def pass_fds(self) -> tuple[int, ...]:
        if any(fd is None for fd in (
                self.worktree_parent_fd, self.worktree_fd, self.gitdir_parent_fd, self.gitdir_fd)):
            raise BoundaryError("descriptor anchor is not open")
        return (self.worktree_parent_fd, self.worktree_fd, self.gitdir_parent_fd, self.gitdir_fd)  # type: ignore[return-value]

    @property
    def command_paths(self) -> tuple[str, str]:
        """Select procfs descriptor paths when usable, otherwise verified names."""
        self.verify()
        if self.worktree_fdpath is None or self.gitdir_fdpath is None:
            raise BoundaryError("descriptor anchor is not open")
        return self.worktree_fdpath, self.gitdir_fdpath

    @property
    def command_worktree(self) -> str:
        return self.command_paths[0]

    @property
    def command_gitdir(self) -> str:
        return self.command_paths[1]

    def close(self) -> None:
        for fd in (self.gitdir_fd, self.gitdir_parent_fd, self.worktree_fd, self.worktree_parent_fd):
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
        self.gitdir_fd = self.gitdir_parent_fd = self.worktree_fd = self.worktree_parent_fd = None
        self.worktree_fdpath = self.gitdir_fdpath = None
        self._uses_procfs_paths = False

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> bool:
        error: BaseException | None = None
        try:
            self.verify()
        except BaseException as caught:
            error = caught
        self.close()
        if error is not None and exc is None:
            raise error
        return False


def _secure_private_dir(path: Path) -> Path:
    if path.exists() or path.is_symlink():
        assert_real_owned_parent(path)
    else:
        assert_real_owned_parent(path.parent, create=True)
        path.mkdir(mode=0o700)
    item = os.lstat(path)
    if (not stat.S_ISDIR(item.st_mode) or item.st_uid != os.getuid()
            or stat.S_IMODE(item.st_mode) != 0o700):
        raise BoundaryError("private runtime directory is unsafe")
    return path


def _sterile_git_environment(*, state_root: Path, allow_protocol: str) -> dict[str, str]:
    state_root = Path(state_root)
    assert_real_owned_parent(state_root, create=True)
    home = _secure_private_dir(state_root / "home")
    temporary = _secure_private_dir(state_root / "tmp")
    return {
        "PATH": FIXED_PATH, "LANG": "C", "LC_ALL": "C", "HOME": str(home), "TMPDIR": str(temporary),
        "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "/usr/bin/false", "GIT_SSH_COMMAND": "/usr/bin/false",
        "GIT_PROXY_COMMAND": "/usr/bin/false", "GIT_ALLOW_PROTOCOL": allow_protocol,
        "GIT_EDITOR": "/usr/bin/false", "GIT_SEQUENCE_EDITOR": "/usr/bin/false",
        "GIT_MERGE_AUTOEDIT": "no",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_CONFIG_COUNT": "8",
        "GIT_CONFIG_KEY_0": "core.hooksPath", "GIT_CONFIG_VALUE_0": os.devnull,
        "GIT_CONFIG_KEY_1": "credential.helper", "GIT_CONFIG_VALUE_1": "",
        "GIT_CONFIG_KEY_2": "core.fsmonitor", "GIT_CONFIG_VALUE_2": "false",
        "GIT_CONFIG_KEY_3": "commit.gpgsign", "GIT_CONFIG_VALUE_3": "false",
        "GIT_CONFIG_KEY_4": "tag.gpgSign", "GIT_CONFIG_VALUE_4": "false",
        "GIT_CONFIG_KEY_5": "gpg.program", "GIT_CONFIG_VALUE_5": "/usr/bin/false",
        "GIT_CONFIG_KEY_6": "protocol.ext.allow", "GIT_CONFIG_VALUE_6": "never",
        "GIT_CONFIG_KEY_7": "rerere.enabled", "GIT_CONFIG_VALUE_7": "false",
        "GIT_AUTHOR_NAME": "Peirce", "GIT_AUTHOR_EMAIL": "peirce@example.invalid",
        "GIT_COMMITTER_NAME": "Peirce", "GIT_COMMITTER_EMAIL": "peirce@example.invalid",
    }


def sterile_local_git_environment(*, state_root: Path) -> dict[str, str]:
    """Build a credential-free environment with every Git transport denied."""
    return _sterile_git_environment(state_root=state_root, allow_protocol="")


def sterile_git_environment(token: str, *, state_root: Path,
                            repository_url: str) -> dict[str, str]:
    """Build the reviewed HTTPS transport environment; credentials never enter argv."""
    if (not isinstance(token, str) or not token or "\x00" in token
            or not is_canonical_github_origin(repository_url)):
        raise BoundaryError("credential transport pair is invalid")
    env = _sterile_git_environment(state_root=state_root, allow_protocol="https")
    encoded = base64.b64encode(f"x-access-token:{token}".encode()).decode()
    env.update({"GIT_CONFIG_COUNT": "9",
                "GIT_CONFIG_KEY_8": f"http.{repository_url}.extraHeader",
                "GIT_CONFIG_VALUE_8": f"Authorization: Basic {encoded}"})
    return env


def sterile_git_argv(descriptor: RepositoryDescriptor, command: Sequence[str], *,
                     anchor: DescriptorAnchor | None = None) -> list[str]:
    """Construct literal Git argv using both descriptor-anchored FD paths."""
    if (not isinstance(command, (list, tuple))
            or any(not isinstance(item, str) or not item for item in command)):
        raise BoundaryError("Git argv is invalid")
    if anchor is None or anchor.descriptor != descriptor:
        raise BoundaryError("descriptor anchor is required")
    validate_external_git_metadata(descriptor)
    anchor.verify()
    worktree, gitdir = anchor.command_paths
    return [GIT_BIN, "-C", worktree, f"--git-dir={gitdir}",
            f"--work-tree={worktree}", *command]


def redact_text(value: str, secrets: Sequence[str]) -> str:
    for secret in secrets:
        if secret:
            value = value.replace(secret, "[REDACTED]")
    return value


def redact_process(value: Mapping[str, Any], secrets: Sequence[str]) -> dict[str, Any]:
    """Recursively redact credentials from every process-result field."""
    def clean(item: Any) -> Any:
        if isinstance(item, str):
            return redact_text(item, secrets)
        if isinstance(item, Mapping):
            return {key: clean(child) for key, child in item.items()}
        if isinstance(item, tuple):
            return tuple(clean(child) for child in item)
        if isinstance(item, list):
            return [clean(child) for child in item]
        return item

    return clean(dict(value))


def repository_lock_path(repository_id: str, *, state_root: Path) -> Path:
    _identity(repository_id, numeric=True)
    root = Path(state_root) / "locks"
    assert_real_owned_parent(root, create=True)
    return root / f"repository-{repository_id}.lock"


def channel_lock_path(workspace_id: str, channel_id: str, *, state_root: Path) -> Path:
    _identity(workspace_id)
    _identity(channel_id)
    root = Path(state_root) / "locks"
    assert_real_owned_parent(root, create=True)
    key = hashlib.sha256(f"{workspace_id}\0{channel_id}".encode()).hexdigest()
    return root / f"channel-{key}.lock"


def _validate_lock_handle(path: Path, fd: int) -> None:
    item = os.fstat(fd)
    named = os.lstat(path)
    if (not stat.S_ISREG(item.st_mode) or item.st_uid != os.getuid()
            or stat.S_IMODE(item.st_mode) != 0o600
            or (named.st_dev, named.st_ino) != (item.st_dev, item.st_ino)
            or stat.S_ISLNK(named.st_mode)):
        raise BoundaryError("lock file is unsafe")


def _open_lock(path: Path):
    fd: int | None = None
    try:
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        _validate_lock_handle(path, fd)
        return os.fdopen(fd, "a+")
    except BoundaryError:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        raise
    except OSError as exc:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        raise BoundaryError("lock file is unsafe") from exc


@contextmanager
def repository_lock(repository_id: str, *, state_root: Path) -> Iterator[None]:
    path = repository_lock_path(repository_id, state_root=state_root)
    with _open_lock(path) as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            _validate_lock_handle(path, handle.fileno())
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


@contextmanager
def channel_lock(workspace_id: str, channel_id: str, *, state_root: Path) -> Iterator[None]:
    path = channel_lock_path(workspace_id, channel_id, state_root=state_root)
    with _open_lock(path) as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            _validate_lock_handle(path, handle.fileno())
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


@contextmanager
def ordered_locks(workspace_id: str, channel_id: str, repository_id: str,
                  *, state_root: Path) -> Iterator[None]:
    """Acquire the channel boundary before the repository boundary."""
    with channel_lock(workspace_id, channel_id, state_root=state_root):
        with repository_lock(repository_id, state_root=state_root):
            yield


_TOKEN_PROFILES: dict[str, dict[str, str]] = {
    "observe": {"metadata": "read"},
    "git_remote_read": {"metadata": "read", "contents": "read"},
    "workspace_read": {"metadata": "read", "contents": "read"},
    "git_push_delete": {"metadata": "read", "contents": "write"},
    "github_collaboration": {
        "metadata": "read", "contents": "read", "issues": "write", "pull_requests": "write",
        "checks": "read", "statuses": "write",
    },
    "risk_report": {"metadata": "read", "issues": "write"},
}


def _profile(name: str) -> dict[str, str]:
    if not isinstance(name, str) or name not in _TOKEN_PROFILES:
        raise BoundaryError("token profile is invalid")
    return dict(_TOKEN_PROFILES[name])


def narrow_token_request(repository_id: str, profile: str) -> dict[str, Any]:
    _identity(repository_id, numeric=True)
    return {"permissions": _profile(profile), "repository_ids": [int(repository_id)]}


def _validate_exact_token(data: Any, permissions: Mapping[str, str], *,
                          repository_id: str | None, owner: str | None, name: str | None,
                          repository_echo_optional: bool = False) -> str:
    if not isinstance(data, Mapping):
        raise BoundaryError("token response is not exact")
    token, expires_at = data.get("token"), data.get("expires_at")
    if (not isinstance(token, str) or not token.strip() or "\x00" in token
            or not isinstance(expires_at, str) or not expires_at.strip()):
        raise BoundaryError("token response is not exact")
    try:
        expiry = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        if expiry.tzinfo is None or expiry <= datetime.now(timezone.utc):
            raise ValueError
    except (TypeError, ValueError) as exc:
        raise BoundaryError("token expiry is not exact") from exc
    if data.get("permissions") != dict(permissions) or data.get("repository_selection") != "selected":
        raise BoundaryError("token permissions are not exact")
    repositories = data.get("repositories")
    if repositories is None and repository_echo_optional:
        return token
    if (not isinstance(repositories, list) or len(repositories) != 1
            or not isinstance(repositories[0], Mapping)):
        raise BoundaryError("token must select exactly one repository")
    repository = repositories[0]
    if (repository_id is not None and str(repository.get("id")) != repository_id) \
            or owner is not None and name is not None and (
                repository.get("name") != name
                or repository.get("full_name") != f"{owner}/{name}"):
        raise BoundaryError("token repository identity is not exact")
    return token


def validate_token_response(data: Any, descriptor: RepositoryDescriptor, profile: str) -> str:
    """Accept only a live, selected, one-repository token for a named profile."""
    if not isinstance(descriptor, RepositoryDescriptor):
        raise BoundaryError("repository descriptor is invalid")
    _identity(descriptor.repository_id, numeric=True)
    return _validate_exact_token(
        data, _profile(profile), repository_id=descriptor.repository_id,
        owner=descriptor.owner, name=descriptor.name)


def validate_repository_token_response(data: Any, repository_id: str, owner: str,
                                        name: str, profile: str) -> str:
    """Validate an exact repository token without introducing a workspace path.

    Network-only capabilities must not manufacture a worktree merely to reuse
    the token identity boundary.  Expiry, selected-repository, permission, and
    one-repository checks remain identical to ``validate_token_response``.
    """
    _identity(repository_id, numeric=True)
    if (not isinstance(owner, str) or not GITHUB_REPO_PART.fullmatch(owner)
            or not isinstance(name, str) or not GITHUB_REPO_PART.fullmatch(name)):
        raise BoundaryError("repository identity is invalid")
    return _validate_exact_token(
        data, _profile(profile), repository_id=repository_id, owner=owner, name=name)


GITHUB_API_ROOT = "https://api.github.com"
GITHUB_API_VERSION = "2026-03-10"
MAX_PROVIDER_RESPONSE_BYTES = 256 * 1024
# Illustrative fixed identities for this public snapshot only. They are
# deliberately unverified and must be replaced with deployment-specific facts;
# the exact identity checks below remain host-owned and strict.
FIXED_SOURCE_REPOSITORY_ID = "101"
FIXED_ADMIN_REPOSITORY_ID = "202"
PRODUCTION_ENV_NAMES = (
    "GITHUB_APP_ID", "GITHUB_APP_INSTALLATION_ID", "GITHUB_APP_PRIVATE_KEY_PATH",
    "SLACK_BOT_TOKEN", "PEIRCE_SLACK_WORKSPACE_ID", "PEIRCE_SOURCE_CHANNEL_ID",
    "PEIRCE_SOURCE_REPOSITORY_ID", "PEIRCE_ADMIN_CHANNEL_ID",
    "PEIRCE_ADMIN_REPOSITORY_ID", "PEIRCE_PROJECT_WORKSPACE_ROOT",
    "PEIRCE_PROJECT_STATE_ROOT", "HERMES_PROJECTS_DB",
)


def validate_production_environment(mapping: Mapping[str, Any]) -> dict[str, Any]:
    """Purely validate production setting shapes without returning their values."""
    problems: dict[str, str] = {}
    values: dict[str, str] = {}
    if not isinstance(mapping, Mapping):
        return {"ok": False, "status": "invalid", "names": list(PRODUCTION_ENV_NAMES),
                "invalid": list(PRODUCTION_ENV_NAMES)}
    for name in PRODUCTION_ENV_NAMES:
        value = mapping.get(name)
        if not isinstance(value, str) or not value.strip() or "\x00" in value:
            problems[name] = "missing_or_invalid"
        else:
            values[name] = value.strip()
    for name in ("GITHUB_APP_ID", "GITHUB_APP_INSTALLATION_ID",
                  "PEIRCE_SOURCE_REPOSITORY_ID", "PEIRCE_ADMIN_REPOSITORY_ID"):
        if name in values and not REPOSITORY_ID.fullmatch(values[name]):
            problems[name] = "invalid_identity"
    for name, expected in (
        ("PEIRCE_SOURCE_REPOSITORY_ID", FIXED_SOURCE_REPOSITORY_ID),
        ("PEIRCE_ADMIN_REPOSITORY_ID", FIXED_ADMIN_REPOSITORY_ID),
    ):
        if name in values and values[name] != expected:
            problems[name] = "unexpected_fixed_identity"
    for name in ("PEIRCE_SLACK_WORKSPACE_ID", "PEIRCE_SOURCE_CHANNEL_ID",
                 "PEIRCE_ADMIN_CHANNEL_ID"):
        if name in values and not IDENTITY.fullmatch(values[name]):
            problems[name] = "invalid_identity"
    for name in ("GITHUB_APP_PRIVATE_KEY_PATH", "PEIRCE_PROJECT_WORKSPACE_ROOT",
                 "PEIRCE_PROJECT_STATE_ROOT", "HERMES_PROJECTS_DB"):
        if name in values and (not Path(values[name]).is_absolute()
                               or Path(os.path.normpath(values[name])) != Path(values[name])):
            problems[name] = "invalid_path"
    for left, right in (("PEIRCE_SOURCE_CHANNEL_ID", "PEIRCE_ADMIN_CHANNEL_ID"),
                        ("PEIRCE_SOURCE_REPOSITORY_ID", "PEIRCE_ADMIN_REPOSITORY_ID"),
                        ("PEIRCE_PROJECT_WORKSPACE_ROOT", "PEIRCE_PROJECT_STATE_ROOT")):
        if left in values and right in values and values[left] == values[right]:
            problems[left] = problems[right] = "not_distinct"
    db = Path(values["HERMES_PROJECTS_DB"]) if "HERMES_PROJECTS_DB" in values else None
    state = Path(values["PEIRCE_PROJECT_STATE_ROOT"]) if "PEIRCE_PROJECT_STATE_ROOT" in values else None
    workspace = (Path(values["PEIRCE_PROJECT_WORKSPACE_ROOT"])
                 if "PEIRCE_PROJECT_WORKSPACE_ROOT" in values else None)
    if db is not None and state is not None and (db == state or db in state.parents or state in db.parents):
        problems["HERMES_PROJECTS_DB"] = problems["PEIRCE_PROJECT_STATE_ROOT"] = "overlap"
    if workspace is not None and state is not None and (workspace in state.parents or state in workspace.parents):
        problems["PEIRCE_PROJECT_WORKSPACE_ROOT"] = problems["PEIRCE_PROJECT_STATE_ROOT"] = "overlap"
    profile = db.parent if db is not None else None
    if workspace is not None and profile is not None and (
            workspace == profile or workspace in profile.parents or profile in workspace.parents):
        problems["PEIRCE_PROJECT_WORKSPACE_ROOT"] = problems["HERMES_PROJECTS_DB"] = "overlap"
    if state is not None and profile is not None and (
            state == profile or state in profile.parents or profile in state.parents):
        problems["PEIRCE_PROJECT_STATE_ROOT"] = problems["HERMES_PROJECTS_DB"] = "overlap"
    invalid = [name for name in PRODUCTION_ENV_NAMES if name in problems]
    return {"ok": not invalid, "status": "valid" if not invalid else "invalid",
            "names": list(PRODUCTION_ENV_NAMES), "invalid": invalid}


def _stdlib_http_request(method: str, url: str, *, headers: Mapping[str, str],
                          json_body: Mapping[str, Any] | None = None,
                          timeout: float = 10.0, max_bytes: int = MAX_PROVIDER_RESPONSE_BYTES,
                          allow_redirects: bool = False, trust_env: bool = False) -> Mapping[str, Any]:
    import urllib.error
    import urllib.request

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
            return None

    if allow_redirects or trust_env:
        raise BoundaryError("provider transport configuration is invalid")
    body = None if json_body is None else json.dumps(json_body, separators=(",", ":")).encode()
    request = urllib.request.Request(url, data=body, method=method, headers=dict(headers))
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        response = opener.open(request, timeout=timeout)
    except urllib.error.HTTPError as exc:
        response = exc
    try:
        raw = response.read(max_bytes + 1)
        if len(raw) > max_bytes:
            raise BoundaryError("provider response exceeds bound")
        data = json.loads(raw.decode("utf-8")) if raw else None
        return {"status_code": int(response.status), "data": data}
    except BoundaryError:
        raise
    except Exception as exc:
        raise BoundaryError("provider response is malformed") from exc
    finally:
        response.close()


class EnvironmentBroker:
    """Lazy exact-host deployment adapter for the callback-based capabilities."""

    def __init__(self, environ: Mapping[str, str] | None = None, *,
                 http_transport: Any = None, jwt_encoder: Callable[..., Any] | None = None,
                 clock: Callable[[], float] = time.time) -> None:
        self.environ = os.environ if environ is None else environ
        self.http_transport = http_transport or _stdlib_http_request
        self.jwt_encoder = jwt_encoder
        self.clock = clock

    def require(self, *names: str) -> tuple[str, ...]:
        values: list[str] = []
        for name in names:
            value = self.environ.get(name)
            if not isinstance(value, str) or not value.strip() or "\x00" in value:
                raise BoundaryError(f"required environment setting is unavailable: {name}")
            values.append(value.strip())
        return tuple(values)

    def _private_key(self) -> bytes:
        (value,) = self.require("GITHUB_APP_PRIVATE_KEY_PATH")
        path = Path(value)
        if not path.is_absolute():
            raise BoundaryError("GitHub App private key path is invalid")
        fd: int | None = None
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            item = os.fstat(fd)
            if (not stat.S_ISREG(item.st_mode) or item.st_nlink != 1
                    or item.st_size <= 0 or item.st_size > 1024 * 1024
                    or item.st_uid != 0 or item.st_gid != os.getegid()
                    or stat.S_IMODE(item.st_mode) != 0o640):
                raise BoundaryError("GitHub App private key is unsafe")
            chunks: list[bytes] = []
            remaining = item.st_size
            while remaining:
                chunk = os.read(fd, min(65536, remaining))
                if not chunk:
                    raise BoundaryError("GitHub App private key changed")
                chunks.append(chunk)
                remaining -= len(chunk)
            if os.read(fd, 1):
                raise BoundaryError("GitHub App private key changed")
            after = os.fstat(fd)
            before_state = (item.st_dev, item.st_ino, stat.S_IFMT(item.st_mode), item.st_uid,
                            item.st_gid, stat.S_IMODE(item.st_mode), item.st_nlink, item.st_size)
            after_state = (after.st_dev, after.st_ino, stat.S_IFMT(after.st_mode), after.st_uid,
                           after.st_gid, stat.S_IMODE(after.st_mode), after.st_nlink, after.st_size)
            if after_state != before_state:
                raise BoundaryError("GitHub App private key changed")
            return b"".join(chunks)
        except BoundaryError:
            raise
        except OSError as exc:
            raise BoundaryError("GitHub App private key is unavailable") from exc
        finally:
            if fd is not None:
                os.close(fd)

    def app_jwt(self) -> str:
        app_id, = self.require("GITHUB_APP_ID")
        encoder = self.jwt_encoder
        if encoder is None:
            try:
                import jwt
                encoder = jwt.encode
            except Exception as exc:
                raise BoundaryError("GitHub JWT support is unavailable") from exc
        now = int(self.clock())
        try:
            token = encoder({"iat": now - 30, "exp": now + 540, "iss": app_id},
                            self._private_key(), algorithm="RS256")
        except BoundaryError:
            raise
        except Exception as exc:
            raise BoundaryError("GitHub App authentication failed") from exc
        if isinstance(token, bytes):
            token = token.decode("ascii")
        if not isinstance(token, str) or not token:
            raise BoundaryError("GitHub App authentication failed")
        return token

    def _request(self, method: str, url: str, token: str, *,
                 body: Mapping[str, Any] | None = None, raw_status: bool = False) -> Any:
        if not url.startswith(GITHUB_API_ROOT + "/"):
            raise BoundaryError("provider host is invalid")
        headers = {"Accept": "application/vnd.github+json", "Authorization": f"Bearer {token}",
                   "X-GitHub-Api-Version": GITHUB_API_VERSION, "User-Agent": "project-gateway"}
        target = self.http_transport.request if hasattr(self.http_transport, "request") else self.http_transport
        try:
            response = target(method, url, headers=headers, json_body=body, timeout=10.0,
                              max_bytes=MAX_PROVIDER_RESPONSE_BYTES,
                              allow_redirects=False, trust_env=False)
        except BoundaryError:
            raise
        except Exception as exc:
            raise BoundaryError("provider request failed") from exc
        if not isinstance(response, Mapping):
            raise BoundaryError("provider response is malformed")
        status = response.get("status_code", response.get("status"))
        data = response.get("data")
        try:
            bounded = len(json.dumps(data, ensure_ascii=False).encode()) <= MAX_PROVIDER_RESPONSE_BYTES
        except Exception:
            bounded = False
        if not isinstance(status, int) or isinstance(status, bool) or not bounded:
            raise BoundaryError("provider response is malformed")
        if raw_status:
            return {"status_code": status, "data": data}
        if status < 200 or status >= 300:
            raise BoundaryError("provider request was rejected")
        return data

    def token_reader(self, request: Mapping[str, Any]) -> Any:
        installation, = self.require("GITHUB_APP_INSTALLATION_ID")
        if not REPOSITORY_ID.fullmatch(installation) or not isinstance(request, Mapping):
            raise BoundaryError("installation token request is invalid")
        allowed = {"permissions", "repository_ids", "installation_id"}
        if set(request) - allowed or request.get("installation_id", int(installation)) != int(installation):
            raise BoundaryError("installation token request is invalid")
        repository_ids, permissions = request.get("repository_ids"), request.get("permissions")
        if (not isinstance(repository_ids, list) or len(repository_ids) != 1
                or not isinstance(repository_ids[0], int) or isinstance(repository_ids[0], bool)
                or not isinstance(permissions, Mapping)
                or dict(permissions) not in _TOKEN_PROFILES.values()):
            raise BoundaryError("installation token request is invalid")
        return self._request("POST", f"{GITHUB_API_ROOT}/app/installations/{installation}/access_tokens",
                             self.app_jwt(), body={"permissions": dict(permissions),
                                                   "repository_ids": list(repository_ids)})

    @staticmethod
    def _provider_observation(data: Any, installation_id: str) -> Any:
        try:
            from .project import ProviderObservation
        except ImportError:  # pragma: no cover
            from project import ProviderObservation  # type: ignore
        if not isinstance(data, Mapping) or not isinstance(data.get("owner"), Mapping):
            raise BoundaryError("repository observation is malformed")
        repository_id, owner, name = str(data.get("id")), data["owner"].get("login"), data.get("name")
        branch = data.get("default_branch")
        if (not REPOSITORY_ID.fullmatch(repository_id) or not isinstance(owner, str)
                or not GITHUB_REPO_PART.fullmatch(owner) or not isinstance(name, str)
                or not GITHUB_REPO_PART.fullmatch(name) or not isinstance(branch, str)):
            raise BoundaryError("repository observation is malformed")
        canonical = f"https://github.com/{owner}/{name}.git"
        if data.get("clone_url") not in (None, canonical) or data.get("full_name") not in (None, f"{owner}/{name}"):
            raise BoundaryError("repository observation identity is inconsistent")
        return ProviderObservation(repository_id, installation_id, owner, name, canonical, branch)

    def _verify_installation(self, owner: str, name: str, expected: str) -> None:
        data = self._request("GET", f"{GITHUB_API_ROOT}/repos/{owner}/{name}/installation",
                             self.app_jwt())
        if not isinstance(data, Mapping) or str(data.get("id")) != expected:
            raise BoundaryError("repository installation identity does not match configuration")

    @staticmethod
    def _installation_token(data: Any, permissions: Mapping[str, str], *,
                            repository_id: str | None = None, owner: str | None = None,
                            name: str | None = None) -> str:
        return _validate_exact_token(
            data, permissions, repository_id=repository_id, owner=owner, name=name,
            repository_echo_optional=True)

    def access_reader(self, locator: Any) -> Any:
        installation, = self.require("GITHUB_APP_INSTALLATION_ID")
        owner, name = getattr(locator, "owner", None), getattr(locator, "name", None)
        if not isinstance(owner, str) or not GITHUB_REPO_PART.fullmatch(owner) \
                or not isinstance(name, str) or not GITHUB_REPO_PART.fullmatch(name):
            raise BoundaryError("repository locator is invalid")
        self._verify_installation(owner, name, installation)
        permissions = _profile("observe")
        token_data = self._request(
            "POST", f"{GITHUB_API_ROOT}/app/installations/{installation}/access_tokens",
            self.app_jwt(), body={"permissions": permissions, "repositories": [name]})
        token = self._installation_token(token_data, permissions, owner=owner, name=name)
        data = self._request("GET", f"{GITHUB_API_ROOT}/repos/{owner}/{name}", token)
        observed = self._provider_observation(data, installation)
        if (observed.owner, observed.name) != (owner, name):
            raise BoundaryError("repository observation identity changed")
        self._installation_token(token_data, permissions, repository_id=observed.repository_id,
                                 owner=observed.owner, name=observed.name)
        return observed

    def observe(self, candidate: Any) -> Any:
        installation, = self.require("GITHUB_APP_INSTALLATION_ID")
        repository_id = getattr(candidate, "repository_id", None)
        if not isinstance(repository_id, str) or not REPOSITORY_ID.fullmatch(repository_id):
            raise BoundaryError("repository candidate is invalid")
        permissions = _profile("observe")
        token_data = self.token_reader(narrow_token_request(repository_id, "observe"))
        token = self._installation_token(token_data, permissions, repository_id=repository_id)
        data = self._request("GET", f"{GITHUB_API_ROOT}/repositories/{repository_id}", token)
        observed = self._provider_observation(data, installation)
        if observed.repository_id != repository_id:
            raise BoundaryError("repository observation identity changed")
        self._installation_token(token_data, permissions, repository_id=repository_id,
                                 owner=observed.owner, name=observed.name)
        self._verify_installation(observed.owner, observed.name, installation)
        return observed

    def bookmark_transport(self, operation: str, payload: Mapping[str, Any]) -> Any:
        token, = self.require("SLACK_BOT_TOKEN")
        methods = {"list": "bookmarks.list", "add": "bookmarks.add", "delete": "bookmarks.remove"}
        if operation not in methods or not isinstance(payload, Mapping):
            raise BoundaryError("Slack bookmark request is invalid")
        target = self.http_transport.request if hasattr(self.http_transport, "request") else self.http_transport
        try:
            response = target("POST", f"https://slack.com/api/{methods[operation]}",
                              headers={"Authorization": f"Bearer {token}",
                                       "Content-Type": "application/json; charset=utf-8"},
                              json_body=dict(payload), timeout=10.0,
                              max_bytes=MAX_PROVIDER_RESPONSE_BYTES,
                              allow_redirects=False, trust_env=False)
        except Exception as exc:
            raise BoundaryError("Slack bookmark request failed") from exc
        if not isinstance(response, Mapping):
            raise BoundaryError("Slack bookmark response is malformed")
        data = response.get("data")
        if response.get("status_code", response.get("status")) != 200 or not isinstance(data, Mapping):
            raise BoundaryError("Slack bookmark response is malformed")
        return dict(data)

    def comment_api_transport(self, method: str, path: str, token: str, version: str) -> Any:
        if (method not in {"GET", "DELETE"} or version != GITHUB_API_VERSION
                or not re.fullmatch(
                    r"/repos/[A-Za-z0-9._-]+/[A-Za-z0-9._-]+/"
                    r"(?:issues(?:/[1-9][0-9]{0,8}|/comments/[1-9][0-9]{0,8})|"
                    r"pulls(?:/[1-9][0-9]{0,8}|/comments/[1-9][0-9]{0,8}))", path)):
            raise BoundaryError("GitHub comment request is invalid")
        return self._request(method, GITHUB_API_ROOT + path, token, raw_status=True)


__all__ = [
    "BoundaryError", "RepositoryDescriptor", "DescriptorAnchor",
    "validate_descriptor_path", "validate_external_git_metadata", "path_is_contaminated",
    "assert_real_owned_parent", "sterile_local_git_environment", "sterile_git_environment",
    "sterile_git_argv",
    "redact_text", "redact_process", "repository_lock_path", "channel_lock_path",
    "repository_lock", "channel_lock", "ordered_locks", "narrow_token_request",
    "validate_token_response", "validate_repository_token_response", "is_canonical_github_origin",
    "EnvironmentBroker", "validate_production_environment", "PRODUCTION_ENV_NAMES",
    "GITHUB_API_ROOT", "GITHUB_API_VERSION",
]
