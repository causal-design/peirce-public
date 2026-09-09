# SPDX-License-Identifier: AGPL-3.0-only
"""Trusted project routing, independent workspace, and bookmark capabilities.

Provider observations and effects are supplied as injected callbacks.  The
gateway retains no workflow authority: each capability validates its own exact
repository or channel boundary when invoked.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import base64
import hashlib
import os
import re
import stat
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator, Mapping
from urllib.parse import urlparse

from . import cli_runner, host_boundary, registry


IDENTITY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
REPOSITORY_ID = re.compile(r"^[0-9]+$")
REPO_PART = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")
FULL_SHA = re.compile(r"^[0-9a-f]{40}$")

# Snapshot breadth is bounded independently from the existing 512-file limit.
# The entry budget counts every encountered name, including excluded profile
# roots and empty directories; the directory budget counts every traversed dir.
MAX_LEARNING_ENTRIES = 1024
MAX_LEARNING_DIRECTORIES = 256
INITIALIZE_MARKER = ".peirce-initialize-in-progress"
class ProjectError(ValueError):
    """A trusted route or association request is invalid."""


class FixedProjectError(ProjectError):
    """A fixed route cannot be mutated or selected as an ordinary project."""


class ObservationMismatch(ProjectError):
    """The provider did not return the immutable identity being selected."""


class WorkspaceError(ProjectError):
    """An explicit candidate workspace is unsafe or cannot be prepared."""


class _IncompleteWorkspace(WorkspaceError):
    """Safe concrete Git metadata lacks one or more closed config entries."""


class _UncertainWorkspace(WorkspaceError):
    """A metadata read did not produce a concrete observation."""

    def __init__(self, labels: tuple[str, ...], process: tuple[Mapping[str, Any], ...]) -> None:
        super().__init__("workspace Git metadata observation is uncertain")
        self.labels = labels
        self.process = process


class BookmarkError(ProjectError):
    """A bookmark request or successful provider response is invalid."""


@dataclass(frozen=True)
class TrustedOrigin:
    workspace_id: str
    channel_id: str
    channel_name: str = ""


@dataclass(frozen=True)
class CanonicalCandidate:
    owner: str
    name: str
    repository_id: str

    @property
    def full_name(self) -> str:
        return f"{self.owner}/{self.name}"


@dataclass(frozen=True)
class RepositoryLocator:
    owner: str
    name: str


@dataclass(frozen=True)
class ProviderObservation:
    repository_id: str
    installation_id: str
    owner: str
    name: str
    url: str
    default_branch: str


@dataclass(frozen=True)
class WorkspaceInspection:
    state: str
    repository_id: str
    worktree: str
    trusted_gitdir: str
    branch: str | None = None
    head: str | None = None
    upstream: str | None = None
    dirty: bool | None = None
    ahead: int | None = None
    behind: int | None = None
    process_uncertainty: tuple[str, ...] = ()
    process_failures: tuple[str, ...] = ()


@dataclass(frozen=True)
class WorkspaceEffect:
    effect: str
    repository_id: str
    inspection: WorkspaceInspection
    process: tuple[Mapping[str, Any], ...] = ()


@dataclass(frozen=True)
class Bookmark:
    bookmark_id: str
    title: str
    url: str


@dataclass(frozen=True)
class BookmarkObservation:
    channel_id: str
    bookmarks: tuple[Bookmark, ...]
    uncertain: bool = False
    error: str | None = None


@dataclass(frozen=True)
class BookmarkEffect:
    effect: str
    channel_id: str
    bookmark: Bookmark | None = None
    bookmark_id: str | None = None
    uncertain: bool = False
    error: str | None = None


@dataclass(frozen=True)
class FixedProject:
    """A configured fixed project with all local facts supplied explicitly."""

    origin: TrustedOrigin
    repository: registry.RepositoryFacts
    layout: str | None = None


@dataclass(frozen=True)
class LearningSnapshotEntry:
    relative_path: str
    size: int
    mode: int
    sha256: str
    content_base64: str


@dataclass(frozen=True)
class LearningSnapshot:
    state: str
    authorized_source_repository_id: str
    entries: tuple[LearningSnapshotEntry, ...] = ()
    uncertain: bool = False
    error: str | None = None

    @property
    def evidence_source(self) -> str:
        return "live_profile"


@dataclass(frozen=True)
class CurrentProjectRoute:
    """The one route shape returned for both fixed and dynamic projects."""

    origin: TrustedOrigin
    repository: registry.RepositoryFacts
    fixed: bool = False

    @property
    def repository_id(self) -> str:
        return self.repository.repository_id

    @property
    def owner(self) -> str:
        return self.repository.owner

    @property
    def name(self) -> str:
        return self.repository.name

    @property
    def trusted_gitdir(self) -> str:
        return self.repository.trusted_gitdir


def _identity(value: str, *, numeric: bool = False) -> None:
    pattern = REPOSITORY_ID if numeric else IDENTITY
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise ProjectError("identity is invalid")


def _candidate(value: CanonicalCandidate) -> CanonicalCandidate:
    if not isinstance(value, CanonicalCandidate):
        raise ProjectError("canonical candidate is invalid")
    result = value
    _identity(result.owner)
    _identity(result.name)
    if not REPO_PART.fullmatch(result.owner) or not REPO_PART.fullmatch(result.name):
        raise ProjectError("canonical candidate is invalid")
    _identity(result.repository_id, numeric=True)
    return result


def _origin(value: TrustedOrigin) -> TrustedOrigin:
    if not isinstance(value, TrustedOrigin):
        raise ProjectError("trusted origin is invalid")
    result = value
    _identity(result.workspace_id)
    _identity(result.channel_id)
    if not isinstance(result.channel_name, str):
        raise ProjectError("trusted origin is invalid")
    return result


def _observation(value: ProviderObservation) -> ProviderObservation:
    if not isinstance(value, ProviderObservation):
        raise ObservationMismatch("provider observation is invalid")
    result = value
    _identity(result.repository_id, numeric=True)
    _identity(result.installation_id, numeric=True)
    parsed = urlparse(result.url) if isinstance(result.url, str) else None
    canonical_url = f"https://github.com/{result.owner}/{result.name}.git"
    if (not REPO_PART.fullmatch(result.owner) or not REPO_PART.fullmatch(result.name)
            or parsed is None or result.url != canonical_url or parsed.scheme != "https"
            or parsed.hostname != "github.com" or parsed.port is not None
            or parsed.username or parsed.password or parsed.query or parsed.fragment
            or not _default_branch(result.default_branch)):
        raise ObservationMismatch("provider observation is invalid")
    return result


def _default_branch(value: Any) -> bool:
    """Accept a canonical short Git branch name, never a symbolic/full ref."""
    if (not isinstance(value, str) or not value or len(value) > 255
            or value in {"HEAD", "@", ".", ".."} or value.startswith("-")
            or value.startswith(("refs/heads/", "refs/remotes/", "origin/"))
            or value.startswith("/") or value.endswith(("/", "."))
            or "//" in value or ".." in value or "@{" in value
            or any(ord(character) < 32 or ord(character) == 127
                   or character in " ~^:?*[\\" for character in value)):
        return False
    return all(part and not part.startswith(".") and not part.endswith(".lock")
               for part in value.split("/"))


def _printable(value: str, maximum: int, label: str) -> str:
    if (not isinstance(value, str) or not value or len(value) > maximum
            or any(not character.isprintable() for character in value)):
        raise BookmarkError(f"bookmark {label} is invalid")
    return value


def _bookmark_url(value: str) -> str:
    value = _printable(value, 2048, "URL")
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.username or parsed.password:
        raise BookmarkError("bookmark URL is invalid")
    return value


def _bookmark_value(value: Any, channel_id: str) -> Bookmark:
    if not isinstance(value, dict) or value.get("type") != "link" \
            or value.get("channel_id") != channel_id:
        raise BookmarkError("bookmark response is invalid")
    bookmark_id = _printable(value.get("id"), 128, "ID")
    title = _printable(value.get("title"), 300, "title")
    url = _bookmark_url(value.get("link"))
    return Bookmark(bookmark_id, title, url)


def build_peirce_isolated_projects(
    project_registry: registry.ProjectRegistry,
    trusted_workspace_id: str,
    source_channel_id: str,
    source_repository_id: str,
    admin_channel_id: str,
    admin_repository_id: str,
    installation_id: str,
) -> tuple[FixedProject, FixedProject]:
    """Build the two host-trusted Peirce routes from fixed layout facts."""
    if not isinstance(project_registry, globals()["registry"].ProjectRegistry):
        raise FixedProjectError("registry is invalid")
    _identity(trusted_workspace_id)
    _identity(source_channel_id)
    _identity(admin_channel_id)
    _identity(source_repository_id, numeric=True)
    _identity(admin_repository_id, numeric=True)
    _identity(installation_id, numeric=True)
    if source_channel_id == admin_channel_id or source_repository_id == admin_repository_id:
        raise FixedProjectError("fixed project identities must be distinct")

    def make(layout: str, channel_id: str, repository_id: str, name: str,
             local_name: str) -> FixedProject:
        facts = globals()["registry"].RepositoryFacts(
            repository_id, name, installation_id, "peirce-example", name,
            str(project_registry.workspace_root / local_name),
            f"https://github.com/peirce-example/{name}.git", "main",
            str(project_registry.state_root / "reserved" / f"{local_name}.git"),
        )
        return FixedProject(TrustedOrigin(trusted_workspace_id, channel_id), facts, layout)

    return (make("source", source_channel_id, source_repository_id, "peirce", "peirce"),
            make("admin", admin_channel_id, admin_repository_id,
                 "peirce-admin", "peirce-admin"))


class ProjectGateway:
    """Perform independently authorized routing, workspace, and bookmark operations."""

    def __init__(
        self,
        registry: registry.ProjectRegistry,
        observe: Callable[[CanonicalCandidate], ProviderObservation],
        fixed_projects: Iterable[FixedProject] = (),
        *,
        state_root: Path | str | None = None,
        token_reader: Callable[[Mapping[str, Any]], Any] | None = None,
        process_runner: Callable[..., Mapping[str, Any]] | None = None,
        protected_profile_root: Path | str | None = None,
    ) -> None:
        if not isinstance(registry, globals()["registry"].ProjectRegistry):
            raise ProjectError("registry is invalid")
        if not callable(observe):
            raise ProjectError("provider observation callback is invalid")
        self.registry = registry
        self.provider_reader = observe
        self.token_reader = token_reader
        self.process_runner = process_runner or cli_runner.run_argv
        self.state_root = Path(state_root) if state_root is not None else self.registry.state_root
        if self.state_root != self.registry.state_root:
            raise ProjectError("state root must match registry state root")
        self.protected_profile_root = (self._configured_profile_root(protected_profile_root)
                                       if protected_profile_root is not None else None)
        self._fixed: dict[tuple[str, str], FixedProject] = {}
        self._fixed_ids: set[str] = set()
        self._fixed_by_id: dict[str, FixedProject] = {}
        for item in fixed_projects:
            route = self._fixed_route(item)
            key = (route.origin.workspace_id, route.origin.channel_id)
            if key in self._fixed or route.repository.repository_id in self._fixed_ids:
                raise FixedProjectError("fixed project identities must be unique")
            self._fixed[key] = route
            self._fixed_ids.add(route.repository.repository_id)
            self._fixed_by_id[route.repository.repository_id] = route
        production = [item for item in self._fixed_by_id.values() if item.layout is not None]
        if production and (len(production) != 2
                           or {item.layout for item in production} != {"source", "admin"}):
            raise FixedProjectError("production fixed layouts must contain source and admin")
        for item in production:
            self._validate_production_fixed(item)
            self._reject_profile_overlap(Path(item.repository.worktree))
            self._reject_profile_overlap(Path(item.repository.trusted_gitdir))
        if len(production) == 2:
            paths = [Path(item.repository.worktree) for item in production] + [
                Path(item.repository.trusted_gitdir) for item in production]
            for index, left in enumerate(paths):
                for right in paths[index + 1:]:
                    if self._paths_overlap(left, right):
                        raise FixedProjectError("source and admin paths must be disjoint")

    @staticmethod
    def _configured_profile_root(value: Path | str) -> Path:
        path = Path(value)
        if not path.is_absolute() or Path(os.path.normpath(str(path))) != path:
            raise ProjectError("protected profile root is invalid")
        current = Path(path.anchor)
        for part in path.parts[1:]:
            current /= part
            try:
                item = os.lstat(current)
            except FileNotFoundError:
                continue
            except OSError as exc:
                raise ProjectError("protected profile root is unavailable") from exc
            if stat.S_ISLNK(item.st_mode):
                if current not in host_boundary.SYSTEM_TEMP_ALIASES:
                    raise ProjectError("protected profile root contains a symlink")
                item = os.stat(current)
            if not stat.S_ISDIR(item.st_mode):
                raise ProjectError("protected profile root traversal is invalid")
            if current == path and (item.st_uid != os.getuid() or item.st_mode & 0o022):
                raise ProjectError("protected profile root is unsafe")
        return path

    @staticmethod
    def _paths_overlap(left: Path, right: Path) -> bool:
        lexical_left = Path(os.path.abspath(left))
        lexical_right = Path(os.path.abspath(right))
        pairs = ((lexical_left, lexical_right),
                 (lexical_left.resolve(strict=False), lexical_right.resolve(strict=False)))
        return any(a == b or a in b.parents or b in a.parents for a, b in pairs)

    def _reject_profile_overlap(self, path: Path) -> None:
        if self.protected_profile_root is not None and self._paths_overlap(
                path, self.protected_profile_root):
            raise WorkspaceError("repository path overlaps protected profile root")

    def _validate_production_fixed(self, route: FixedProject) -> None:
        expected = {
            "source": ("peirce", "peirce"),
            "admin": ("peirce-admin", "peirce-admin"),
        }
        if route.layout not in expected:
            raise FixedProjectError("fixed project layout is invalid")
        repository_name, local_name = expected[route.layout]
        facts = route.repository
        required = globals()["registry"].RepositoryFacts(
            facts.repository_id, repository_name, facts.installation_id,
            "peirce-example", repository_name,
            str(self.registry.workspace_root / local_name),
            f"https://github.com/peirce-example/{repository_name}.git", "main",
            str(self.state_root / "reserved" / f"{local_name}.git"),
        )
        if facts != required:
            raise FixedProjectError("production fixed project facts are not exact")

    def _transient_facts(self, observed: ProviderObservation) -> registry.RepositoryFacts:
        repository_id = observed.repository_id
        if repository_id in self._fixed_ids:
            raise FixedProjectError("fixed repository cannot be an ordinary candidate")
        return registry.RepositoryFacts(
            repository_id, f"repository-{repository_id}", observed.installation_id,
            observed.owner, observed.name, str(self.registry.workspace_root / repository_id),
            observed.url, observed.default_branch,
            str(self.state_root / "git" / repository_id),
        )

    @staticmethod
    def _fixed_route(value: FixedProject) -> FixedProject:
        if not isinstance(value, FixedProject):
            raise FixedProjectError("fixed project is invalid")
        route = value
        origin = _origin(route.origin)
        try:
            facts = globals()["registry"].ProjectRegistry.validate_repository_facts(route.repository)
        except globals()["registry"].RegistryError as exc:
            raise FixedProjectError("fixed project facts are invalid") from exc
        if route.layout not in (None, "source", "admin"):
            raise FixedProjectError("fixed project layout is invalid")
        return FixedProject(origin, facts, route.layout)

    def _key(self, origin: TrustedOrigin) -> TrustedOrigin:
        return _origin(origin)

    def _fixed_for(self, origin: TrustedOrigin) -> FixedProject | None:
        return self._fixed.get((origin.workspace_id, origin.channel_id))

    def _dynamic_route(self, origin: TrustedOrigin) -> CurrentProjectRoute | None:
        result = self.registry.active_binding_for_channel(origin.workspace_id, origin.channel_id)
        if result is None:
            return None
        repository_id = result.repository.repository_id
        if repository_id in self._fixed_ids:
            raise FixedProjectError("ordinary channel cannot select a fixed repository")
        return CurrentProjectRoute(origin, result.repository, False)

    def _resolve(self, origin: TrustedOrigin) -> CurrentProjectRoute | None:
        """Read the current route without creating or changing registry state."""
        trusted = self._key(origin)
        fixed = self._fixed_for(trusted)
        if fixed is not None:
            return CurrentProjectRoute(trusted, fixed.repository, True)
        return self._dynamic_route(trusted)

    def show(self, origin: TrustedOrigin) -> CurrentProjectRoute | None:
        return self._resolve(origin)

    def _observe(self, candidate: CanonicalCandidate) -> ProviderObservation:
        if self.provider_reader is None:
            raise ProjectError("provider observation callback is unavailable")
        observed = _observation(self.provider_reader(candidate))
        if observed.repository_id != candidate.repository_id:
            raise ObservationMismatch("provider observation does not match candidate")
        return observed

    def _workspace_descriptor(self, facts: registry.RepositoryFacts) -> host_boundary.RepositoryDescriptor:
        try:
            facts = globals()["registry"].ProjectRegistry.validate_repository_facts(facts)
        except globals()["registry"].RegistryError as exc:
            raise WorkspaceError("repository facts are invalid") from exc
        canonical_url = f"https://github.com/{facts.owner}/{facts.name}.git"
        if (not REPO_PART.fullmatch(facts.owner) or not REPO_PART.fullmatch(facts.name)
                or not _default_branch(facts.default_branch)
                or not host_boundary.is_canonical_github_origin(facts.url)
                or facts.url != canonical_url):
            raise WorkspaceError("repository facts are invalid")
        fixed = self._fixed_by_id.get(facts.repository_id)
        if fixed is not None:
            if fixed.layout is None:
                raise FixedProjectError("fixed repository workspace is not configured")
            if facts != fixed.repository:
                raise FixedProjectError("fixed repository facts do not match configured facts")
            worktree, gitdir = Path(facts.worktree), Path(facts.trusted_gitdir)
            self._validate_production_fixed(fixed)
        else:
            worktree = self.registry.workspace_root / facts.repository_id
            gitdir = self.state_root / "git" / facts.repository_id
            if Path(facts.worktree) != worktree or Path(facts.trusted_gitdir) != gitdir:
                raise WorkspaceError("candidate workspace paths are not ID-derived")
        self._reject_profile_overlap(worktree)
        self._reject_profile_overlap(gitdir)
        return host_boundary.RepositoryDescriptor(facts.repository_id, worktree, gitdir,
                                                  worktree.parent, gitdir.parent,
                                                  facts.owner, facts.name)

    @staticmethod
    def _pair_state(descriptor: host_boundary.RepositoryDescriptor) -> str:
        worktree = descriptor.worktree.exists() or descriptor.worktree.is_symlink()
        gitdir = descriptor.trusted_gitdir.exists() or descriptor.trusted_gitdir.is_symlink()
        return "present" if worktree and gitdir else "partial" if worktree or gitdir else "absent"

    @staticmethod
    def _secret_forms(token: str | None) -> tuple[str, ...]:
        if not token:
            return ()
        encoded = base64.b64encode(f"x-access-token:{token}".encode()).decode()
        return token, encoded

    def _run_git(self, descriptor: host_boundary.RepositoryDescriptor, command: list[str],
                  token: str | None = None,
                   repository_url: str | None = None,
                   anchor: host_boundary.DescriptorAnchor | None = None) -> Mapping[str, Any]:
        if (token is None) != (repository_url is None):
            raise WorkspaceError("workspace Git transport pair is invalid")
        try:
            if anchor is not None:
                argv = host_boundary.sterile_git_argv(descriptor, command, anchor=anchor)
                if token is None and repository_url is None:
                    env = host_boundary.sterile_local_git_environment(state_root=self.state_root)
                else:
                    env = host_boundary.sterile_git_environment(
                        token, state_root=self.state_root, repository_url=repository_url)
                raw = self.process_runner(argv, env=env, pass_fds=anchor.pass_fds,
                                          timeout_seconds=30.0, max_output_bytes=65536)
                if not isinstance(raw, Mapping):
                    raise WorkspaceError("process response is invalid")
                result = host_boundary.redact_process(raw, self._secret_forms(token))
                if any(secret in repr(result) for secret in self._secret_forms(token)):
                    raise WorkspaceError("workspace credential escaped redaction")
                if (result.get("state") not in {"exited", "timed_out", "signaled", "spawn_failed"}
                        or not isinstance(result.get("uncertain"), bool)
                        or not isinstance(result.get("stdout"), str)
                        or not isinstance(result.get("stderr"), str)
                        or (result.get("state") == "exited"
                            and (not isinstance(result.get("exit_code"), int)
                                 or isinstance(result.get("exit_code"), bool)))):
                    raise WorkspaceError("process response is invalid")
                return result
            with host_boundary.DescriptorAnchor(descriptor) as opened:
                return self._run_git(descriptor, command, token, repository_url, opened)
        except WorkspaceError:
            raise
        except host_boundary.BoundaryError:
            raise WorkspaceError("workspace boundary is invalid") from None
        except Exception:
            raise WorkspaceError("workspace process failed") from None

    @staticmethod
    def _process_uncertain(result: Mapping[str, Any]) -> bool:
        uncertainty_facts = result.get("uncertainty_facts")
        return (result.get("state") in {"timed_out", "signaled", "spawn_failed"}
                or bool(result.get("uncertain"))
                or bool(result.get("stdout_truncated"))
                or bool(result.get("stderr_truncated"))
                or (isinstance(uncertainty_facts, Mapping)
                    and any(value not in (None, False, "")
                            for value in uncertainty_facts.values())))

    @classmethod
    def _process_failure(cls, result: Mapping[str, Any]) -> bool:
        return (result.get("state") != "exited" or result.get("exit_code") != 0
                or cls._process_uncertain(result))

    @staticmethod
    def _canonical_fetch_refspec() -> str:
        return "+refs/heads/*:refs/remotes/origin/*"

    @staticmethod
    def _initialize_marker_payload(facts: registry.RepositoryFacts) -> bytes:
        return (f"repository_id={facts.repository_id}\n"
                f"default_branch={facts.default_branch}\n").encode("utf-8")

    def _has_initialize_marker(self, anchor: host_boundary.DescriptorAnchor,
                               facts: registry.RepositoryFacts) -> bool:
        assert anchor.gitdir_fd is not None
        try:
            item = os.stat(INITIALIZE_MARKER, dir_fd=anchor.gitdir_fd,
                           follow_symlinks=False)
        except FileNotFoundError:
            return False
        payload_expected = self._initialize_marker_payload(facts)
        if (not stat.S_ISREG(item.st_mode) or item.st_nlink != 1
                or item.st_uid != os.getuid() or stat.S_IMODE(item.st_mode) != 0o600
                or item.st_size != len(payload_expected)):
            raise WorkspaceError("workspace initialization marker is invalid")
        fd = None
        try:
            fd = os.open(INITIALIZE_MARKER, os.O_RDONLY | os.O_NOFOLLOW,
                         dir_fd=anchor.gitdir_fd)
            opened = os.fstat(fd)
            payload = os.read(fd, item.st_size + 1)
            after = os.fstat(fd)
            def identity(value: os.stat_result) -> tuple[int, ...]:
                return (value.st_dev, value.st_ino, value.st_uid, value.st_mode,
                        value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
            if (identity(opened) != identity(item) or identity(after) != identity(item)
                    or payload != payload_expected):
                raise WorkspaceError("workspace initialization marker is invalid")
        except OSError:
            raise WorkspaceError("workspace initialization marker is invalid") from None
        finally:
            if fd is not None:
                os.close(fd)
        return True

    def _create_initialize_marker(self, anchor: host_boundary.DescriptorAnchor,
                                  facts: registry.RepositoryFacts) -> None:
        assert anchor.gitdir_fd is not None
        fd = None
        try:
            fd = os.open(INITIALIZE_MARKER,
                         os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=anchor.gitdir_fd)
            view = memoryview(self._initialize_marker_payload(facts))
            while view:
                written = os.write(fd, view)
                if written <= 0:
                    raise OSError("short marker write")
                view = view[written:]
            os.fsync(fd)
            os.fsync(anchor.gitdir_fd)
            if not self._has_initialize_marker(anchor, facts):
                raise OSError("marker verification failed")
        except (OSError, WorkspaceError):
            raise _UncertainWorkspace(("initialize_marker",), ()) from None
        finally:
            if fd is not None:
                os.close(fd)

    def _remove_initialize_marker(self, anchor: host_boundary.DescriptorAnchor,
                                  facts: registry.RepositoryFacts) -> None:
        assert anchor.gitdir_fd is not None
        try:
            if not self._has_initialize_marker(anchor, facts):
                raise OSError("marker disappeared")
            os.unlink(INITIALIZE_MARKER, dir_fd=anchor.gitdir_fd)
            os.fsync(anchor.gitdir_fd)
        except (OSError, WorkspaceError):
            try:
                if not self._has_initialize_marker(anchor, facts):
                    self._create_initialize_marker(anchor, facts)
            except (WorkspaceError, _UncertainWorkspace):
                pass
            raise _UncertainWorkspace(("initialize_marker",), ()) from None

    def _validate_bare_metadata(self, descriptor: host_boundary.RepositoryDescriptor,
                                facts: registry.RepositoryFacts, *,
                                allow_incomplete: bool = False,
                                allow_stale_origin: bool = False,
                                anchor: host_boundary.DescriptorAnchor
                                ) -> tuple[Mapping[str, Any], ...]:
        """Validate the sole bare-metadata contract through one pinned descriptor."""
        if anchor.descriptor != descriptor or anchor.gitdir_fd is None:
            raise WorkspaceError("workspace descriptor anchor is invalid")
        try:
            anchor.verify()
        except host_boundary.BoundaryError:
            raise WorkspaceError("workspace pair is unavailable") from None
        try:
            if self._has_initialize_marker(anchor, facts):
                raise WorkspaceError("workspace initialization is in progress")
            for name in ("config", "HEAD"):
                item = os.stat(name, dir_fd=anchor.gitdir_fd, follow_symlinks=False)
                if not stat.S_ISREG(item.st_mode) or item.st_nlink != 1 or item.st_size <= 0:
                    raise WorkspaceError("workspace Git metadata entry is unsafe")
            for name in ("objects", "refs"):
                item = os.stat(name, dir_fd=anchor.gitdir_fd, follow_symlinks=False)
                if not stat.S_ISDIR(item.st_mode):
                    raise WorkspaceError("workspace Git metadata entry is unsafe")
        except FileNotFoundError:
            raise WorkspaceError(
                "workspace Git metadata is incomplete and requires operator attention") from None
        config = self._run_git(descriptor, ["config", "--local", "--null", "--list"],
                               anchor=anchor)
        head = self._run_git(descriptor, ["symbolic-ref", "--quiet", "HEAD"], anchor=anchor)
        uncertain = tuple(label for label, result in (("config", config), ("head", head))
                          if self._process_uncertain(result))
        if uncertain:
            raise _UncertainWorkspace(uncertain, (config, head))
        if self._process_failure(config):
            raise WorkspaceError("workspace Git metadata is invalid")
        raw = config.get("stdout")
        if not isinstance(raw, str):
            raise WorkspaceError("workspace Git configuration is invalid")
        entries: dict[tuple[str, str | None, str], list[str]] = {}
        for item in raw.split("\0"):
            if not item:
                continue
            if "\n" in item:
                key, value = item.split("\n", 1)
            elif "=" in item:
                key, value = item.split("=", 1)
            else:
                raise WorkspaceError("workspace Git configuration is invalid")
            section, separator, remainder = key.partition(".")
            if not separator or not section or not remainder:
                raise WorkspaceError("workspace Git configuration is invalid")
            section = section.lower()
            subsection = None
            setting = remainder
            if section in {"branch", "remote"}:
                subsection, separator, setting = remainder.rpartition(".")
                if not separator or not subsection or not setting:
                    raise WorkspaceError("workspace Git configuration is invalid")
            normalized = (section, subsection, setting.lower())
            entries.setdefault(normalized, []).append(value)
        required = {
            ("core", None, "repositoryformatversion"): ["0"],
            ("core", None, "filemode"): ["true"],
            ("core", None, "bare"): ["true"],
            ("core", None, "logallrefupdates"): ["true"],
            ("core", None, "hookspath"): [os.devnull],
            ("remote", "origin", "url"): [facts.url],
            ("remote", "origin", "fetch"): [self._canonical_fetch_refspec()],
            ("init", None, "defaultbranch"): [facts.default_branch],
            ("user", None, "name"): ["Peirce"],
            ("user", None, "email"): ["peirce@example.invalid"],
            ("branch", facts.default_branch, "remote"): ["origin"],
            ("branch", facts.default_branch, "merge"): [f"refs/heads/{facts.default_branch}"],
        }
        platform = {("core", None, "ignorecase"), ("core", None, "precomposeunicode")}
        branch_settings: dict[str, set[str]] = {}
        for key, values in entries.items():
            if key in required:
                if key[0] == "branch" and key[1] is not None:
                    branch_settings.setdefault(key[1], set()).add(key[2])
                continue
            section, branch, setting = key
            if allow_incomplete and key in platform and len(values) == 1:
                continue
            if (section == "branch" and branch is not None and _default_branch(branch)
                    and setting in {"remote", "merge"} and len(values) == 1
                    and values == (["origin"] if setting == "remote"
                                   else [f"refs/heads/{branch}"])):
                branch_settings.setdefault(branch, set()).add(setting)
                continue
            raise WorkspaceError("workspace Git configuration is unsafe")
        if any(settings != {"remote", "merge"}
               and not (allow_incomplete and branch == facts.default_branch)
               for branch, settings in branch_settings.items()):
            raise WorkspaceError("workspace Git branch configuration is incomplete")
        missing: list[str] = []
        for key, value in required.items():
            actual = entries.get(key)
            if actual is None:
                missing.append(key)
            elif (key == ("remote", "origin", "url") and allow_stale_origin
                  and actual != value and len(actual) == 1
                  and host_boundary.is_canonical_github_origin(actual[0])):
                continue
            elif actual != value:
                raise WorkspaceError("workspace Git configuration is not canonical")
        head_value = self._process_value(head)
        raw_head = self._run_git(
            descriptor, ["rev-parse", "--verify", "HEAD"], anchor=anchor)
        peeled_head = self._run_git(
            descriptor, ["rev-parse", "--verify", "HEAD^{commit}"], anchor=anchor)
        commit_uncertain = tuple(
            label for label, result in (("raw_head", raw_head), ("peeled_head", peeled_head))
            if self._process_uncertain(result))
        if commit_uncertain:
            raise _UncertainWorkspace(commit_uncertain, (config, head, raw_head, peeled_head))
        raw_value = self._process_value(raw_head)
        peeled_value = self._process_value(peeled_head)
        if head_value is not None:
            if (not head_value.startswith("refs/heads/")
                    or not _default_branch(head_value[len("refs/heads/"):])):
                raise WorkspaceError("workspace HEAD is invalid")
            unborn = self._process_failure(raw_head) and self._process_failure(peeled_head)
            if unborn:
                target = self._run_git(
                    descriptor, ["for-each-ref", "--format=%(refname)", head_value],
                    anchor=anchor)
                if self._process_uncertain(target):
                    raise _UncertainWorkspace(
                        ("unborn_ref",), (config, head, raw_head, peeled_head, target))
                if (self._process_failure(target) or target.get("stdout") != ""
                        or target.get("stderr") != ""):
                    raise WorkspaceError("workspace unborn HEAD target is invalid")
            if not unborn and (not raw_value or not FULL_SHA.fullmatch(raw_value)
                               or peeled_value != raw_value):
                raise WorkspaceError("workspace HEAD commit identity is invalid")
        elif (head.get("state") == "exited" and head.get("exit_code") == 1
              and not self._process_uncertain(head)):
            if (not raw_value or not FULL_SHA.fullmatch(raw_value)
                    or peeled_value != raw_value):
                raise WorkspaceError("workspace detached HEAD is invalid")
        else:
            # A normal detached symbolic-ref observation exits exactly one.
            # Other failures include malformed symbolic refs and remain invalid.
            raise WorkspaceError("workspace HEAD is invalid")
        if missing and not allow_incomplete:
            raise _IncompleteWorkspace("workspace Git configuration is incomplete")
        anchor.verify()
        return config, head, raw_head, peeled_head

    def _initialize_workspace(self, descriptor: host_boundary.RepositoryDescriptor,
                              facts: registry.RepositoryFacts, *, needs_init: bool,
                              anchor: host_boundary.DescriptorAnchor) -> list[Mapping[str, Any]]:
        results: list[Mapping[str, Any]] = []
        try:
            if needs_init:
                assert anchor.gitdir_fd is not None
                env = host_boundary.sterile_local_git_environment(state_root=self.state_root)
                argv = [host_boundary.GIT_BIN, "-C", anchor.command_gitdir,
                        "init", "--bare", "--initial-branch", facts.default_branch]
                raw = self.process_runner(argv, env=env, pass_fds=anchor.pass_fds,
                                          timeout_seconds=30.0, max_output_bytes=65536)
                result = host_boundary.redact_process(raw, ()) if isinstance(raw, Mapping) else {}
                results.append(result)
                if self._process_failure(result):
                    return results
            commands = [
                ["config", "--local", "--replace-all", "core.repositoryFormatVersion", "0"],
                ["config", "--local", "--replace-all", "core.fileMode", "true"],
                ["config", "--local", "--replace-all", "core.bare", "true"],
                ["config", "--local", "--replace-all", "core.logAllRefUpdates", "true"],
                ["config", "--local", "--replace-all", "core.hooksPath", os.devnull],
                ["config", "--local", "--replace-all", "remote.origin.url", facts.url],
                ["config", "--local", "--replace-all", "remote.origin.fetch",
                 self._canonical_fetch_refspec()],
                ["config", "--local", "--replace-all", "init.defaultBranch", facts.default_branch],
                ["config", "--local", "--replace-all", "user.name", "Peirce"],
                ["config", "--local", "--replace-all", "user.email", "peirce@example.invalid"],
                ["config", "--local", "--replace-all", f"branch.{facts.default_branch}.remote", "origin"],
                ["config", "--local", "--replace-all", f"branch.{facts.default_branch}.merge",
                 f"refs/heads/{facts.default_branch}"],
                ["config", "--local", "--unset-all", "core.ignoreCase"],
                ["config", "--local", "--unset-all", "core.precomposeUnicode"],
            ]
            for command in commands:
                result = self._run_git(descriptor, command, anchor=anchor)
                # Unset reports one when the platform key was already absent.
                if command[2] == "--unset-all" and result.get("state") == "exited" \
                        and result.get("exit_code") in {1, 5} \
                        and not self._process_uncertain(result):
                    result = dict(result, exit_code=0)
                results.append(result)
                if self._process_failure(result):
                    return results
        except Exception:
            if results:
                results.append({"state": "timed_out", "exit_code": None, "stdout": "",
                                "stderr": "", "uncertain": True,
                                "failure": "workspace_repair_unknown"})
                return results
            raise WorkspaceError("workspace initialization failed") from None
        return results

    @staticmethod
    def _process_value(result: Mapping[str, Any]) -> str | None:
        if (result.get("state") == "exited" and result.get("exit_code") == 0
                and isinstance(result.get("stdout"), str)):
            return result["stdout"].strip() or None
        return None

    def _inspect_workspace(self, facts: registry.RepositoryFacts) -> WorkspaceInspection:
        descriptor = self._workspace_descriptor(facts)
        state = self._pair_state(descriptor)
        base = dict(repository_id=facts.repository_id, worktree=str(descriptor.worktree),
                    trusted_gitdir=str(descriptor.trusted_gitdir))
        if state != "present":
            return WorkspaceInspection(state=state, **base)
        host_boundary.validate_external_git_metadata(descriptor)
        commands = {
            "branch": ["symbolic-ref", "--quiet", "--short", "HEAD"],
            "head": ["rev-parse", "--verify", "HEAD"],
            "upstream": ["rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{upstream}"],
            "dirty": ["status", "--porcelain", "--untracked-files=normal"],
            "counts": ["rev-list", "--left-right", "--count", "HEAD...@{upstream}"],
        }
        try:
            with host_boundary.DescriptorAnchor(descriptor) as anchor:
                self._validate_bare_metadata(descriptor, facts, anchor=anchor)
                results = {name: self._run_git(descriptor, command, anchor=anchor)
                           for name, command in commands.items()}
        except _UncertainWorkspace as exc:
            return WorkspaceInspection(state="partial", **base,
                                       process_uncertainty=exc.labels)
        except (WorkspaceError, host_boundary.BoundaryError):
            return WorkspaceInspection(state="invalid", **base, process_failures=("git_metadata",))
        uncertain = tuple(name for name, result in results.items()
                          if self._process_uncertain(result))
        branch_detached = (results["branch"].get("state") == "exited"
                           and results["branch"].get("exit_code") == 1
                           and not self._process_uncertain(results["branch"]))
        failures = tuple(name for name, result in results.items()
                         if self._process_failure(result) and name not in uncertain
                         and not (name == "branch" and branch_detached))
        dirty_result = results["dirty"]
        dirty = (bool(self._process_value(dirty_result))
                 if dirty_result.get("state") == "exited" and dirty_result.get("exit_code") == 0
                 else None)
        ahead = behind = None
        counts = self._process_value(results["counts"])
        if counts:
            parts = counts.split()
            if len(parts) == 2 and all(part.isdigit() for part in parts):
                ahead, behind = int(parts[0]), int(parts[1])
        branch_value, head_value = self._process_value(results["branch"]), self._process_value(results["head"])
        critical = {"head", "dirty"}
        final_state = "present"
        if critical.intersection(uncertain) or "branch" in uncertain:
            final_state = "partial"
        elif (critical.intersection(failures) or not head_value or dirty is None
              or (branch_detached and not FULL_SHA.fullmatch(head_value))
              or (not branch_detached and ("branch" in failures or not branch_value))):
            final_state = "invalid"
        return WorkspaceInspection(state=final_state, **base, branch=branch_value,
                                   head=head_value,
                                   upstream=self._process_value(results["upstream"]), dirty=dirty,
                                   ahead=ahead, behind=behind, process_uncertainty=uncertain,
                                   process_failures=failures)

    def inspect_workspace(self, facts: registry.RepositoryFacts) -> WorkspaceInspection:
        with host_boundary.repository_lock(facts.repository_id, state_root=self.state_root):
            return self._inspect_workspace(facts)

    def _fresh_workspace_access(self, facts: registry.RepositoryFacts) -> ProviderObservation:
        """Re-observe the exact repository before entering the effect boundary."""
        if not callable(self.provider_reader):
            raise WorkspaceError("provider observation callback is unavailable")
        try:
            observed = _observation(
                self.provider_reader(CanonicalCandidate(
                    facts.owner, facts.name, facts.repository_id))
            )
        except Exception as exc:
            if isinstance(exc, ObservationMismatch):
                raise
            raise WorkspaceError("fresh repository observation failed") from None
        if observed.repository_id != facts.repository_id:
            raise ObservationMismatch("fresh provider observation does not match repository identity")
        return observed

    @staticmethod
    def _uncertain_inspection(facts: registry.RepositoryFacts,
                              labels: tuple[str, ...]) -> WorkspaceInspection:
        return WorkspaceInspection(
            state="partial", repository_id=facts.repository_id,
            worktree=facts.worktree, trusted_gitdir=facts.trusted_gitdir,
            process_uncertainty=labels,
        )

    @staticmethod
    def _effect_inspection(facts: registry.RepositoryFacts, state: str,
                           uncertainty: tuple[str, ...] = (),
                           failures: tuple[str, ...] = ()) -> WorkspaceInspection:
        return WorkspaceInspection(
            state=state, repository_id=facts.repository_id, worktree=facts.worktree,
            trusted_gitdir=facts.trusted_gitdir, process_uncertainty=uncertainty,
            process_failures=failures,
        )

    def initialize_workspace(self, facts: registry.RepositoryFacts) -> WorkspaceEffect:
        """Initialize only the canonical external-gitdir pair and local Git config.

        Reinvocation is an explicit caller choice.  A safely incomplete canonical
        setup may therefore be completed, but this capability never obtains a
        credential, fetches, or checks out a revision.
        """
        descriptor = self._workspace_descriptor(facts)
        with host_boundary.repository_lock(facts.repository_id, state_root=self.state_root):
            state = self._pair_state(descriptor)
            if state == "partial":
                raise WorkspaceError("partial workspace pair requires operator attention")
            if state == "absent":
                host_boundary.assert_real_owned_parent(descriptor.worktree_parent, create=True)
                host_boundary.assert_real_owned_parent(descriptor.gitdir_parent, create=True)
                try:
                    descriptor.worktree.mkdir(mode=0o700)
                    descriptor.trusted_gitdir.mkdir(mode=0o700)
                except OSError as exc:
                    raise WorkspaceError("workspace pair could not be created") from exc
            try:
                host_boundary.validate_external_git_metadata(descriptor)
            except host_boundary.BoundaryError as exc:
                raise WorkspaceError("workspace metadata is invalid") from exc
            processes: list[Mapping[str, Any]] = []
            mutating_process_executed = False
            try:
                with host_boundary.DescriptorAnchor(descriptor) as anchor:
                    assert anchor.gitdir_fd is not None
                    marker = self._has_initialize_marker(anchor, facts)
                    names = os.listdir(anchor.gitdir_fd)
                    needs_init = marker or (state == "absent" or not names)
                    needs_repair = needs_init
                    if needs_init and not marker:
                        # Only an empty legacy/new gitdir may enter the retry protocol.
                        if names:
                            raise WorkspaceError(
                                "workspace Git metadata is incomplete and requires operator attention")
                        self._create_initialize_marker(anchor, facts)
                        marker = True
                    if not needs_init:
                        try:
                            validation = self._validate_bare_metadata(
                                descriptor, facts, anchor=anchor)
                            processes.extend(validation)
                        except _IncompleteWorkspace:
                            self._validate_bare_metadata(
                                descriptor, facts, allow_incomplete=True,
                                allow_stale_origin=True, anchor=anchor)
                            needs_repair = True
                        except WorkspaceError:
                            # Only a canonical subset (including an old canonical
                            # origin and platform-generated core keys) is repairable.
                            self._validate_bare_metadata(
                                descriptor, facts, allow_incomplete=True,
                                allow_stale_origin=True, anchor=anchor)
                            needs_repair = True
                    if needs_repair:
                        initialized = self._initialize_workspace(
                            descriptor, facts, needs_init=needs_init, anchor=anchor)
                        processes.extend(initialized)
                        mutating_process_executed = bool(initialized)
                        failed = next((item for item in initialized
                                       if self._process_failure(item)), None)
                        if failed is not None:
                            uncertain = self._process_uncertain(failed)
                            return WorkspaceEffect(
                                "uncertain" if uncertain else "failed", facts.repository_id,
                                self._effect_inspection(
                                    facts, "partial", ("workspace_write",) if uncertain else (),
                                    () if uncertain else ("workspace_write",)), tuple(processes))
                    if marker:
                        self._remove_initialize_marker(anchor, facts)
                    validation = self._validate_bare_metadata(
                        descriptor, facts, anchor=anchor)
                    processes.extend(validation)
            except _UncertainWorkspace as exc:
                return WorkspaceEffect("uncertain", facts.repository_id,
                                       self._uncertain_inspection(facts, exc.labels),
                                       tuple(processes) + exc.process)
            except WorkspaceError:
                raise
            except host_boundary.BoundaryError:
                if mutating_process_executed:
                    return WorkspaceEffect(
                        "uncertain", facts.repository_id,
                        self._effect_inspection(
                            facts, "partial", ("workspace_write", "descriptor_anchor")),
                        tuple(processes))
                raise WorkspaceError("workspace initialization failed") from None
            except OSError:
                raise WorkspaceError("workspace initialization failed") from None
            return WorkspaceEffect("initialized", facts.repository_id,
                                   self._effect_inspection(facts, "present"), tuple(processes))

    def fetch_workspace(self, facts: registry.RepositoryFacts) -> WorkspaceEffect:
        """Perform one credentialed fetch against an already initialized workspace."""
        descriptor = self._workspace_descriptor(facts)
        with host_boundary.repository_lock(facts.repository_id, state_root=self.state_root):
            if self._pair_state(descriptor) != "present":
                raise WorkspaceError("workspace is not initialized")
            fetch: Mapping[str, Any] | None = None
            try:
                with host_boundary.DescriptorAnchor(descriptor) as anchor:
                    self._validate_bare_metadata(
                        descriptor, facts, allow_stale_origin=True, anchor=anchor)
                    observed = self._fresh_workspace_access(facts)
                    token_descriptor = host_boundary.RepositoryDescriptor(
                        descriptor.repository_id, descriptor.worktree, descriptor.trusted_gitdir,
                        descriptor.worktree_parent, descriptor.gitdir_parent,
                        observed.owner, observed.name)
                    if not callable(self.token_reader):
                        raise WorkspaceError("workspace token callback is unavailable")
                    request = host_boundary.narrow_token_request(
                        facts.repository_id, "workspace_read")
                    request["installation_id"] = int(observed.installation_id)
                    try:
                        token = host_boundary.validate_token_response(
                            self.token_reader(request), token_descriptor, "workspace_read")
                    except Exception:
                        raise WorkspaceError(
                            "workspace credential response is invalid") from None
                    fetch = self._run_git(
                        descriptor, ["fetch", "--prune", observed.url,
                                     self._canonical_fetch_refspec()], token,
                        observed.url, anchor)
            except _IncompleteWorkspace:
                raise WorkspaceError("workspace is not initialized") from None
            except host_boundary.BoundaryError as exc:
                if fetch is not None:
                    return WorkspaceEffect(
                        "uncertain", facts.repository_id,
                        self._effect_inspection(
                            facts, "partial", ("fetch", "descriptor_anchor")), (fetch,))
                raise WorkspaceError("workspace metadata is invalid") from exc
            except _UncertainWorkspace as exc:
                return WorkspaceEffect("uncertain", facts.repository_id,
                                       self._uncertain_inspection(facts, exc.labels), exc.process)
            assert fetch is not None
            if self._process_failure(fetch):
                return WorkspaceEffect("uncertain" if self._process_uncertain(fetch) else "failed",
                                       facts.repository_id,
                                       self._effect_inspection(
                                           facts, "partial",
                                           ("fetch",) if self._process_uncertain(fetch) else (),
                                           () if self._process_uncertain(fetch) else ("fetch",)),
                                       (fetch,))
            return WorkspaceEffect("fetched", facts.repository_id,
                                   self._effect_inspection(facts, "present"), (fetch,))

    def learning_snapshot(self, origin: TrustedOrigin) -> LearningSnapshot:
        """Read the bounded live-learning view for the trusted source route."""
        route = self._resolve(self._key(origin))
        fixed = self._fixed_by_id.get(route.repository_id) if route is not None else None
        if route is None or not route.fixed or fixed is None or fixed.layout != "source":
            raise FixedProjectError("learning snapshot is available only for the fixed source route")
        repository_id = route.repository_id
        root = self.protected_profile_root
        if root is None:
            return LearningSnapshot("unsupported", repository_id)
        try:
            root_item = os.lstat(root)
        except FileNotFoundError:
            return LearningSnapshot("absent", repository_id)
        except OSError:
            return LearningSnapshot("error", repository_id, uncertain=True,
                                    error="profile_unavailable")
        if (stat.S_ISLNK(root_item.st_mode) or not stat.S_ISDIR(root_item.st_mode)
                or root_item.st_uid != os.getuid() or root_item.st_mode & 0o022):
            return LearningSnapshot("error", repository_id, uncertain=True,
                                    error="unsafe_profile_root")

        root_fd: int | None = None
        parent_fd: int | None = None
        entries: list[LearningSnapshotEntry] = []
        pinned_files: dict[str, tuple[int, ...]] = {}
        total = 0
        count = 0
        encountered = 0
        directories = 0

        def file_state(item: os.stat_result) -> tuple[int, ...]:
            return (item.st_dev, item.st_ino, item.st_uid, item.st_mode,
                    item.st_size, item.st_mtime_ns, item.st_ctime_ns, item.st_nlink)

        def directory_state(item: os.stat_result) -> tuple[int, ...]:
            return file_state(item)

        def safe_directory(item: os.stat_result) -> bool:
            return (stat.S_ISDIR(item.st_mode) and not stat.S_ISLNK(item.st_mode)
                    and item.st_uid == os.getuid() and not item.st_mode & 0o022)

        def checked_names(fd: int, *, charge: bool) -> tuple[str, ...]:
            nonlocal encountered
            names: list[str] = []
            with os.scandir(fd) as iterator:
                for item in iterator:
                    if len(names) >= MAX_LEARNING_ENTRIES:
                        raise WorkspaceError("learning tree has too many entries")
                    if charge:
                        encountered += 1
                        if encountered > MAX_LEARNING_ENTRIES:
                            raise WorkspaceError("learning tree has too many entries")
                    names.append(item.name)
            names.sort()
            return tuple(names)

        def open_directory(parent: int, name: str, *, list_entries: bool = False,
                           charge: bool = True
                           ) -> tuple[int, os.stat_result, tuple[str, ...] | None]:
            nonlocal directories
            before = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if not safe_directory(before):
                raise WorkspaceError("unsafe learning directory")
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            current = os.fstat(child)
            if directory_state(current) != directory_state(before) or not safe_directory(current):
                os.close(child)
                raise WorkspaceError("learning directory changed")
            directories += 1
            if directories > MAX_LEARNING_DIRECTORIES:
                os.close(child)
                raise WorkspaceError("learning tree has too many directories")
            try:
                names = checked_names(child, charge=charge) if list_entries else None
            except BaseException:
                os.close(child)
                raise
            return child, before, names

        def verify_directory(parent: int, name: str, fd: int, before: os.stat_result,
                             names: tuple[str, ...] | None) -> None:
            after = os.fstat(fd)
            named = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if (directory_state(after) != directory_state(before)
                    or directory_state(named) != directory_state(before)
                    or not safe_directory(after)
                    or (names is not None and checked_names(fd, charge=False) != names)):
                raise WorkspaceError("learning directory changed")

        def read_file(parent: int, name: str, relative: str) -> None:
            nonlocal count, total
            before = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if (not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode)
                    or before.st_uid != os.getuid() or before.st_mode & 0o7022
                    or before.st_nlink != 1):
                raise WorkspaceError("unsafe learning file")
            if before.st_size > 256 * 1024:
                raise WorkspaceError("learning file is too large")
            count += 1
            if count > 512:
                raise WorkspaceError("too many learning files")
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
            try:
                current = os.fstat(fd)
                if (file_state(current) != file_state(before)
                        or not stat.S_ISREG(current.st_mode) or current.st_nlink != 1):
                    raise WorkspaceError("learning file changed")
                chunks: list[bytes] = []
                remaining = before.st_size
                while remaining:
                    chunk = os.read(fd, min(65536, remaining))
                    if not chunk:
                        raise WorkspaceError("learning file changed")
                    chunks.append(chunk)
                    remaining -= len(chunk)
                if os.read(fd, 1):
                    raise WorkspaceError("learning file changed")
                content = b"".join(chunks)
                after = os.fstat(fd)
                named = os.stat(name, dir_fd=parent, follow_symlinks=False)
                if (file_state(after) != file_state(before)
                        or file_state(named) != file_state(before)
                        or after.st_nlink != 1 or named.st_nlink != 1):
                    raise WorkspaceError("learning file changed")
            finally:
                os.close(fd)
            total += len(content)
            if total > 2 * 1024 * 1024:
                raise WorkspaceError("learning snapshot is too large")
            entries.append(LearningSnapshotEntry(
                relative, len(content), stat.S_IMODE(before.st_mode),
                hashlib.sha256(content).hexdigest(), base64.b64encode(content).decode("ascii")))
            pinned_files[relative] = file_state(before)

        def verify_included_files() -> None:
            for relative, expected in pinned_files.items():
                parts = relative.split("/")
                parent = root_fd
                opened: list[int] = []
                try:
                    for name in parts[:-1]:
                        child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                        dir_fd=parent)
                        opened.append(child)
                        if not safe_directory(os.fstat(child)):
                            raise WorkspaceError("learning directory changed")
                        parent = child
                    current = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
                    if file_state(current) != expected:
                        raise WorkspaceError("learning file changed")
                finally:
                    for fd in reversed(opened):
                        os.close(fd)

        def read_skill_definitions(parent: int) -> None:
            directory_name = "skills"
            fd, before, names = open_directory(parent, directory_name, list_entries=True)
            try:
                assert names is not None
                for name in names:
                    item = os.stat(name, dir_fd=fd, follow_symlinks=False)
                    if stat.S_ISREG(item.st_mode) and not stat.S_ISLNK(item.st_mode):
                        continue
                    if not safe_directory(item):
                        raise WorkspaceError("unsafe learning directory")
                    skill_fd, skill_before, skill_names = open_directory(
                        fd, name)
                    try:
                        try:
                            os.stat("SKILL.md", dir_fd=skill_fd, follow_symlinks=False)
                        except FileNotFoundError:
                            pass
                        else:
                            read_file(skill_fd, "SKILL.md", f"skills/{name}/SKILL.md")
                        verify_directory(fd, name, skill_fd, skill_before, skill_names)
                    finally:
                        os.close(skill_fd)
                verify_directory(parent, directory_name, fd, before, names)
            finally:
                os.close(fd)

        try:
            parent_fd = os.open(root.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            root_fd = os.open(root.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                              dir_fd=parent_fd)
            pinned = os.fstat(root_fd)
            directories = 1
            if directory_state(pinned) != directory_state(root_item) or not safe_directory(pinned):
                raise WorkspaceError("learning root changed")

            try:
                memory_item = os.stat("memories", dir_fd=root_fd, follow_symlinks=False)
            except FileNotFoundError:
                memory_item = None
            if memory_item is not None:
                memories_fd, memories_before, memory_names = open_directory(
                    root_fd, "memories")
                try:
                    for name in ("MEMORY.md", "USER.md"):
                        try:
                            os.stat(name, dir_fd=memories_fd, follow_symlinks=False)
                        except FileNotFoundError:
                            continue
                        else:
                            read_file(memories_fd, name, f"memories/{name}")
                    verify_directory(root_fd, "memories", memories_fd,
                                     memories_before, memory_names)
                finally:
                    os.close(memories_fd)

            try:
                skills_item = os.stat("skills", dir_fd=root_fd, follow_symlinks=False)
            except FileNotFoundError:
                skills_item = None
            if skills_item is not None:
                # Only the learned/reviewed profile-local skill tree is reachable.
                # Bundled Hermes skills live outside this pinned protected root.
                read_skill_definitions(root_fd)

            verify_included_files()
            named_root = os.stat(root.name, dir_fd=parent_fd, follow_symlinks=False)
            final_root = os.fstat(root_fd)
            absolute_root = os.lstat(root)
            if (directory_state(absolute_root) != directory_state(root_item)
                    or stat.S_ISLNK(absolute_root.st_mode)
                    or directory_state(named_root) != directory_state(root_item)
                    or directory_state(final_root) != directory_state(root_item)):
                raise WorkspaceError("learning root changed")
        except (OSError, WorkspaceError):
            return LearningSnapshot("error", repository_id, uncertain=True,
                                    error="unsafe_or_changed_profile")
        finally:
            if root_fd is not None:
                try:
                    os.close(root_fd)
                except OSError:
                    pass
            if parent_fd is not None:
                try:
                    os.close(parent_fd)
                except OSError:
                    pass
        ordered = tuple(sorted(entries, key=lambda item: item.relative_path))
        return LearningSnapshot("supported" if ordered else "empty", repository_id, ordered)

    def set(
        self,
        origin: TrustedOrigin,
        candidate: CanonicalCandidate,
        expected_repository_id: str | None = None,
    ) -> CurrentProjectRoute:
        trusted = self._key(origin)
        selected = _candidate(candidate)
        fixed = self._fixed_for(trusted)
        if fixed is not None:
            raise FixedProjectError("fixed project cannot be mutated")
        if selected.repository_id in self._fixed_ids:
            raise FixedProjectError("ordinary channel cannot select a fixed repository")
        if expected_repository_id is not None:
            _identity(expected_repository_id, numeric=True)
            # A stale first-use compare-and-set can be rejected by a read
            # before creating host lock artifacts in an empty state boundary.
            if not self.registry.db_path.exists():
                current = self.registry.active_binding_for_channel(
                    trusted.workspace_id, trusted.channel_id
                )
                if current is None:
                    raise registry.AssociationConflict("association has changed")
        with host_boundary.ordered_locks(trusted.workspace_id, trusted.channel_id, selected.repository_id,
                                         state_root=self.state_root):
            current = self.registry.active_binding_for_channel(trusted.workspace_id, trusted.channel_id)
            current_id = current.repository.repository_id if current is not None else None
            if current_id in self._fixed_ids:
                raise FixedProjectError("ordinary channel cannot select a fixed repository")
            if (current_id != expected_repository_id and current_id != selected.repository_id
                    or current_id == selected.repository_id
                    and expected_repository_id not in (None, selected.repository_id)):
                raise registry.AssociationConflict("association has changed")
            observed = self._observe(selected)
            result = self.registry._set_association(
                trusted.workspace_id, trusted.channel_id, observed.repository_id,
                observed.installation_id, observed.owner, observed.name, observed.url,
                observed.default_branch, expected_repository_id,
            )
        facts = result.repository
        return CurrentProjectRoute(trusted, facts, False)

    def clear(
        self,
        origin: TrustedOrigin,
        expected_repository_id: str | None = None,
    ) -> registry.BindingFacts | None:
        trusted = self._key(origin)
        if self._fixed_for(trusted) is not None:
            raise FixedProjectError("fixed project cannot be mutated")
        if expected_repository_id is not None:
            _identity(expected_repository_id, numeric=True)
        # An absent database has no association to clear and must not create
        # host lock artifacts in its otherwise-empty state boundary.
        if not self.registry.db_path.exists():
            current = self.registry.active_binding_for_channel(
                trusted.workspace_id, trusted.channel_id
            )
            if current is None:
                if expected_repository_id is not None:
                    raise registry.AssociationConflict("association has changed")
                return None
        # Read while holding the channel lock, then hold the current repository
        # lock as well.  This is the same boundary used by transmissions.
        with host_boundary.channel_lock(trusted.workspace_id, trusted.channel_id, state_root=self.state_root):
            current = self.registry.active_binding_for_channel(trusted.workspace_id, trusted.channel_id)
            current_id = current.repository.repository_id if current is not None else None
            if current_id in self._fixed_ids:
                raise FixedProjectError("ordinary channel cannot select a fixed repository")
            if current_id is None:
                return self.registry._clear_association(
                    trusted.workspace_id, trusted.channel_id, expected_repository_id
                )
            with host_boundary.repository_lock(current_id, state_root=self.state_root):
                return self.registry._clear_association(
                    trusted.workspace_id, trusted.channel_id, expected_repository_id
                )

    @contextmanager
    def locked_current_route(self, origin: TrustedOrigin) -> Iterator[CurrentProjectRoute | None]:
        """Pin a freshly resolved route through a bounded provider transmission."""
        trusted = self._key(origin)
        with host_boundary.channel_lock(trusted.workspace_id, trusted.channel_id, state_root=self.state_root):
            # Resolution after the channel lock is intentional: a set/clear
            # cannot land between this read and the repository lock.
            current = self._resolve(trusted)
            if current is None:
                yield None
                return
            with host_boundary.repository_lock(current.repository_id, state_root=self.state_root):
                route = self._resolve(trusted)
                if route is None:
                    yield None
                else:
                    yield route

    @contextmanager
    def locked_current_channel_route(self, origin: TrustedOrigin) -> Iterator[CurrentProjectRoute | None]:
        """Pin current association while a capability acquires its own repository lock."""
        trusted = self._key(origin)
        with host_boundary.channel_lock(trusted.workspace_id, trusted.channel_id,
                                        state_root=self.state_root):
            yield self._resolve(trusted)


class ChannelBookmarks:
    """Channel-only bookmark capability without repository or registry state."""

    def __init__(self, bookmark_transport: Callable[[str, Mapping[str, Any]], Any]) -> None:
        if not callable(bookmark_transport):
            raise BookmarkError("bookmark transport is unavailable")
        self.bookmark_transport = bookmark_transport

    @staticmethod
    def _key(origin: TrustedOrigin) -> TrustedOrigin:
        return _origin(origin)

    def _slack(self, operation: str, payload: Mapping[str, Any]) -> Any:
        return self.bookmark_transport(operation, payload)

    def list_bookmarks(self, origin: TrustedOrigin) -> BookmarkObservation:
        trusted = self._key(origin)
        try:
            response = self._slack("list", {"channel_id": trusted.channel_id})
        except Exception as exc:
            return BookmarkObservation(trusted.channel_id, (), True, type(exc).__name__)
        if isinstance(response, dict) and response.get("ok") is False:
            return BookmarkObservation(trusted.channel_id, (), True,
                                        str(response.get("error", "provider_rejected")))
        if (not isinstance(response, dict) or response.get("ok") is not True
                or not isinstance(response.get("bookmarks"), list)):
            return BookmarkObservation(trusted.channel_id, (), True, "invalid_response")
        try:
            return BookmarkObservation(trusted.channel_id, tuple(
                _bookmark_value(item, trusted.channel_id) for item in response["bookmarks"]))
        except BookmarkError:
            return BookmarkObservation(trusted.channel_id, (), True, "invalid_response")

    def add_bookmark(self, origin: TrustedOrigin, title: str, url: str) -> BookmarkEffect:
        trusted = self._key(origin)
        title, url = _printable(title, 300, "title"), _bookmark_url(url)
        try:
            response = self._slack("add", {"channel_id": trusted.channel_id,
                                            "title": title, "type": "link", "link": url})
        except Exception as exc:
            return BookmarkEffect("uncertain", trusted.channel_id, uncertain=True,
                                  error=type(exc).__name__)
        if isinstance(response, dict) and response.get("ok") is False:
            error = str(response.get("error", "provider_rejected"))
            uncertain = self._slack_error_uncertain(error)
            return BookmarkEffect("uncertain" if uncertain else "no_effect", trusted.channel_id,
                                  uncertain=uncertain, error=error)
        if (not isinstance(response, dict) or response.get("ok") is not True
                or "bookmark" not in response):
            return BookmarkEffect("uncertain", trusted.channel_id, uncertain=True,
                                  error="invalid_response")
        try:
            item = _bookmark_value(response["bookmark"], trusted.channel_id)
        except BookmarkError:
            return BookmarkEffect("uncertain", trusted.channel_id, uncertain=True,
                                  error="invalid_response")
        if item.title != title or item.url != url:
            return BookmarkEffect("uncertain", trusted.channel_id, uncertain=True,
                                  error="mismatched_response")
        return BookmarkEffect("added", trusted.channel_id, item, item.bookmark_id)

    def delete_bookmark(self, origin: TrustedOrigin, bookmark_id: str) -> BookmarkEffect:
        trusted = self._key(origin)
        bookmark_id = _printable(bookmark_id, 128, "ID")
        try:
            response = self._slack("delete", {"channel_id": trusted.channel_id,
                                              "bookmark_id": bookmark_id})
        except Exception as exc:
            return BookmarkEffect("uncertain", trusted.channel_id, bookmark_id=bookmark_id,
                                  uncertain=True, error=type(exc).__name__)
        if isinstance(response, dict) and response.get("ok") is False:
            error = str(response.get("error", "provider_rejected"))
            uncertain = error != "not_found" and self._slack_error_uncertain(error)
            return BookmarkEffect("uncertain" if uncertain else "no_effect", trusted.channel_id,
                                  bookmark_id=bookmark_id, uncertain=uncertain, error=error)
        if (not isinstance(response, dict) or response.get("ok") is not True
                or ("bookmark_id" in response and response["bookmark_id"] != bookmark_id)):
            return BookmarkEffect("uncertain", trusted.channel_id, bookmark_id=bookmark_id,
                                  uncertain=True, error="invalid_response")
        if "deleted" in response and response["deleted"] is not True:
            return BookmarkEffect("no_effect", trusted.channel_id, bookmark_id=bookmark_id)
        return BookmarkEffect("deleted", trusted.channel_id, bookmark_id=bookmark_id)

    @staticmethod
    def _slack_error_uncertain(error: str) -> bool:
        return error in {"internal_error", "fatal_error", "request_timeout",
                         "service_unavailable", "temporarily_unavailable"}

__all__ = [
    "TrustedOrigin", "CanonicalCandidate", "RepositoryLocator", "ProviderObservation",
    "WorkspaceInspection", "WorkspaceEffect", "Bookmark", "ChannelBookmarks",
    "BookmarkObservation", "BookmarkEffect", "FixedProject",
    "LearningSnapshotEntry", "LearningSnapshot", "build_peirce_isolated_projects",
    "CurrentProjectRoute", "ProjectGateway", "ProjectError", "FixedProjectError",
    "ObservationMismatch", "WorkspaceError", "BookmarkError",
]
