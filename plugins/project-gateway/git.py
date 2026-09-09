# SPDX-License-Identifier: AGPL-3.0-only
"""Bounded local Git composition and one-shot remote effects."""

from __future__ import annotations

import base64
from dataclasses import dataclass, replace
import os
import re
import secrets
import stat
from typing import Any, Mapping, Sequence

from . import host_boundary, project, registry


SHA = re.compile(r"^[0-9a-f]{40}$")
MAX_PATHS = 256
MAX_MESSAGE = 16_384


class GitError(ValueError):
    """A request or a pre-effect observation failed closed."""


@dataclass(frozen=True)
class GitObservation:
    state: str
    repository_id: str
    branch: str | None = None
    sha: str | None = None
    process: Mapping[str, Any] | None = None
    uncertain: bool = False
    anchor_state: str | None = None
    local_state: str | None = None


@dataclass(frozen=True)
class GitEffect:
    effect: str
    repository_id: str
    branch: str | None = None
    commit: str | None = None
    parent: str | None = None
    process: Mapping[str, Any] | None = None
    uncertain: bool = False
    anchor_state: str | None = None
    local_state: str | None = None


def git_policy_help() -> Mapping[str, Any]:
    return {
        "scope": "exact current repository",
        "run": {
            "observations": sorted(_READ_FLAGS),
            "local_effects": ["branch", "switch", "checkout", "add", "restore", "clean",
                              "merge --no-edit <full-SHA>", "commit --no-edit during merge",
                              "merge --abort during merge"],
            "branch_rule": "safe non-default branch",
            "paths": "explicit literal repository-relative paths",
        },
        "direct_actions": ["commit", "remote_ref", "push", "delete_remote_branch",
                            "checkout_default"],
        "checkout_default": {
            "expected_head": ("full lowercase SHA; explicit null only for freshly observed "
                              "canonical unborn default"),
        },
        "publication": "standard fast-forward task work only; remote default update unavailable",
    }


def _safe_path(value: Any) -> bool:
    return (isinstance(value, str) and bool(value) and len(value) <= 4096
            and not value.startswith(("/", "-")) and "\x00" not in value
            and "\\" not in value and value[0] not in "!^"
            and not any(char in value for char in "*?[]{}:")
            and all(part not in {"", ".", "..", ".git"} for part in value.split("/")))


def _safe_branch(value: Any) -> bool:
    return isinstance(value, str) and project._default_branch(value) and not value.endswith(".lock")


def _work_branch(value: Any, facts: registry.RepositoryFacts) -> bool:
    return _safe_branch(value) and value != facts.default_branch


def _paths(values: Any) -> list[str]:
    if (not isinstance(values, (list, tuple)) or not values or len(values) > MAX_PATHS
            or any(not _safe_path(value) for value in values)):
        raise GitError("paths must be explicit literal relative paths")
    result = list(dict.fromkeys(values))
    if len(result) != len(values):
        raise GitError("paths must be deduplicated")
    return result


_READ_FLAGS = {
    "status": {"--short", "--porcelain", "--porcelain=v1", "--branch",
               "--untracked-files=no", "--untracked-files=normal", "--untracked-files=all"},
    "diff": {"--cached", "--staged", "--stat", "--name-only", "--name-status",
             "--no-renames", "--check", "--quiet", "--exit-code"},
    "log": {"--oneline", "--decorate", "--no-decorate", "--stat", "--name-only",
            "--no-merges", "--first-parent", "--all"},
    "show": {"--stat", "--name-only", "--name-status", "--oneline", "--no-renames"},
    "rev-parse": {"--verify", "--short", "--abbrev-ref", "--symbolic-full-name",
                  "--is-inside-work-tree"},
    "rev-list": {"--count", "--left-right", "--parents", "--first-parent", "--all"},
    "ls-files": {"--cached", "--deleted", "--modified", "--others", "--exclude-standard", "--stage"},
}


def validate_run_argv(argv: Any, facts: registry.RepositoryFacts) -> list[str]:
    if (not isinstance(argv, list) or not argv or len(argv) > 64
            or any(not isinstance(item, str) or not item or len(item) > 4096 for item in argv)
            or argv[0] == "git" or argv[0].startswith("-")):
        raise GitError("invalid Git argv")
    command, args = argv[0], argv[1:]
    if command == "branch":
        if args in ([], ["--show-current"], ["--list"], ["--all"]):
            return argv
        if len(args) == 1 and _work_branch(args[0], facts):
            return argv
        if len(args) == 2 and args[0] == "-D" and _work_branch(args[1], facts):
            return argv
        raise GitError("branch form is unavailable")
    if command in _READ_FLAGS:
        separated = False
        for item in args:
            if item == "--":
                if separated:
                    raise GitError("duplicate path separator")
                separated = True
            elif separated:
                if not _safe_path(item):
                    raise GitError("unsafe literal path")
            elif item.startswith("-"):
                if item not in _READ_FLAGS[command]:
                    raise GitError("Git option is unavailable")
            elif command in {"log", "show", "rev-parse", "rev-list"}:
                if not (SHA.fullmatch(item) or item in {"HEAD", "@{upstream}"} or _safe_branch(item)):
                    raise GitError("Git revision is unavailable")
            else:
                raise GitError("path operands require --")
        return argv
    if command in {"switch", "checkout"}:
        create = {"switch": {"--create", "-c"}, "checkout": {"--branch", "-b"}}[command]
        if len(args) == 1 and (_work_branch(args[0], facts)
                               or (command == "checkout" and SHA.fullmatch(args[0]))):
            return argv
        if len(args) == 2 and args[0] in create and _work_branch(args[1], facts):
            return argv
        raise GitError("checkout form is unavailable")
    if command == "merge":
        if args == ["--abort"]:
            return argv
        if len(args) == 2 and args[0] == "--no-edit" and SHA.fullmatch(args[1]):
            return argv
        raise GitError("merge form is unavailable")
    if command == "commit":
        if args == ["--no-edit"]:
            return argv
        raise GitError("commit form is unavailable")
    if command == "add" and len(args) >= 2 and args[0] == "--":
        _paths(args[1:])
        return argv
    if command == "restore" and len(args) >= 5 and args[:4] == [
            "--source=HEAD", "--staged", "--worktree", "--"]:
        _paths(args[4:])
        return argv
    if command == "clean" and len(args) >= 3 and args[:2] == ["-fd", "--"]:
        _paths(args[2:])
        return argv
    raise GitError("Git command is unavailable")


@dataclass(frozen=True)
class _IndexBaseline:
    data: bytes
    existed: bool
    mode: int
    device: int | None
    inode: int | None

    @classmethod
    def capture(cls, anchor: host_boundary.DescriptorAnchor) -> "_IndexBaseline":
        assert anchor.gitdir_fd is not None
        try:
            named = os.stat("index", dir_fd=anchor.gitdir_fd, follow_symlinks=False)
        except FileNotFoundError:
            return cls(b"", False, 0o600, None, None)
        if not stat.S_ISREG(named.st_mode) or named.st_size > 64 * 1024 * 1024:
            raise GitError("index is unsafe or too large")
        fd = os.open("index", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=anchor.gitdir_fd)
        try:
            opened = os.fstat(fd)
            chunks: list[bytes] = []
            while True:
                value = os.read(fd, 1024 * 1024)
                if not value:
                    break
                chunks.append(value)
            closed = os.fstat(fd)
        finally:
            os.close(fd)
        again = os.stat("index", dir_fd=anchor.gitdir_fd, follow_symlinks=False)
        identity = (named.st_dev, named.st_ino, named.st_size)
        if ((opened.st_dev, opened.st_ino, opened.st_size) != identity
                or (closed.st_dev, closed.st_ino, closed.st_size) != identity
                or (again.st_dev, again.st_ino, again.st_size) != identity
                or sum(map(len, chunks)) != named.st_size):
            raise GitError("index changed while being captured")
        return cls(b"".join(chunks), True, stat.S_IMODE(named.st_mode), named.st_dev, named.st_ino)

    def matches(self, anchor: host_boundary.DescriptorAnchor) -> bool:
        assert anchor.gitdir_fd is not None
        try:
            current = _IndexBaseline.capture(anchor)
        except (GitError, OSError):
            return False
        return (current.data, current.existed, current.mode, current.device, current.inode) == \
            (self.data, self.existed, self.mode, self.device, self.inode)


class ProjectGit:
    def __init__(self, gateway: project.ProjectGateway) -> None:
        if not isinstance(gateway, project.ProjectGateway):
            raise GitError("project gateway is invalid")
        self.gateway = gateway

    def _descriptor(self, facts: registry.RepositoryFacts) -> host_boundary.RepositoryDescriptor:
        try:
            return self.gateway._workspace_descriptor(facts)
        except project.ProjectError as exc:
            raise GitError("repository descriptor is invalid") from exc

    @staticmethod
    def _check_expected(route: project.CurrentProjectRoute | None, expected: str) -> project.CurrentProjectRoute:
        if not isinstance(expected, str) or not expected.isdigit():
            raise GitError("expected repository ID is invalid")
        if route is None or route.repository_id != expected:
            raise GitError("current repository changed")
        return route

    @staticmethod
    def _status(result: Mapping[str, Any]) -> str:
        if result.get("state") == "exited" and result.get("exit_code") == 0 \
                and result.get("uncertain") is False \
                and not result.get("stdout_truncated") and not result.get("stderr_truncated"):
            return "success"
        if result.get("state") in {"exited", "spawn_failed", "rejected"} \
                and result.get("uncertain") is False \
                and not result.get("stdout_truncated") and not result.get("stderr_truncated"):
            return "failure"
        return "uncertain"

    @staticmethod
    def _uncertain(result: Mapping[str, Any]) -> bool:
        return ProjectGit._status(result) == "uncertain"

    @staticmethod
    def _well_formed_process_result(result: Mapping[str, Any]) -> bool:
        state = result.get("state")
        code = result.get("exit_code")
        return (state in {"exited", "timed_out", "signaled", "spawn_failed", "rejected"}
                and "exit_code" in result
                and isinstance(result.get("stdout"), str)
                and isinstance(result.get("stderr"), str)
                and isinstance(result.get("uncertain"), bool)
                and isinstance(result.get("stdout_truncated"), bool)
                and isinstance(result.get("stderr_truncated"), bool)
                and ((state == "exited" and isinstance(code, int)
                      and not isinstance(code, bool))
                     or (state != "exited" and code is None)))

    def _process(self, descriptor: host_boundary.RepositoryDescriptor,
                 command: Sequence[str], anchor: host_boundary.DescriptorAnchor, *,
                 token: str | None = None, url: str | None = None,
                  env_extra: Mapping[str, str] | None = None,
                  stdin: str | bytes | None = None) -> Mapping[str, Any]:
        if (token is None) != (url is None):
            raise GitError("Git transport pair is invalid")
        forms: tuple[str, ...] = ()
        if token:
            encoded = base64.b64encode(f"x-access-token:{token}".encode()).decode()
            forms = (token, encoded, f"Basic {encoded}")
        invoked = False
        try:
            argv = host_boundary.sterile_git_argv(descriptor, command, anchor=anchor)
            if token is None and url is None:
                env = host_boundary.sterile_local_git_environment(
                    state_root=self.gateway.state_root)
            else:
                env = host_boundary.sterile_git_environment(
                    token, state_root=self.gateway.state_root, repository_url=url)
            if env_extra:
                expected_root = re.escape(anchor.command_gitdir.rstrip("/"))
                index = env_extra.get("GIT_INDEX_FILE", "")
                if (set(env_extra) != {
                        "GIT_INDEX_FILE", "GIT_LITERAL_PATHSPECS", "GIT_OPTIONAL_LOCKS"}
                        or env_extra.get("GIT_LITERAL_PATHSPECS") != "1"
                        or env_extra.get("GIT_OPTIONAL_LOCKS") != "0"
                        or not re.fullmatch(
                            expected_root + r"/gateway-index-[0-9a-f]{32}/index", index)):
                    raise GitError("private Git environment is invalid")
                env.update(env_extra)
            # Recheck after all invocation preparation, immediately before the
            # externally supplied runner can observe or execute the command.
            anchor.verify()
            invoked = True
            raw = self.gateway.process_runner(
                argv, env=env, stdin=stdin, pass_fds=anchor.pass_fds,
                timeout_seconds=30.0, max_output_bytes=65536)
            if not isinstance(raw, Mapping):
                raise TypeError
            result = host_boundary.redact_process(raw, forms)
            if not self._well_formed_process_result(result):
                raise TypeError
            if any(secret and secret in repr(result) for secret in forms):
                raise TypeError
            return result
        except Exception:
            if invoked:
                return {"state": "timed_out", "exit_code": None, "stdout": "", "stderr": "",
                        "uncertain": True, "stdout_truncated": False,
                        "stderr_truncated": False, "failure": "runner_result_unknown"}
            return {"state": "spawn_failed", "exit_code": None, "stdout": "", "stderr": "",
                    "uncertain": False, "stdout_truncated": False,
                    "stderr_truncated": False, "failure": "runner_unavailable"}

    def _must(self, descriptor: host_boundary.RepositoryDescriptor, command: Sequence[str],
              anchor: host_boundary.DescriptorAnchor, **kwargs: Any) -> Mapping[str, Any]:
        result = self._process(descriptor, command, anchor, **kwargs)
        if self._status(result) != "success":
            raise GitError("local Git observation or effect failed")
        return result

    def _value(self, descriptor: host_boundary.RepositoryDescriptor, command: Sequence[str],
               anchor: host_boundary.DescriptorAnchor, **kwargs: Any) -> str:
        return str(self._must(descriptor, command, anchor, **kwargs).get("stdout", "")).strip()

    @staticmethod
    def _close_anchor(anchor: host_boundary.DescriptorAnchor, result: GitEffect | GitObservation | None = None):
        changed = False
        try:
            anchor.verify()
        except BaseException:
            changed = True
        finally:
            anchor.close()
        if changed:
            if result is None:
                raise GitError("descriptor path changed")
            if isinstance(result, GitEffect):
                return replace(result, effect="unknown", uncertain=True,
                               anchor_state="changed", local_state=None)
            return replace(result, state="unknown", uncertain=True,
                           anchor_state="changed", local_state=None)
        return result

    def _open(self, descriptor: host_boundary.RepositoryDescriptor) -> host_boundary.DescriptorAnchor:
        try:
            return host_boundary.DescriptorAnchor(descriptor).__enter__()
        except Exception as exc:
            raise GitError("repository anchor is unavailable") from exc

    def _validate_open(self, descriptor: host_boundary.RepositoryDescriptor,
                       facts: registry.RepositoryFacts,
                       anchor: host_boundary.DescriptorAnchor
                       ) -> tuple[Mapping[str, Any], ...]:
        """Apply the complete local metadata contract through the action's anchor."""
        try:
            return self.gateway._validate_bare_metadata(descriptor, facts, anchor=anchor)
        except (project.ProjectError, host_boundary.BoundaryError, OSError):
            raise GitError("repository metadata is invalid") from None

    def _require_merge_head(self, descriptor: host_boundary.RepositoryDescriptor,
                            anchor: host_boundary.DescriptorAnchor) -> None:
        """Require an exact in-progress merge marker through the pinned gitdir."""
        if anchor.gitdir_fd is None:
            raise GitError("repository anchor is unavailable")
        fd: int | None = None
        try:
            named = os.stat("MERGE_HEAD", dir_fd=anchor.gitdir_fd, follow_symlinks=False)
            if (not stat.S_ISREG(named.st_mode) or named.st_uid != os.getuid()
                    or named.st_nlink != 1 or named.st_mode & 0o022 or named.st_size != 41):
                raise GitError("merge state is unsafe")
            fd = os.open("MERGE_HEAD", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=anchor.gitdir_fd)
            opened = os.fstat(fd)
            data = os.read(fd, 42)
            closed = os.fstat(fd)
            again = os.stat("MERGE_HEAD", dir_fd=anchor.gitdir_fd, follow_symlinks=False)
            identity = (named.st_dev, named.st_ino, named.st_mode, named.st_size,
                        named.st_mtime_ns, named.st_ctime_ns)
            if any((item.st_dev, item.st_ino, item.st_mode, item.st_size,
                    item.st_mtime_ns, item.st_ctime_ns) != identity
                   for item in (opened, closed, again)):
                raise GitError("merge state changed")
            text = data.decode("ascii")
            if len(data) != 41 or not text.endswith("\n") or not SHA.fullmatch(text[:-1]):
                raise GitError("merge state is malformed")
            self._resolve_exact_commit(descriptor, text[:-1], anchor)
            anchor.verify()
        except GitError:
            raise
        except (OSError, UnicodeError) as exc:
            raise GitError("merge is not verifiably in progress") from exc
        finally:
            if fd is not None:
                os.close(fd)

    def _require_no_merge_head(self, descriptor: host_boundary.RepositoryDescriptor,
                               anchor: host_boundary.DescriptorAnchor) -> None:
        if anchor.gitdir_fd is None:
            raise GitError("repository anchor is unavailable")
        try:
            os.stat("MERGE_HEAD", dir_fd=anchor.gitdir_fd, follow_symlinks=False)
        except FileNotFoundError:
            anchor.verify()
            return
        except OSError as exc:
            raise GitError("merge state is unsafe") from exc
        self._require_merge_head(descriptor, anchor)
        raise GitError("dedicated commit is unavailable during a merge")

    @staticmethod
    def _require_no_merge_autostash(anchor: host_boundary.DescriptorAnchor) -> None:
        if anchor.gitdir_fd is None:
            raise GitError("repository anchor is unavailable")
        try:
            os.stat("MERGE_AUTOSTASH", dir_fd=anchor.gitdir_fd, follow_symlinks=False)
        except FileNotFoundError:
            anchor.verify()
            return
        except OSError as exc:
            raise GitError("merge autostash state is unsafe") from exc
        raise GitError("merge autostash state is unavailable")

    def _merge_state(self, descriptor: host_boundary.RepositoryDescriptor,
                     anchor: host_boundary.DescriptorAnchor) -> str:
        if anchor.gitdir_fd is None:
            return "unverifiable"
        try:
            os.stat("MERGE_HEAD", dir_fd=anchor.gitdir_fd, follow_symlinks=False)
        except FileNotFoundError:
            try:
                anchor.verify()
            except Exception:
                return "unverifiable"
            return "absent"
        except OSError:
            return "unverifiable"
        try:
            self._require_merge_head(descriptor, anchor)
        except GitError:
            return "unverifiable"
        return "valid"

    def _resolve_exact_commit(self, descriptor: host_boundary.RepositoryDescriptor,
                              sha: str, anchor: host_boundary.DescriptorAnchor) -> str:
        expression = f"{sha}^{{commit}}"
        resolved = self._process(descriptor, ["rev-parse", "--verify", expression], anchor)
        if (self._status(resolved) != "success"
                or str(resolved.get("stdout", "")).strip() != sha):
            raise GitError("Git commit object is unavailable or uncertain")
        return expression

    def _reject_default_merge(self, descriptor: host_boundary.RepositoryDescriptor,
                              facts: registry.RepositoryFacts,
                              anchor: host_boundary.DescriptorAnchor) -> None:
        observed = self._process(
            descriptor, ["symbolic-ref", "--quiet", "--short", "HEAD"], anchor)
        status = self._status(observed)
        if status == "uncertain":
            raise GitError("symbolic HEAD is uncertain")
        if status == "success" and str(observed.get("stdout", "")).strip() == facts.default_branch:
            raise GitError("merge is unavailable on the default branch")
        if status != "success" and not self._detached_symbolic_failure(observed):
            raise GitError("symbolic HEAD is invalid")

    @staticmethod
    def _detached_symbolic_failure(result: Mapping[str, Any]) -> bool:
        return (result.get("state") == "exited" and result.get("exit_code") == 1
                and result.get("uncertain") is False
                and not result.get("stdout_truncated") and not result.get("stderr_truncated"))

    def run(self, origin: project.TrustedOrigin, expected_repository_id: str,
            argv: list[str]) -> GitObservation | GitEffect:
        with self.gateway.locked_current_route(origin) as current:
            route = self._check_expected(current, expected_repository_id)
            command = validate_run_argv(argv, route.repository)
            execution = command
            requested_detached = (command[1] if len(command) == 2
                                  and command[0] == "checkout" and SHA.fullmatch(command[1])
                                  else None)
            merge_start = command[:2] == ["merge", "--no-edit"]
            merge_completion = command == ["commit", "--no-edit"]
            merge_abort = command == ["merge", "--abort"]
            descriptor = self._descriptor(route.repository)
            anchor = self._open(descriptor)
            result: GitObservation | GitEffect | None = None
            try:
                self._validate_open(descriptor, route.repository, anchor)
                if merge_start or merge_completion or merge_abort:
                    self._require_no_merge_autostash(anchor)
                if merge_completion or merge_abort:
                    self._require_merge_head(descriptor, anchor)
                if merge_start or merge_completion:
                    self._reject_default_merge(descriptor, route.repository, anchor)
                if requested_detached is not None:
                    expression = self._resolve_exact_commit(
                        descriptor, requested_detached, anchor)
                    execution = ["checkout", "--detach", expression]
                elif merge_start:
                    expression = self._resolve_exact_commit(descriptor, command[2], anchor)
                    execution = ["merge", "--no-edit", expression]
                if command[0] == "branch" and len(command) == 3 and command[1] in {"-d", "--delete", "-D"}:
                    current_branch = self._value(descriptor, ["branch", "--show-current"], anchor)
                    if command[2] == current_branch:
                        raise GitError("current branch cannot be deleted")
                process = self._process(descriptor, execution, anchor)
                mutation = command[0] in {"add", "restore", "clean", "switch", "checkout",
                                          "merge", "commit"} \
                    or (command[0] == "branch" and command[1:] not in ([], ["--show-current"], ["--list"], ["--all"]))
                if mutation:
                    status = self._status(process)
                    result = GitEffect("applied" if status == "success" else
                                       ("failed" if status == "failure" else "unknown"),
                                       route.repository_id, process=process,
                                       uncertain=status == "uncertain")
                    if status == "failure" and (merge_start or merge_completion or merge_abort):
                        merge_state = self._merge_state(descriptor, anchor)
                        if merge_state == "valid":
                            result = replace(result, local_state="merge_in_progress")
                        elif merge_state == "unverifiable":
                            result = replace(result, effect="unknown", uncertain=True,
                                             local_state="merge_state_unverified")
                        else:
                            result = replace(result, effect="unknown", uncertain=True,
                                             local_state="merge_state_absent_after_failure")
                    if status == "success" and command[0] in {
                            "branch", "switch", "checkout", "merge", "commit"}:
                        try:
                            self._validate_open(descriptor, route.repository, anchor)
                        except GitError:
                            result = replace(result, effect="unknown", uncertain=True,
                                             local_state="metadata_invalid_after_effect")
                    if status == "success" and requested_detached is not None \
                            and result.effect == "applied":
                        symbolic = self._process(
                            descriptor, ["symbolic-ref", "--quiet", "--short", "HEAD"], anchor)
                        resolved = self._process(
                            descriptor, ["rev-parse", "--verify", "HEAD^{commit}"], anchor)
                        if (not self._detached_symbolic_failure(symbolic)
                                or self._status(resolved) != "success"
                                or str(resolved.get("stdout", "")).strip() != requested_detached):
                            result = replace(result, effect="unknown", uncertain=True,
                                             local_state="detached_post_state_unverified")
                else:
                    status = self._status(process)
                    result = GitObservation("observed" if status == "success" else
                                            ("failed" if status == "failure" else "unknown"),
                                            route.repository_id, process=process,
                                            uncertain=status == "uncertain")
            finally:
                result = self._close_anchor(anchor, result)
            assert result is not None
            return result

    @staticmethod
    def _inside(path: str, requested: Sequence[str]) -> bool:
        return any(path == item or path.startswith(item.rstrip("/") + "/") for item in requested)

    def _zpaths(self, descriptor: host_boundary.RepositoryDescriptor, command: Sequence[str],
                anchor: host_boundary.DescriptorAnchor, **kwargs: Any) -> list[str]:
        raw = self._value(descriptor, command, anchor, **kwargs)
        return sorted(item for item in raw.split("\0") if item)

    def _branch_head(self, descriptor: host_boundary.RepositoryDescriptor,
                      anchor: host_boundary.DescriptorAnchor) -> tuple[str, str]:
        return (self._value(descriptor, ["symbolic-ref", "--quiet", "--short", "HEAD"], anchor),
                self._value(descriptor, ["rev-parse", "--verify", "HEAD"], anchor))

    @staticmethod
    def _exact_missing_head(result: Mapping[str, Any]) -> bool:
        code = result.get("exit_code")
        return (result.get("state") == "exited" and isinstance(code, int)
                and not isinstance(code, bool) and code == 128 and result.get("stdout") == ""
                and isinstance(result.get("stderr"), str)
                and result.get("uncertain") is False
                and result.get("stdout_truncated") is False
                and result.get("stderr_truncated") is False)

    def _branch_head_or_unborn(
        self,
        descriptor: host_boundary.RepositoryDescriptor,
        anchor: host_boundary.DescriptorAnchor,
        validated: tuple[Mapping[str, Any], ...],
    ) -> tuple[str, str | None]:
        """Reobserve HEAD, accepting absence only after exact canonical unborn proof."""
        branch = self._value(
            descriptor, ["symbolic-ref", "--quiet", "--short", "HEAD"], anchor)
        head = self._process(descriptor, ["rev-parse", "--verify", "HEAD"], anchor)
        if self._status(head) == "success":
            value = str(head.get("stdout", "")).strip()
            if not SHA.fullmatch(value):
                raise GitError("HEAD is malformed")
            return branch, value
        if len(validated) != 4 or not self._exact_missing_head(head):
            raise GitError("HEAD is unavailable or uncertain")
        _, symbolic, raw_head, peeled_head = validated
        if (self._status(symbolic) != "success"
                or str(symbolic.get("stdout", "")).strip() != f"refs/heads/{branch}"
                or not self._exact_missing_head(raw_head)
                or not self._exact_missing_head(peeled_head)):
            raise GitError("HEAD absence is not canonical")
        return branch, None

    @staticmethod
    def _write_all(fd: int, data: bytes) -> None:
        view = memoryview(data)
        while view:
            count = os.write(fd, view)
            if count <= 0:
                raise OSError("short write")
            view = view[count:]

    def commit(self, origin: project.TrustedOrigin, expected_repository_id: str,
               paths: Sequence[str], message: str, expected_head: str,
               expected_branch: str) -> GitEffect:
        if not SHA.fullmatch(expected_head if isinstance(expected_head, str) else ""):
            raise GitError("expected HEAD must be a full lowercase SHA")
        if (not isinstance(message, str) or not message.strip() or len(message) > MAX_MESSAGE
                or "\x00" in message):
            raise GitError("commit message is invalid")
        with self.gateway.locked_current_route(origin) as current:
            route = self._check_expected(current, expected_repository_id)
            requested = _paths(paths)
            if not _work_branch(expected_branch, route.repository):
                raise GitError("commit branch is outside task policy")
            descriptor = self._descriptor(route.repository)
            anchor = self._open(descriptor)
            result: GitEffect | None = None
            private = f"gateway-index-{secrets.token_hex(16)}"
            private_fd: int | None = None
            lock_fd: int | None = None
            own_lock = False
            try:
                self._validate_open(descriptor, route.repository, anchor)
                if self._branch_head(descriptor, anchor) != (expected_branch, expected_head):
                    raise GitError("branch or HEAD changed")
                self._require_no_merge_head(descriptor, anchor)
                baseline = _IndexBaseline.capture(anchor)
                assert anchor.gitdir_fd is not None
                os.mkdir(private, 0o700, dir_fd=anchor.gitdir_fd)
                private_fd = os.open(private, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                     dir_fd=anchor.gitdir_fd)
                index_name = f"{anchor.command_gitdir}/{private}/index"
                env = {"GIT_INDEX_FILE": index_name, "GIT_LITERAL_PATHSPECS": "1",
                       "GIT_OPTIONAL_LOCKS": "0"}
                if baseline.existed:
                    fd = os.open("index", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                 baseline.mode, dir_fd=private_fd)
                    try:
                        self._write_all(fd, baseline.data)
                    finally:
                        os.close(fd)
                    staged = self._zpaths(descriptor,
                        ["diff", "--cached", "--name-only", "--no-renames", "-z", expected_head],
                        anchor, env_extra=env)
                    if any(not self._inside(path, requested) for path in staged):
                        raise GitError("unrelated staged paths need reconciliation")
                self._must(descriptor, ["read-tree", expected_head], anchor, env_extra=env)
                self._must(descriptor, ["add", "-A", "--", *requested], anchor, env_extra=env)
                delta = self._zpaths(descriptor,
                    ["diff", "--cached", "--name-only", "--no-renames", "-z", expected_head],
                    anchor, env_extra=env)
                if not delta:
                    raise GitError("commit has no delta")
                if any(not _safe_path(path) or not self._inside(path, requested)
                       or not _safe_path(path) for path in delta):
                    raise GitError("candidate commit escaped path policy")

                def drifted() -> bool:
                    changed = self._zpaths(descriptor,
                        ["diff", "--name-only", "--no-renames", "-z", "--", *requested],
                        anchor, env_extra=env)
                    untracked = self._zpaths(descriptor,
                        ["ls-files", "--others", "--exclude-standard", "-z", "--", *requested],
                        anchor, env_extra=env)
                    return bool(changed or untracked)

                if drifted():
                    raise GitError("requested worktree changed during candidate construction")
                if self._branch_head(descriptor, anchor) != (expected_branch, expected_head):
                    raise GitError("branch or HEAD changed during candidate construction")
                if drifted():
                    raise GitError("requested worktree changed before publication")
                try:
                    lock_fd = os.open("index.lock", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                      baseline.mode, dir_fd=anchor.gitdir_fd)
                    own_lock = True
                except FileExistsError as exc:
                    raise GitError("index is concurrently locked") from exc
                if not baseline.matches(anchor):
                    raise GitError("shared index changed concurrently")
                candidate_fd = os.open("index", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=private_fd)
                try:
                    candidate = b""
                    while True:
                        chunk = os.read(candidate_fd, 1024 * 1024)
                        if not chunk:
                            break
                        candidate += chunk
                finally:
                    os.close(candidate_fd)
                self._write_all(lock_fd, candidate)
                os.fchmod(lock_fd, baseline.mode)
                os.fsync(lock_fd)
                tree = self._value(descriptor, ["write-tree"], anchor, env_extra=env)
                if not SHA.fullmatch(tree):
                    raise GitError("candidate tree is malformed")
                commit_process = self._process(descriptor,
                    ["commit-tree", tree, "-p", expected_head], anchor, stdin=message)
                commit_sha = str(commit_process.get("stdout", "")).strip()
                if self._status(commit_process) != "success" or not SHA.fullmatch(commit_sha):
                    branch = self._process(descriptor,
                        ["rev-parse", "--verify", f"refs/heads/{expected_branch}"], anchor)
                    observed = str(branch.get("stdout", "")).strip()
                    if (SHA.fullmatch(commit_sha) and self._status(branch) == "success"
                            and observed == commit_sha):
                        try:
                            os.close(lock_fd)
                            lock_fd = None
                            os.rename("index.lock", "index", src_dir_fd=anchor.gitdir_fd,
                                      dst_dir_fd=anchor.gitdir_fd)
                            own_lock = False
                            os.fsync(anchor.gitdir_fd)
                            local_state = "index_published"
                        except OSError:
                            local_state = "index_publication_unknown"
                        result = GitEffect("committed", route.repository_id, expected_branch,
                                           commit_sha, expected_head, commit_process,
                                           local_state != "index_published",
                                           local_state=local_state)
                    else:
                        state = ("old" if self._status(branch) == "success"
                                 and observed == expected_head else "unreadable")
                        result = GitEffect("no_effect" if state == "old" else "unknown",
                                           route.repository_id, expected_branch, parent=expected_head,
                                           process=commit_process, uncertain=state != "old", local_state=state)
                else:
                    update = self._process(descriptor,
                        ["update-ref", "-m", "project-gateway direct commit",
                         f"refs/heads/{expected_branch}", commit_sha, expected_head], anchor)
                    observed_process = self._process(descriptor,
                        ["rev-parse", "--verify", f"refs/heads/{expected_branch}"], anchor)
                    observed = str(observed_process.get("stdout", "")).strip()
                    if self._status(observed_process) == "success" and observed == commit_sha:
                        try:
                            os.close(lock_fd)
                            lock_fd = None
                            os.rename("index.lock", "index", src_dir_fd=anchor.gitdir_fd,
                                      dst_dir_fd=anchor.gitdir_fd)
                            own_lock = False
                            os.fsync(anchor.gitdir_fd)
                            local_state = "index_published"
                        except OSError:
                            local_state = "index_publication_unknown"
                        result = GitEffect("committed", route.repository_id, expected_branch,
                                           commit_sha, expected_head, update,
                                           local_state != "index_published",
                                           local_state=local_state)
                    elif self._status(observed_process) == "success" and observed == expected_head:
                        result = GitEffect("no_effect", route.repository_id, expected_branch,
                                           commit_sha, expected_head, update, False, local_state="old")
                    else:
                        result = GitEffect("unknown", route.repository_id, expected_branch,
                                           commit_sha, expected_head, update, True, local_state="unreadable")
            finally:
                if lock_fd is not None:
                    try:
                        os.close(lock_fd)
                    except OSError:
                        pass
                if own_lock and anchor.gitdir_fd is not None:
                    try:
                        os.unlink("index.lock", dir_fd=anchor.gitdir_fd)
                    except OSError:
                        pass
                if private_fd is not None:
                    try:
                        for name in os.listdir(private_fd):
                            try:
                                os.unlink(name, dir_fd=private_fd)
                            except OSError:
                                pass
                        os.close(private_fd)
                        private_fd = None
                        assert anchor.gitdir_fd is not None
                        os.rmdir(private, dir_fd=anchor.gitdir_fd)
                    except OSError:
                        pass
                result = self._close_anchor(anchor, result)
            assert result is not None
            return result

    def _fresh(self, facts: registry.RepositoryFacts) -> project.ProviderObservation:
        if not callable(self.gateway.provider_reader):
            raise GitError("provider observation callback is unavailable")
        try:
            observed = project._observation(
                self.gateway.provider_reader(project.CanonicalCandidate(
                    facts.owner, facts.name, facts.repository_id)))
        except Exception:
            raise GitError("fresh provider observation failed") from None
        if observed.repository_id != facts.repository_id:
            raise GitError("fresh provider route changed")
        return observed

    def _preflight_local(self, facts: registry.RepositoryFacts) -> None:
        """Reject poisoned route-derived metadata before any provider observation."""
        descriptor = self._descriptor(facts)
        anchor = self._open(descriptor)
        try:
            self._validate_open(descriptor, facts, anchor)
        finally:
            self._close_anchor(anchor)

    def _fresh_descriptor(self, facts: registry.RepositoryFacts,
                           observed: project.ProviderObservation) -> host_boundary.RepositoryDescriptor:
        local = self._descriptor(facts)
        return host_boundary.RepositoryDescriptor(
            local.repository_id, local.worktree, local.trusted_gitdir,
            local.worktree_parent, local.gitdir_parent, observed.owner, observed.name)

    def _token(self, observed: project.ProviderObservation, profile: str,
               descriptor: host_boundary.RepositoryDescriptor) -> str:
        if not callable(self.gateway.token_reader):
            raise GitError("Git token callback is unavailable")
        try:
            request = host_boundary.narrow_token_request(observed.repository_id, profile)
            request["installation_id"] = int(observed.installation_id)
            return host_boundary.validate_token_response(
                self.gateway.token_reader(request), descriptor, profile)
        except Exception:
            raise GitError("Git credential response is invalid") from None

    def _remote(self, descriptor: host_boundary.RepositoryDescriptor,
                observed: project.ProviderObservation, token: str, branches: Sequence[str],
                anchor: host_boundary.DescriptorAnchor) -> Mapping[str, Any]:
        return self._process(descriptor,
            ["ls-remote", "--heads", observed.url, *[f"refs/heads/{b}" for b in branches]],
            anchor, token=token, url=observed.url)

    @staticmethod
    def _parse_remote(result: Mapping[str, Any], branches: Sequence[str]) -> dict[str, str | None] | None:
        if ProjectGit._status(result) != "success":
            return None
        expected = {f"refs/heads/{branch}": branch for branch in branches}
        values = {branch: None for branch in branches}
        for line in str(result.get("stdout", "")).splitlines():
            parts = line.split("\t")
            if (len(parts) != 2 or not SHA.fullmatch(parts[0]) or parts[1] not in expected
                    or values[expected[parts[1]]] is not None):
                return None
            values[expected[parts[1]]] = parts[0]
        return values

    def remote_ref(self, origin: project.TrustedOrigin, expected_repository_id: str,
                   branch: str) -> GitObservation:
        if not _safe_branch(branch):
            raise GitError("branch is invalid")
        with self.gateway.locked_current_route(origin) as current:
            route = self._check_expected(current, expected_repository_id)
            self._preflight_local(route.repository)
            observed = self._fresh(route.repository)
            descriptor = self._fresh_descriptor(route.repository, observed)
            anchor = self._open(descriptor)
            result: GitObservation | None = None
            try:
                self._validate_open(descriptor, route.repository, anchor)
                token = self._token(observed, "git_remote_read", descriptor)
                process = self._remote(descriptor, observed, token, [branch], anchor)
                parsed = self._parse_remote(process, [branch])
                if parsed is None:
                    result = GitObservation("unknown", route.repository_id, branch,
                                            process=process, uncertain=True)
                else:
                    sha = parsed[branch]
                    result = GitObservation("present" if sha else "absent",
                                            route.repository_id, branch, sha, process)
            finally:
                result = self._close_anchor(anchor, result)
            assert result is not None
            return result

    def push(self, origin: project.TrustedOrigin, expected_repository_id: str, branch: str,
             commit: str, expected_base: str) -> GitEffect:
        if not SHA.fullmatch(commit if isinstance(commit, str) else "") \
                or not SHA.fullmatch(expected_base if isinstance(expected_base, str) else ""):
            raise GitError("push SHAs must be full lowercase values")
        if commit == expected_base:
            raise GitError("local push range is empty")
        with self.gateway.locked_current_route(origin) as current:
            route = self._check_expected(current, expected_repository_id)
            if not _work_branch(branch, route.repository):
                raise GitError("push branch is outside task policy")
            self._preflight_local(route.repository)
            observed = self._fresh(route.repository)
            if branch == observed.default_branch:
                raise GitError("push branch is outside task policy")
            descriptor = self._fresh_descriptor(route.repository, observed)
            anchor = self._open(descriptor)
            result: GitEffect | None = None
            try:
                self._validate_open(descriptor, route.repository, anchor)
                if self._branch_head(descriptor, anchor) != (branch, commit):
                    raise GitError("local branch does not identify the push commit")
                self._resolve_exact_commit(descriptor, commit, anchor)
                self._must(
                    descriptor, ["merge-base", "--is-ancestor", expected_base, commit], anchor)
                token = self._token(observed, "git_push_delete", descriptor)
                preflight = self._remote(descriptor, observed, token,
                                         [branch, observed.default_branch], anchor)
                parsed = self._parse_remote(preflight, [branch, observed.default_branch])
                if parsed is None:
                    raise GitError("remote preflight is unknown")
                target, default = parsed[branch], parsed[observed.default_branch]
                if target == commit:
                    result = GitEffect("already_published", route.repository_id, branch,
                                       commit, expected_base, preflight)
                elif target != expected_base and not (target is None and default == expected_base):
                    raise GitError("remote branch diverged from expected base")
                else:
                    process = self._process(descriptor,
                        ["push", "--porcelain", observed.url,
                         f"{commit}^{{commit}}:refs/heads/{branch}"],
                        anchor, token=token, url=observed.url)
                    status = self._status(process)
                    if status == "success":
                        result = GitEffect("published", route.repository_id, branch,
                                           commit, expected_base, process)
                    else:
                        result = GitEffect("unknown", route.repository_id, branch,
                                           commit, expected_base, process, uncertain=True)
            finally:
                result = self._close_anchor(anchor, result)
            assert result is not None
            return result

    @staticmethod
    def _lease_rejected(result: Mapping[str, Any]) -> bool:
        if ProjectGit._status(result) != "failure" or result.get("stdout_truncated") \
                or result.get("stderr_truncated"):
            return False
        text = f"{result.get('stdout', '')}\n{result.get('stderr', '')}".lower()
        return "[rejected]" in text and ("stale info" in text or "stale-info" in text)

    def delete_remote_branch(self, origin: project.TrustedOrigin, expected_repository_id: str,
                             branch: str, expected_sha: str) -> GitEffect:
        if not _safe_branch(branch) or not SHA.fullmatch(expected_sha if isinstance(expected_sha, str) else ""):
            raise GitError("remote deletion request is invalid")
        with self.gateway.locked_current_route(origin) as current:
            route = self._check_expected(current, expected_repository_id)
            if branch == route.repository.default_branch:
                raise GitError("default branch cannot be deleted")
            self._preflight_local(route.repository)
            observed = self._fresh(route.repository)
            if branch == observed.default_branch:
                raise GitError("default branch cannot be deleted")
            descriptor = self._fresh_descriptor(route.repository, observed)
            anchor = self._open(descriptor)
            result: GitEffect | None = None
            try:
                self._validate_open(descriptor, route.repository, anchor)
                token = self._token(observed, "git_push_delete", descriptor)
                preflight = self._remote(descriptor, observed, token, [branch], anchor)
                parsed = self._parse_remote(preflight, [branch])
                if parsed is None:
                    raise GitError("remote preflight is unknown")
                if parsed[branch] is None:
                    result = GitEffect("no_effect", route.repository_id, branch,
                                       expected_sha, process=preflight, local_state="absent")
                elif parsed[branch] != expected_sha:
                    raise GitError("remote branch diverged from expected SHA")
                else:
                    process = self._process(descriptor,
                        ["push", "--porcelain",
                         f"--force-with-lease=refs/heads/{branch}:{expected_sha}",
                         observed.url, f":refs/heads/{branch}"], anchor,
                        token=token, url=observed.url)
                    if self._status(process) == "success":
                        result = GitEffect("deleted", route.repository_id, branch,
                                           expected_sha, process=process)
                    elif process.get("state") == "spawn_failed":
                        result = GitEffect("no_effect", route.repository_id, branch,
                                           expected_sha, process=process, local_state="not_attempted")
                    elif self._lease_rejected(process):
                        result = GitEffect("no_effect", route.repository_id, branch,
                                           expected_sha, process=process, local_state="lease_rejected")
                    else:
                        result = GitEffect("unknown", route.repository_id, branch,
                                           expected_sha, process=process, uncertain=True)
            finally:
                result = self._close_anchor(anchor, result)
            assert result is not None
            return result

    def checkout_default(self, origin: project.TrustedOrigin, expected_repository_id: str,
                          expected_branch: str, expected_head: str | None,
                          expected_target: str) -> GitEffect:
        if (not _safe_branch(expected_branch)
                or (expected_head is not None and not SHA.fullmatch(
                    expected_head if isinstance(expected_head, str) else "")) or not SHA.fullmatch(
                expected_target if isinstance(expected_target, str) else "")):
            raise GitError("default synchronization expectations are invalid")
        with self.gateway.locked_current_route(origin) as current:
            route = self._check_expected(current, expected_repository_id)
            self._preflight_local(route.repository)
            observed = self._fresh(route.repository)
            if expected_head is None and expected_branch != observed.default_branch:
                raise GitError("unborn branch does not match fresh default branch")
            descriptor = self._fresh_descriptor(route.repository, observed)
            anchor = self._open(descriptor)
            result: GitEffect | None = None
            try:
                validated = self._validate_open(descriptor, route.repository, anchor)
                if self._branch_head_or_unborn(
                        descriptor, anchor, validated) != (expected_branch, expected_head):
                    raise GitError("branch or HEAD changed")
                status = self._value(descriptor,
                    ["status", "--porcelain=v1", "--untracked-files=all"], anchor)
                if status:
                    raise GitError("workspace must be completely clean")
                target_expression = self._resolve_exact_commit(
                    descriptor, expected_target, anchor)
                target_ref = f"refs/remotes/origin/{observed.default_branch}"
                target = self._value(descriptor, ["rev-parse", "--verify", target_ref], anchor)
                if target != expected_target:
                    raise GitError("default target changed")
                validated = self._validate_open(descriptor, route.repository, anchor)
                if self._branch_head_or_unborn(
                        descriptor, anchor, validated) != (expected_branch, expected_head):
                    raise GitError("branch or HEAD changed before checkout")
                branch_mode = "-b" if expected_head is None else "-B"
                checkout = self._process(descriptor,
                    ["checkout", "--no-recurse-submodules", "--no-overwrite-ignore",
                     branch_mode, observed.default_branch, target_expression], anchor)
                if self._status(checkout) == "success":
                    observations = {
                        "branch": self._process(descriptor,
                            ["symbolic-ref", "--quiet", "--short", "HEAD"], anchor),
                        "head": self._process(descriptor,
                            ["rev-parse", "--verify", "HEAD"], anchor),
                        "upstream": self._process(descriptor,
                            ["rev-parse", "--abbrev-ref", "@{upstream}"], anchor),
                        "clean": self._process(descriptor,
                            ["status", "--porcelain=v1", "--untracked-files=all"], anchor),
                        "target": self._process(descriptor,
                            ["rev-parse", "--verify", target_ref], anchor),
                    }
                    failed = [name for name, value in observations.items()
                              if self._status(value) != "success"]
                    values = {name: str(value.get("stdout", "")).strip()
                              for name, value in observations.items()}
                    head = values["head"] if SHA.fullmatch(values["head"]) else None
                    if head != expected_target and "head" not in failed:
                        failed.append("head")
                    expected_upstream = f"origin/{observed.default_branch}"
                    for name, valid in (
                        ("branch", values["branch"] == observed.default_branch),
                        ("upstream", values["upstream"] == expected_upstream),
                        ("clean", not values["clean"]),
                        ("target", values["target"] == expected_target),
                    ):
                        if not valid and name not in failed:
                            failed.append(name)
                    if failed:
                        local_state = "post_observation_uncertain:" + ",".join(sorted(failed))
                    else:
                        local_state = (f"branch={values['branch']};head={values['head']};"
                                       f"upstream={values['upstream']};"
                                       f"clean={'true' if not values['clean'] else 'false'};"
                                       f"target={values['target']}")
                    result = GitEffect("unknown" if failed else "checked_out", route.repository_id,
                                       observed.default_branch, head, expected_head, checkout,
                                       uncertain=bool(failed), local_state=local_state)
                    try:
                        self._validate_open(descriptor, route.repository, anchor)
                    except GitError:
                        detail = (f"{result.local_state};metadata_invalid_after_effect"
                                  if result.local_state and result.local_state.startswith(
                                      "post_observation_uncertain:")
                                  else "metadata_invalid_after_effect")
                        result = replace(result, effect="unknown", uncertain=True,
                                         local_state=detail)
                else:
                    result = GitEffect("unknown", route.repository_id,
                                       observed.default_branch, parent=expected_head,
                                       process=checkout, uncertain=True,
                                       local_state="checkout_unknown")
            finally:
                result = self._close_anchor(anchor, result)
            assert result is not None
            return result


__all__ = ["GitError", "GitObservation", "GitEffect", "ProjectGit", "validate_run_argv",
           "git_policy_help"]
