# SPDX-License-Identifier: AGPL-3.0-only
"""Exact-current-repository GitHub collaboration and independent risk reports."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from enum import Enum
import json
import os
from pathlib import Path
import re
import tempfile
from types import MappingProxyType
from typing import Any, Callable, Mapping, Sequence
from urllib.parse import parse_qs, urlsplit
import unicodedata

from . import cli_runner, host_boundary, project


GH_BIN = "/opt/slack-hermes/bin/gh"
GH_HOST = "github.com"
GITHUB_API_VERSION = "2026-03-10"
# Illustrative, unverified example organization; deployment must adapt this
# host-owned fixed destination without weakening repository identity checks.
ADMIN_OWNER = "peirce-example"
ADMIN_NAME = "peirce-admin"
MAX_ARGV = 64
MAX_VALUE = 4096
MAX_STDIN_BYTES = 64 * 1024
MAX_OUTPUT_BYTES = 64 * 1024
TIMEOUT_SECONDS = 30.0
MAX_API_RESPONSE_BYTES = 64 * 1024
POSITIVE_ID = re.compile(r"^[1-9][0-9]{0,8}$")
REPOSITORY_ID = re.compile(r"^[0-9]+$")
REPO_PART = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")
TRUSTED_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class GitHubError(ValueError):
    """A GitHub request failed a host-owned policy or identity boundary."""


class _APIUncertain(Exception):
    pass


@dataclass(frozen=True)
class GitHubResult:
    state: str
    effect: str
    repository_id: str
    process: Mapping[str, Any] | None = None
    evidence: tuple[Mapping[str, Any], ...] = ()
    uncertain: bool = False


@dataclass(frozen=True)
class CommentDeleteResult:
    state: str
    effect: str
    repository_id: str
    comment_kind: str
    parent_number: int
    comment_id: int
    evidence: tuple[Mapping[str, Any], ...]
    uncertain: bool = False


@dataclass(frozen=True)
class RiskReportResult:
    state: str
    effect: str
    repository_id: str
    process: Mapping[str, Any] | None = None
    evidence: tuple[Mapping[str, Any], ...] = ()
    uncertain: bool = False


class RiskSource(str, Enum):
    SLACK = "slack"


class RiskCategory(str, Enum):
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    CIRCUMVENTION = "circumvention"
    PERSISTENT_ABUSE = "persistent_abuse"
    OTHER_SIGNIFICANT_RISK = "other_significant_risk"


@dataclass(frozen=True)
class TrustedRiskEvent:
    source: RiskSource
    workspace_id: str
    channel_id: str
    event_id: str

    def __post_init__(self) -> None:
        if not isinstance(self.source, RiskSource) or any(
                not isinstance(value, str) or not TRUSTED_ID.fullmatch(value)
                for value in (self.workspace_id, self.channel_id, self.event_id)):
            raise GitHubError("trusted risk event is invalid")


def _flag(arity: int = 0, kind: str = "literal") -> Mapping[str, Any]:
    return MappingProxyType({"arity": arity, "kind": kind})


_READ = {"--json": _flag(1, "fields")}
_LIST = {**_READ, "--assignee": _flag(1), "--author": _flag(1), "--label": _flag(1),
         "--limit": _flag(1, "number"), "--milestone": _flag(1), "--state": _flag(1, "state")}
_POLICY_RAW: dict[tuple[str, str], dict[str, Any]] = {
    ("issue", "list"): {"flags": _LIST, "pos": (0, 0, "none"), "effect": "read"},
    ("issue", "view"): {"flags": {"--comments": _flag(), "--json": _flag(1, "fields")}, "pos": (1, 1, "number"), "effect": "read"},
    ("issue", "create"): {"flags": {"--title": _flag(1), "--body": _flag(1), "--body-file": _flag(1, "stdin"), "--label": _flag(1), "--assignee": _flag(1), "--milestone": _flag(1)}, "pos": (0, 0, "none"), "effect": "create"},
    ("issue", "edit"): {"flags": {"--title": _flag(1), "--body": _flag(1), "--body-file": _flag(1, "stdin"), "--add-label": _flag(1), "--remove-label": _flag(1), "--add-assignee": _flag(1), "--remove-assignee": _flag(1), "--milestone": _flag(1)}, "pos": (1, 1, "number"), "effect": "update"},
    ("issue", "close"): {"flags": {"--reason": _flag(1, "reason")}, "pos": (1, 1, "number"), "effect": "update"},
    ("issue", "reopen"): {"flags": {}, "pos": (1, 1, "number"), "effect": "update"},
    ("issue", "comment"): {"flags": {"--body": _flag(1), "--body-file": _flag(1, "stdin")}, "pos": (1, 1, "number"), "effect": "comment"},
    ("pr", "list"): {"flags": {**_LIST, "--base": _flag(1, "branch"),
                                  "--head": _flag(1, "branch")}, "pos": (0, 0, "none"), "effect": "read"},
    ("pr", "view"): {"flags": {"--comments": _flag(), "--json": _flag(1, "fields")}, "pos": (1, 1, "number"), "effect": "read"},
    ("pr", "create"): {"flags": {"--title": _flag(1), "--body": _flag(1), "--body-file": _flag(1, "stdin"), "--draft": _flag(), "--head": _flag(1, "branch"), "--base": _flag(1, "branch"), "--label": _flag(1), "--reviewer": _flag(1), "--milestone": _flag(1)}, "pos": (0, 0, "none"), "effect": "create"},
    ("pr", "edit"): {"flags": {"--title": _flag(1), "--body": _flag(1), "--body-file": _flag(1, "stdin"), "--base": _flag(1, "branch"), "--add-label": _flag(1), "--remove-label": _flag(1), "--milestone": _flag(1)}, "pos": (1, 1, "number"), "effect": "update"},
    ("pr", "close"): {"flags": {}, "pos": (1, 1, "number"), "effect": "update"},
    ("pr", "reopen"): {"flags": {}, "pos": (1, 1, "number"), "effect": "update"},
    ("pr", "comment"): {"flags": {"--body": _flag(1), "--body-file": _flag(1, "stdin")}, "pos": (1, 1, "number"), "effect": "comment"},
    ("pr", "checks"): {"flags": {"--required": _flag(), "--watch": _flag(), "--fail-fast": _flag(), "--interval": _flag(1, "number")}, "pos": (1, 1, "number"), "effect": "read"},
    ("pr", "diff"): {"flags": {"--patch": _flag(), "--name-only": _flag(), "--stat": _flag()}, "pos": (0, 1, "number"), "effect": "read"},
    ("pr", "status"): {"flags": {}, "pos": (0, 0, "none"), "effect": "read"},
    ("repo", "view"): {"flags": {"--json": _flag(1, "fields")}, "pos": (0, 0, "none"), "effect": "read"},
}
HIGH_LEVEL_POLICY = MappingProxyType({key: MappingProxyType(value) for key, value in _POLICY_RAW.items()})
API_METHOD_EFFECT = MappingProxyType({"GET": "read", "HEAD": "read", "POST": "create",
                                      "PATCH": "update", "PUT": "update", "DELETE": "delete"})
FORBIDDEN_FAMILIES = ("contents", "files", "git", "data", "ref", "refs", "merge", "merges",
    "forks", "branches", "branch", "protection", "rulesets", "releases", "deployments",
    "collaborators", "teams", "keys", "hooks", "actions", "secrets", "variables", "workflows",
    "environments", "pages", "admin", "administration", "settings")
FORBIDDEN_FLAGS = {"--repo", "-R", "--hostname", "--host", "--with-token", "--header", "-H",
    "--config", "--file", "--json-file", "--input-file", "--jq", "--template", "--help", "-h",
    "--web", "--editor", "--browser", "--fork"}
IDENTITY_ALIASES = {"headrepo", "headrepository", "baserepo", "baserepository"}
JSON_FIELDS = {
    "issue": {"assignees", "author", "body", "closed", "closedAt", "comments", "createdAt",
              "id", "labels", "milestone", "number", "state", "title", "updatedAt", "url"},
    "pr": {"additions", "assignees", "author", "baseRefName", "body", "changedFiles",
           "closedAt", "comments", "commits", "createdAt", "deletions", "files", "headRefName",
           "id", "labels", "mergeStateStatus", "mergeable", "mergedAt", "milestone", "number",
           "reviewDecision", "reviews", "state", "statusCheckRollup", "title", "updatedAt", "url"},
    "repo": {"name", "nameWithOwner", "owner", "id", "url", "isPrivate", "visibility",
             "defaultBranchRef", "description"},
}


def _argv_shape(argv: Any) -> list[str]:
    if (not isinstance(argv, list) or not argv or len(argv) > MAX_ARGV
            or any(not isinstance(v, str) or not v or len(v) > MAX_VALUE or "\x00" in v for v in argv)):
        raise GitHubError("invalid GitHub argv")
    for value in argv:
        flag = value.partition("=")[0]
        if flag in FORBIDDEN_FLAGS or value.startswith(("http://", "https://", "ssh://", "git@")):
            raise GitHubError("GitHub routing, credentials, files, and native help are unavailable")
    if argv[0] in {"auth", "config", "alias", "extension", "graphql", "release", "workflow", "run"}:
        raise GitHubError("GitHub command is unavailable")
    return argv


def _value(kind: str, value: str, command: str) -> None:
    if not value or len(value) > MAX_VALUE or "\x00" in value:
        raise GitHubError("GitHub value is invalid")
    if kind == "number" and not POSITIVE_ID.fullmatch(value):
        raise GitHubError("positive bounded integer required")
    if kind == "state" and value not in {"open", "closed", "all"}:
        raise GitHubError("state is invalid")
    if kind == "reason" and value not in {"completed", "not planned", "duplicate"}:
        raise GitHubError("close reason is invalid")
    if kind == "branch" and (":" in value or value.startswith(("/", "-"))
            or not re.fullmatch(r"[A-Za-z0-9._/@+-]{1,255}", value)):
        raise GitHubError("branch must be explicit and unqualified")
    if kind == "stdin" and value != "-":
        raise GitHubError("body file must be bounded stdin")
    if kind == "fields":
        fields = value.split(",")
        if not fields or any(field not in JSON_FIELDS[command] for field in fields):
            raise GitHubError("JSON fields are outside exact command policy")


def _high_level(argv: list[str]) -> str:
    if len(argv) < 2 or (argv[0], argv[1]) not in HIGH_LEVEL_POLICY:
        raise GitHubError("GitHub command or subcommand is unavailable")
    spec = HIGH_LEVEL_POLICY[(argv[0], argv[1])]
    operands: list[str] = []
    seen: set[str] = set()
    index = 2
    while index < len(argv):
        item = argv[index]
        if item == "--":
            raise GitHubError("operand separator is unavailable")
        if item.startswith("-"):
            flag, equals, inline = item.partition("=")
            rule = spec["flags"].get(flag)
            if rule is None:
                raise GitHubError("GitHub flag is outside exact command policy")
            seen.add(flag)
            if rule["arity"] == 0:
                if equals:
                    raise GitHubError("flag does not take a value")
            else:
                if equals:
                    value = inline
                else:
                    index += 1
                    if index >= len(argv) or (argv[index].startswith("-") and argv[index] != "-"):
                        raise GitHubError("flag value is missing")
                    value = argv[index]
                _value(rule["kind"], value, argv[0])
        else:
            operands.append(item)
        index += 1
    minimum, maximum, grammar = spec["pos"]
    if not minimum <= len(operands) <= maximum or (grammar == "number" and any(
            not POSITIVE_ID.fullmatch(item) for item in operands)):
        raise GitHubError("GitHub operands are invalid")
    if (argv[0], argv[1]) == ("pr", "create") and "--head" not in seen:
        raise GitHubError("pull request creation requires explicit --head")
    return str(spec["effect"])


def _normalized(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.casefold())


def _identity_field(key: str, value: str, owner: str | None, name: str | None) -> None:
    normalized = _normalized(key)
    if normalized in IDENTITY_ALIASES:
        raise GitHubError("repository selector field is unavailable")
    if normalized == "head" and ":" in value:
        raise GitHubError("fork-qualified head is unavailable")
    if normalized in {"owner", "repo", "repository"}:
        if owner is None:
            return
        expected = {"owner": owner, "repo": name, "repository": f"{owner}/{name}"}[normalized]
        if value != expected:
            raise GitHubError("repository identity contradicts current repository")


def _walk_identity(value: Any, owner: str | None, name: str | None, *, nodes: list[int]) -> None:
    nodes[0] += 1
    if nodes[0] > 4096:
        raise GitHubError("JSON input is too complex")
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str):
                raise GitHubError("JSON object key is invalid")
            if isinstance(child, str):
                _identity_field(key, child, owner, name)
            elif _normalized(key) in IDENTITY_ALIASES:
                raise GitHubError("repository selector field is unavailable")
            _walk_identity(child, owner, name, nodes=nodes)
    elif isinstance(value, list):
        for child in value:
            _walk_identity(child, owner, name, nodes=nodes)


def _api_generic(argv: list[str]) -> tuple[str, bool]:
    if argv[0] != "api" or len(argv) < 2:
        raise GitHubError("GitHub API endpoint is required")
    endpoint = argv[1]
    parsed = urlsplit(endpoint)
    if (parsed.scheme or parsed.netloc or endpoint.startswith("/") or "\\" in endpoint or "%" in endpoint
            or parsed.fragment or not parsed.path.startswith("repos/")
            or any(part in {"", ".", ".."} for part in parsed.path.split("/"))
            or parsed.path.casefold().endswith("/graphql") or parsed.path.casefold() == "graphql"):
        raise GitHubError("API path must be a literal repository REST path")
    for key, values in parse_qs(parsed.query, keep_blank_values=True).items():
        for value in values:
            _identity_field(key, value, None, None)
            if re.search(r"(?:^|\s)(?:repo|org|user):", value, re.I):
                raise GitHubError("cross-repository query qualifier is unavailable")
    explicit: str | None = None
    body = False
    stdin_allowed = False
    read_option = False
    index = 2
    while index < len(argv):
        item = argv[index]
        if item in {"-X", "--method"}:
            if explicit is not None:
                raise GitHubError("API method must be specified once")
            index += 1
            if index >= len(argv):
                raise GitHubError("API method is missing")
            explicit = argv[index].upper()
        elif item.startswith("--method=") or (item.startswith("-X") and len(item) > 2):
            if explicit is not None:
                raise GitHubError("API method must be specified once")
            explicit = item.split("=", 1)[1].upper() if "=" in item else item[2:].upper()
        elif item in {"--field", "--raw-field", "-f", "-F", "--input"}:
            index += 1
            if index >= len(argv):
                raise GitHubError("API value is missing")
            value = argv[index]
            if item == "--input":
                if value != "-":
                    raise GitHubError("host file input is unavailable")
                stdin_allowed = True
            else:
                if "=" not in value:
                    raise GitHubError("API field requires name=value")
                key, field = value.split("=", 1)
                _identity_field(key, field, None, None)
                if item in {"--field", "-F"} and field.startswith("@"):
                    raise GitHubError("host file expansion is unavailable")
            body = True
        elif item.startswith(("--field=", "--raw-field=", "-F=", "-f=")) or (
                item.startswith(("-F", "-f")) and len(item) > 2):
            value = item.split("=", 1)[1] if "=" in item else item[2:]
            if "=" not in value:
                raise GitHubError("API field requires name=value")
            key, field = value.split("=", 1)
            _identity_field(key, field, None, None)
            if item.startswith(("--field", "-F")) and field.startswith("@"):
                raise GitHubError("host file expansion is unavailable")
            body = True
        elif item in {"--paginate", "--slurp"}:
            read_option = True
        elif item not in {"--include", "--silent"}:
            raise GitHubError("API option is outside exact policy")
        index += 1
    method = explicit or ("POST" if body else "GET")
    if method not in API_METHOD_EFFECT or (read_option and method not in {"GET", "HEAD"}):
        raise GitHubError("API method or read option is unavailable")
    match = re.fullmatch(r"repos/[^/]+/[^/]+(?:/(.*))?", parsed.path)
    if match is None:
        raise GitHubError("API path must have an exact repository shape")
    suffix = match.group(1) or ""
    lower = suffix.casefold()
    if lower.startswith("compare/") and ":" in suffix:
        raise GitHubError("cross-repository compare selectors are unavailable")
    parts = lower.split("/") if lower else []
    if method not in {"GET", "HEAD"} and (not suffix
            or (parts and parts[0] in FORBIDDEN_FAMILIES)
            or re.fullmatch(r"pulls/[0-9]+/(?:merge|update-branch)", lower)
            or re.fullmatch(r"issues/[0-9]+/transfer", lower)):
        raise GitHubError("high-risk repository mutation is unavailable")
    if method == "DELETE" and (re.fullmatch(r"issues/[0-9]+", lower)
            or re.search(r"(?:^|/)comments/[0-9]+$", lower)
            or re.fullmatch(r"pulls/[0-9]+/reviews/[0-9]+", lower)):
        raise GitHubError("issue and comment deletion are unavailable through run")
    return method, stdin_allowed


def _api_exact(argv: list[str], method: str, owner: str, name: str,
               prior_owner: str, prior_name: str) -> list[str]:
    parsed = urlsplit(argv[1])
    match = re.fullmatch(r"repos/([^/]+)/([^/]+)(?:/(.*))?", parsed.path)
    if not match or (match.group(1), match.group(2)) not in {(owner, name), (prior_owner, prior_name)}:
        raise GitHubError("API must target the exact current repository")
    suffix = match.group(3) or ""
    for key, values in parse_qs(parsed.query, keep_blank_values=True).items():
        for value in values:
            _identity_field(key, value, owner, name)
            if re.search(r"(?:^|\s)(?:repo|org|user):", value, re.I):
                raise GitHubError("cross-repository query qualifier is unavailable")
    index = 2
    while index < len(argv):
        item = argv[index]
        candidate: str | None = None
        if item in {"--field", "--raw-field", "-f", "-F"}:
            index += 1
            candidate = argv[index]
        elif item.startswith(("--field=", "--raw-field=", "-F=", "-f=")):
            candidate = item.split("=", 1)[1]
        elif item.startswith(("-F", "-f")) and len(item) > 2:
            candidate = item[2:]
        if candidate is not None:
            key, field = candidate.split("=", 1)
            _identity_field(key, field, owner, name)
        index += 1
    lower = suffix.casefold()
    write = method not in {"GET", "HEAD"}
    parts = lower.split("/") if lower else []
    if write and (not suffix or (parts and parts[0] in FORBIDDEN_FAMILIES)
            or re.fullmatch(r"pulls/[0-9]+/(?:merge|update-branch)", lower)
            or re.fullmatch(r"issues/[0-9]+/transfer", lower)):
        raise GitHubError("high-risk repository mutation is unavailable")
    if method == "DELETE" and (re.fullmatch(r"issues/[0-9]+", lower)
            or re.search(r"(?:^|/)comments/[0-9]+$", lower)
            or re.fullmatch(r"pulls/[0-9]+/reviews/[0-9]+", lower)):
        raise GitHubError("issue and comment deletion are unavailable through run")
    result = list(argv)
    query = f"?{parsed.query}" if parsed.query else ""
    result[1] = f"repos/{owner}/{name}" + (f"/{suffix}" if suffix else "") + query
    return result


def _stdin(value: Any, *, allowed: bool) -> str | None:
    if value is None:
        return None
    if not allowed or not isinstance(value, str) or len(value.encode("utf-8")) > MAX_STDIN_BYTES or "\x00" in value:
        raise GitHubError("stdin is unavailable or too large")
    return value


def _uncertain_process(value: Mapping[str, Any]) -> bool:
    return (value.get("state") in {"timed_out", "signaled"} or bool(value.get("uncertain"))
            or bool(value.get("stdout_truncated")) or bool(value.get("stderr_truncated"))
            or any((value.get("uncertainty_facts") or {}).values()))


def _process_result(value: Any, token: str) -> tuple[Mapping[str, Any], bool]:
    """Bound and validate an untrusted process result before publishing it."""
    invalid = MappingProxyType({"state": "invalid_result", "uncertain": True})
    if not isinstance(value, Mapping):
        return invalid, False
    state = value.get("state")
    if state not in {"exited", "rejected", "spawn_failed", "timed_out", "signaled", "io_error"}:
        return invalid, False
    exit_code = value.get("exit_code")
    if exit_code is not None and (not isinstance(exit_code, int) or isinstance(exit_code, bool)):
        return invalid, False
    result: dict[str, Any] = {"state": state}
    if "exit_code" in value:
        result["exit_code"] = exit_code
    for key in ("stdout", "stderr"):
        item = value.get(key, "")
        if not isinstance(item, str) or len(item.encode("utf-8")) > MAX_OUTPUT_BYTES:
            return invalid, False
        result[key] = host_boundary.redact_text(item, (token,))
    for key in ("uncertain", "stdout_truncated", "stderr_truncated", "effect_proven_absent"):
        item = value.get(key, False)
        if not isinstance(item, bool):
            return invalid, False
        if key in value:
            result[key] = item
    facts = value.get("uncertainty_facts", {})
    if not isinstance(facts, Mapping) or len(facts) > 16:
        return invalid, False
    clean_facts: dict[str, str | None] = {}
    for key, item in facts.items():
        if (not isinstance(key, str) or len(key) > 64 or
                (item is not None and (not isinstance(item, str)
                 or len(item.encode("utf-8")) > 256))):
            return invalid, False
        clean_facts[key] = None if item is None else host_boundary.redact_text(item, (token,))
    result["uncertainty_facts"] = clean_facts
    return MappingProxyType(result), True


def _redacted(value: Any, token: str) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _redacted(child, token) for key, child in value.items()}
    if isinstance(value, (list, tuple)):
        return tuple(_redacted(child, token) for child in value)
    if isinstance(value, str):
        return host_boundary.redact_text(value, (token,))
    return value


def _gh_environment(token: str, owner: str, name: str, root: Path) -> tuple[dict[str, str], Path]:
    host_boundary.assert_real_owned_parent(root, create=True)
    runtime = Path(tempfile.mkdtemp(prefix="github-", dir=root))
    os.chmod(runtime, 0o700)
    home, config, cwd = runtime / "home", runtime / "config", runtime / "cwd"
    for directory in (home, config, cwd):
        directory.mkdir(mode=0o700)
    env = {
        "PATH": host_boundary.FIXED_PATH, "LANG": "C", "LC_ALL": "C", "HOME": str(home),
        "GH_CONFIG_DIR": str(config), "GH_TOKEN": token, "GH_HOST": GH_HOST,
        "GH_REPO": f"{owner}/{name}", "GH_PROMPT": "0", "GH_PAGER": "cat", "PAGER": "cat",
        "EDITOR": "/usr/bin/false", "VISUAL": "/usr/bin/false", "GIT_EDITOR": "/usr/bin/false",
        "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "/usr/bin/false", "GIT_SSH_COMMAND": "/usr/bin/false",
        "GIT_PROXY_COMMAND": "/usr/bin/false", "GIT_ALLOW_PROTOCOL": "https",
        "GIT_CONFIG_COUNT": "4", "GIT_CONFIG_KEY_0": "core.hooksPath", "GIT_CONFIG_VALUE_0": os.devnull,
        "GIT_CONFIG_KEY_1": "credential.helper", "GIT_CONFIG_VALUE_1": "",
        "GIT_CONFIG_KEY_2": "protocol.ext.allow", "GIT_CONFIG_VALUE_2": "never",
        "GIT_CONFIG_KEY_3": "core.sshCommand", "GIT_CONFIG_VALUE_3": "/usr/bin/false",
        "GIT_CEILING_DIRECTORIES": str(cwd),
    }
    return env, cwd


def _remove_runtime(cwd: Path) -> None:
    import shutil
    shutil.rmtree(cwd.parent, ignore_errors=True)


def github_policy_help() -> Mapping[str, Any]:
    """Return the static public policy without constructing a route or runtime."""
    grouped: dict[str, list[str]] = {}
    for command, subcommand in HIGH_LEVEL_POLICY:
        grouped.setdefault(command, []).append(subcommand)
    return deepcopy({
        "repository_scope": "exact current repository",
        "permissions": host_boundary.narrow_token_request("1", "github_collaboration")["permissions"],
        "high_level": {key: sorted(value) for key, value in grouped.items()},
        "rest": {"path": "repos/{current-owner}/{current-name}/...",
                 "methods": dict(API_METHOD_EFFECT), "graphql": False,
                 "comment_delete": "dedicated action only"},
        "comment_delete": {
            "scope": "one exact current-repository comment",
            "comment_kinds": {
                "issue": "issue or pull-request conversation comment",
                "review": "pull-request review comment",
            },
            "arguments": ["comment_kind", "parent_number", "comment_id"],
        },
        "forbidden": list(FORBIDDEN_FAMILIES)
        + ["repository selectors", "auth overrides", "native help"],
    })


class ProjectGitHub:
    def __init__(self, gateway: project.ProjectGateway,
                 api_transport: Callable[[str, str, str, str], Any]) -> None:
        if not isinstance(gateway, project.ProjectGateway) or not callable(api_transport):
            raise GitHubError("GitHub composition is invalid")
        self.gateway = gateway
        self.api_transport = api_transport

    def help(self) -> Mapping[str, Any]:
        return github_policy_help()

    @staticmethod
    def _expected(route: project.CurrentProjectRoute | None, expected: Any) -> project.CurrentProjectRoute:
        if not isinstance(expected, str) or not REPOSITORY_ID.fullmatch(expected):
            raise GitHubError("expected repository ID is invalid")
        if route is None or route.repository_id != expected:
            raise GitHubError("current repository does not match expected repository ID")
        return route

    def _fresh(self, route: project.CurrentProjectRoute) -> project.ProviderObservation:
        if not callable(self.gateway.provider_reader):
            raise GitHubError("fresh provider observation is unavailable")
        try:
            value = project._observation(self.gateway.provider_reader(project.CanonicalCandidate(
                route.owner, route.name, route.repository_id)))
        except Exception:
            raise GitHubError("fresh provider observation failed") from None
        if value.repository_id != route.repository_id:
            raise GitHubError("fresh provider repository identity changed")
        return value

    def _token(self, observed: project.ProviderObservation, profile: str) -> str:
        if not callable(self.gateway.token_reader):
            raise GitHubError("repository token reader is unavailable")
        request = host_boundary.narrow_token_request(observed.repository_id, profile)
        request["installation_id"] = int(observed.installation_id)
        try:
            return host_boundary.validate_repository_token_response(
                self.gateway.token_reader(request), observed.repository_id,
                observed.owner, observed.name, profile)
        except Exception:
            raise GitHubError("repository token response is invalid") from None

    def run(self, origin: project.TrustedOrigin, expected_repository_id: str,
            argv: list[str], stdin: str | None = None) -> GitHubResult:
        values = _argv_shape(argv)
        if values[0] == "api":
            method, allows_stdin = _api_generic(values)
            generic_effect = API_METHOD_EFFECT[method]
        else:
            generic_effect = _high_level(values)
            allows_stdin = any(item == "--body-file" or item.startswith("--body-file=") for item in values)
            method = ""
        body = _stdin(stdin, allowed=allows_stdin)
        if values[0] == "api" and body:
            try:
                decoded = json.loads(body)
            except ValueError:
                decoded = None
            if decoded is not None:
                # Owner/repository equality is deferred until fresh mutable facts
                # are available, but selector aliases and fork heads are absolute.
                _walk_identity(decoded, None, None, nodes=[0])
        if not isinstance(expected_repository_id, str) or not REPOSITORY_ID.fullmatch(expected_repository_id):
            raise GitHubError("expected repository ID is invalid")
        with self.gateway.locked_current_route(origin) as current:
            route = self._expected(current, expected_repository_id)
            observed = self._fresh(route)
            if values[0] == "api":
                values = _api_exact(values, method, observed.owner, observed.name, route.owner, route.name)
                if body:
                    try:
                        decoded = json.loads(body)
                    except ValueError:
                        decoded = None
                    if decoded is not None:
                        _walk_identity(decoded, observed.owner, observed.name, nodes=[0])
                values.extend(("--header", f"X-GitHub-Api-Version: {GITHUB_API_VERSION}"))
            token = self._token(observed, "github_collaboration")
            env, cwd = _gh_environment(token, observed.owner, observed.name, self.gateway.state_root / "github")
            try:
                raw = self.gateway.process_runner([GH_BIN, *values], cwd=str(cwd), env=env, stdin=body,
                    timeout_seconds=TIMEOUT_SECONDS, max_output_bytes=MAX_OUTPUT_BYTES,
                    max_stdin_bytes=MAX_STDIN_BYTES)
            except Exception:
                raw = {"state": "io_error", "uncertain": True}
            finally:
                _remove_runtime(cwd)
            process, valid_process = _process_result(raw, token)
            uncertain = not valid_process or _uncertain_process(process)
            if uncertain:
                return GitHubResult("unknown", generic_effect, route.repository_id, process, uncertain=True)
            success = process.get("state") == "exited" and process.get("exit_code") == 0
            if success:
                return GitHubResult("succeeded", generic_effect, route.repository_id, process)
            if generic_effect == "read" or process.get("state") in {"rejected", "spawn_failed"} \
                    or process.get("effect_proven_absent") is True:
                return GitHubResult("failed", "no_effect" if generic_effect != "read" else "read",
                                    route.repository_id, process)
            return GitHubResult("unknown", generic_effect, route.repository_id, process, uncertain=True)

    @staticmethod
    def _response(value: Any, token: str) -> tuple[int, Any, Mapping[str, Any]]:
        if not isinstance(value, Mapping) or set(value) - {"status_code", "data", "error"}:
            raise GitHubError("malformed API response")
        status = value.get("status_code")
        if not isinstance(status, int) or isinstance(status, bool) or status < 100 or status > 599:
            raise GitHubError("malformed API response")
        try:
            size = len(json.dumps(value, ensure_ascii=False).encode("utf-8"))
        except (TypeError, ValueError):
            raise GitHubError("malformed API response") from None
        if size > MAX_API_RESPONSE_BYTES:
            raise GitHubError("unbounded API response")
        facts: dict[str, Any] = {}
        error = value.get("error")
        if error is not None:
            if not isinstance(error, str):
                raise GitHubError("malformed API response")
            bounded = host_boundary.redact_text(error, (token,)).encode("utf-8")[:512]
            facts["error"] = bounded.decode("utf-8", errors="ignore")
        return status, value.get("data"), MappingProxyType(facts)

    def comment_delete(self, origin: project.TrustedOrigin, expected_repository_id: str,
                       comment_kind: str, parent_number: int,
                       comment_id: int) -> CommentDeleteResult:
        if not isinstance(comment_kind, str) or comment_kind not in {"issue", "review"}:
            raise GitHubError("comment kind must be 'issue' or 'review'")
        if (not isinstance(parent_number, int) or isinstance(parent_number, bool)
                or not POSITIVE_ID.fullmatch(str(parent_number)) or not isinstance(comment_id, int)
                or isinstance(comment_id, bool) or not POSITIVE_ID.fullmatch(str(comment_id))):
            raise GitHubError("parent and comment IDs must be positive bounded integers")
        if not isinstance(expected_repository_id, str) or not REPOSITORY_ID.fullmatch(expected_repository_id):
            raise GitHubError("expected repository ID is invalid")
        with self.gateway.locked_current_route(origin) as current:
            route = self._expected(current, expected_repository_id)
            observed = self._fresh(route)
            token = self._token(observed, "github_collaboration")
            base = f"/repos/{observed.owner}/{observed.name}"
            canonical_repo = f"https://api.github.com{base}"
            if comment_kind == "issue":
                parent_path = f"{base}/issues/{parent_number}"
                comment_path = f"{base}/issues/comments/{comment_id}"
                canonical_parent = f"{canonical_repo}/issues/{parent_number}"
            else:
                parent_path = f"{base}/pulls/{parent_number}"
                comment_path = f"{base}/pulls/comments/{comment_id}"
                canonical_parent = f"{canonical_repo}/pulls/{parent_number}"
            evidence: list[Mapping[str, Any]] = []

            def result(state: str, effect: str, uncertain: bool = False) -> CommentDeleteResult:
                return CommentDeleteResult(state, effect, route.repository_id, comment_kind,
                                           parent_number, comment_id, tuple(evidence), uncertain)

            def call(method: str, path: str) -> tuple[int, Any]:
                try:
                    status, data, facts = self._response(
                        self.api_transport(method, path, token, GITHUB_API_VERSION), token)
                except GitHubError as exc:
                    evidence.append({"method": method, "path": path, "error": type(exc).__name__})
                    raise _APIUncertain from None
                except Exception as exc:
                    evidence.append({"method": method, "path": path, "error": type(exc).__name__})
                    raise _APIUncertain from None
                evidence.append({"method": method, "path": path, "status": status, **facts})
                return status, data

            try:
                status, parent = call("GET", parent_path)
                if status == 404:
                    return result("absent", "no_effect")
                if status >= 500:
                    raise _APIUncertain
                if status != 200 or not isinstance(parent, Mapping):
                    raise _APIUncertain
                if comment_kind == "issue":
                    pull_request = parent.get("pull_request")
                    if (parent.get("number") != parent_number
                            or parent.get("url") != canonical_parent
                            or parent.get("repository_url") != canonical_repo
                            or (pull_request is not None and
                                (not isinstance(pull_request, Mapping)
                                 or pull_request.get("url") !=
                                 f"{canonical_repo}/pulls/{parent_number}"))):
                        raise GitHubError("parent issue or pull request identity is not exact")
                else:
                    base_identity = parent.get("base")
                    repository = (base_identity.get("repo")
                                  if isinstance(base_identity, Mapping) else None)
                    if (parent.get("number") != parent_number
                            or parent.get("url") != canonical_parent
                            or not isinstance(repository, Mapping)
                            or repository.get("id") != int(route.repository_id)
                            or repository.get("url") != canonical_repo):
                        raise GitHubError("parent pull request identity is not exact")
                status, comment = call("GET", comment_path)
                if status == 404:
                    return result("absent", "no_effect")
                if status >= 500:
                    raise _APIUncertain
                if status != 200 or not isinstance(comment, Mapping):
                    raise _APIUncertain
                parent_url_field = "issue_url" if comment_kind == "issue" else "pull_request_url"
                if (comment.get("id") != comment_id
                        or comment.get(parent_url_field) != canonical_parent):
                    raise GitHubError("comment identity is not exact")
            except GitHubError:
                raise
            except _APIUncertain:
                return result("unknown", "no_effect", True)

            delete_status: int | None = None
            post_status: int | None = None
            post: Any = None
            try:
                delete_status, _ = call("DELETE", comment_path)
            except _APIUncertain:
                pass
            try:
                post_status, post = call("GET", comment_path)
            except _APIUncertain:
                pass
            parent_url_field = "issue_url" if comment_kind == "issue" else "pull_request_url"
            if post_status == 200 and (not isinstance(post, Mapping)
                    or post.get("id") != comment_id
                    or post.get(parent_url_field) != canonical_parent):
                raise GitHubError("comment identity is not exact")
            if delete_status == 204 and post_status == 404:
                return result("deleted", "delete")
            if delete_status == 404 and post_status == 404:
                return result("absent", "no_effect")
            if (delete_status is not None and 400 <= delete_status < 500
                    and post_status == 200):
                return result("not_deleted", "no_effect")
            return result("unknown", "delete", True)


class RiskReporter:
    def __init__(self, admin_repository_id: str, token_reader: Callable[[Mapping[str, Any]], Any],
                  process_runner: Callable[..., Mapping[str, Any]], state_root: Path | str, *,
                  provider_observer: Callable[[Any], Any]) -> None:
        if (not isinstance(admin_repository_id, str) or not REPOSITORY_ID.fullmatch(admin_repository_id)
                or not callable(token_reader) or not callable(process_runner)
                or not callable(provider_observer)):
            raise GitHubError("risk reporter configuration is invalid")
        self.repository_id = admin_repository_id
        self.token_reader = token_reader
        self.process_runner = process_runner
        self.state_root = Path(state_root)
        self.provider_observer = provider_observer

    def _fresh(self) -> project.ProviderObservation:
        try:
            observed = project._observation(self.provider_observer(
                project.CanonicalCandidate(ADMIN_OWNER, ADMIN_NAME, self.repository_id)))
        except Exception:
            raise GitHubError("risk report repository observation failed") from None
        if observed.repository_id != self.repository_id:
            raise GitHubError("risk report repository identity changed")
        return observed

    def _token(self, observed: project.ProviderObservation) -> str:
        request = host_boundary.narrow_token_request(self.repository_id, "risk_report")
        request["installation_id"] = int(observed.installation_id)
        try:
            return host_boundary.validate_repository_token_response(
                self.token_reader(request), self.repository_id,
                observed.owner, observed.name, "risk_report")
        except Exception:
            raise GitHubError("risk report token response is invalid") from None

    def _execute(self, observed: project.ProviderObservation, token: str,
                 argv: list[str], *, stdin: str | None = None
                  ) -> tuple[Mapping[str, Any], bool]:
        env, cwd = _gh_environment(token, observed.owner, observed.name,
                                   self.state_root / "github-risk")
        try:
            raw = self.process_runner(argv, cwd=str(cwd), env=env, stdin=stdin,
                timeout_seconds=TIMEOUT_SECONDS, max_output_bytes=MAX_OUTPUT_BYTES,
                max_stdin_bytes=MAX_STDIN_BYTES)
        except Exception:
            raw = {"state": "io_error", "uncertain": True}
        finally:
            _remove_runtime(cwd)
        return _process_result(raw, token)

    @staticmethod
    def _current(value: Any) -> tuple[str, str, str] | None:
        if value is None:
            return None
        if isinstance(value, project.CurrentProjectRoute):
            repository_id, owner, name = value.repository_id, value.owner, value.name
        elif isinstance(value, project.ProviderObservation):
            try:
                observed = project._observation(value)
            except Exception:
                raise GitHubError("current repository observation is invalid") from None
            repository_id, owner, name = observed.repository_id, observed.owner, observed.name
        else:
            raise GitHubError("current repository must be a trusted route or provider observation")
        if (not REPOSITORY_ID.fullmatch(repository_id) or not REPO_PART.fullmatch(owner)
                or not REPO_PART.fullmatch(name)):
            raise GitHubError("current repository identity is invalid")
        return repository_id, owner, name

    def create(self, category: RiskCategory, event: TrustedRiskEvent, summary: str,
               current_repository: project.CurrentProjectRoute | project.ProviderObservation | None = None
               ) -> RiskReportResult:
        if not isinstance(category, RiskCategory) or not isinstance(event, TrustedRiskEvent):
            raise GitHubError("risk category or event is invalid")
        if (not isinstance(summary, str) or not summary or len(summary.encode("utf-8")) > 1000
                or "\x00" in summary or any(unicodedata.category(char) == "Cc" and char not in "\n\t"
                                              for char in summary)):
            raise GitHubError("risk summary is invalid or exceeds 1,000 UTF-8 bytes")
        current = self._current(current_repository)
        title = f"[{category.value}] {event.source.value} event {event.event_id}"
        lines = [f"Category: {category.value}", f"Source: {event.source.value}",
                   f"Workspace: {event.workspace_id}", f"Channel: {event.channel_id}",
                   f"Event: {event.event_id}"]
        if current:
            lines.extend((f"Current repository ID: {current[0]}",
                          f"Current repository: {current[1]}/{current[2]}"))
        lines.extend(("", "Summary:", summary))
        body = "\n".join(lines)
        observed = self._fresh()
        token = self._token(observed)
        argv = [GH_BIN, "issue", "create", "--title", title, "--body-file", "-"]
        process, valid_process = self._execute(observed, token, argv, stdin=body)
        public_process = MappingProxyType({key: value for key, value in process.items()
                                           if key not in {"stdout", "stderr"}})
        uncertain = not valid_process or _uncertain_process(process)
        if uncertain:
            return RiskReportResult("unknown", "create", self.repository_id,
                                    public_process, uncertain=True)
        if process.get("state") == "exited" and process.get("exit_code") == 0:
            return RiskReportResult("created", "create", self.repository_id, public_process)
        if (process.get("state") in {"rejected", "spawn_failed"}
                and process.get("uncertain") is False
                or process.get("effect_proven_absent") is True):
            return RiskReportResult("failed", "no_effect", self.repository_id, public_process)
        return RiskReportResult("unknown", "create", self.repository_id,
                                public_process, uncertain=True)


__all__ = ["GH_BIN", "GITHUB_API_VERSION", "GitHubError", "GitHubResult",
           "CommentDeleteResult", "RiskReportResult", "RiskSource",
           "RiskCategory", "TrustedRiskEvent", "ProjectGitHub", "RiskReporter",
           "github_policy_help"]
