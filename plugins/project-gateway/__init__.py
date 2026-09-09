# SPDX-License-Identifier: AGPL-3.0-only
"""Project Gateway production registration contract."""

from __future__ import annotations

from contextvars import ContextVar
from dataclasses import fields, is_dataclass
from enum import Enum
import json
import os
import re
from pathlib import Path
from typing import Any, Callable, Mapping

from . import cli_runner, github, host_boundary, project, registry
from .git import ProjectGit, git_policy_help

TOOLSET_NAME = "project_gateway"
TOOL_NAMES = (
    "repository_access", "project_association", "project_workspace",
    "channel_bookmarks", "project_git", "project_github", "risk_report",
)

_TRUSTED_DISPATCH: ContextVar[tuple[Any, str | None]] = ContextVar(
    "project_gateway_trusted_dispatch", default=(None, None))
_RUNTIME_FACTORY: Callable[..., Any] | None = None


class ContractError(ValueError):
    def __init__(self, message: str, code: str = "request_rejected") -> None:
        super().__init__(message)
        self.code = code


def _object(properties: Mapping[str, Any], required: tuple[str, ...]) -> dict[str, Any]:
    return {"type": "object", "properties": dict(properties), "required": list(required),
            "additionalProperties": False}


ACTION = lambda values: {"type": "string", "enum": list(values)}
REPO_ID = {"type": "string", "pattern": "^[0-9]+$", "maxLength": 32}
REPO_PART = {"type": "string", "pattern": "^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$"}
BRANCH = {"type": "string", "minLength": 1, "maxLength": 255}
SHA = {"type": "string", "pattern": "^[0-9a-f]{40}$"}
NULLABLE_SHA = {"oneOf": [SHA, {"type": "null"}]}


def _schema(name: str, description: str, variants: list[dict[str, Any]]) -> dict[str, Any]:
    properties: dict[str, Any] = {}
    schemas_by_property: dict[str, list[dict[str, Any]]] = {}
    for variant in variants:
        for property_name, property_schema in variant["properties"].items():
            schemas = schemas_by_property.setdefault(property_name, [])
            if property_schema not in schemas:
                schemas.append(property_schema)

    for property_name, schemas in schemas_by_property.items():
        if len(schemas) == 1:
            properties[property_name] = schemas[0]
            continue
        if property_name in {"action", "target"} and all(
                schema.get("type") == "string" and isinstance(schema.get("enum"), list)
                and {key: value for key, value in schema.items() if key != "enum"}
                == {key: value for key, value in schemas[0].items() if key != "enum"}
                for schema in schemas):
            enum_values = []
            for schema in schemas:
                for value in schema["enum"]:
                    if value not in enum_values:
                        enum_values.append(value)
            properties[property_name] = {**schemas[0], "enum": enum_values}
        else:
            choices: list[dict[str, Any]] = []
            for schema in schemas:
                candidates = schema["oneOf"] if set(schema) == {"oneOf"} else [schema]
                choices.extend(candidate for candidate in candidates if candidate not in choices)
            properties[property_name] = {"oneOf": choices}

    required = [
        property_name for property_name in variants[0].get("required", [])
        if all(property_name in variant.get("required", []) for variant in variants)
    ]
    return {"name": name, "description": description,
            "parameters": _object(properties, tuple(required))}


SCHEMAS: dict[str, dict[str, Any]] = {
    "repository_access": _schema("repository_access", "Observe current GitHub App access for one canonical owner/name. Signature: observe(owner, name).", [
        _object({"action": ACTION(("observe",)), "owner": REPO_PART, "name": REPO_PART},
                ("action", "owner", "name"))]),
    "project_association": _schema("project_association", "Read or change only the trusted current channel association in SQLite. Signatures: show(); set(expected_repository_id [required, nullable], owner, name, repository_id); clear(expected_repository_id [required, nullable]).", [
        _object({"action": ACTION(("show",))}, ("action",)),
        _object({"action": ACTION(("set",)), "expected_repository_id": {"oneOf": [REPO_ID, {"type": "null"}]},
                 "owner": REPO_PART, "name": REPO_PART, "repository_id": REPO_ID},
                ("action", "expected_repository_id", "owner", "name", "repository_id")),
        _object({"action": ACTION(("clear",)), "expected_repository_id": {"oneOf": [REPO_ID, {"type": "null"}]}},
                ("action", "expected_repository_id"))]),
    "project_workspace": _schema("project_workspace", "Inspect, initialize, or fetch one exact current or observed repository workspace, or read fixed source learning bytes. Signatures: inspect|initialize|fetch(target); candidate target also requires owner, name, expected_repository_id; learning_snapshot().", [
        _object({"action": ACTION(("inspect", "initialize", "fetch")), "target": ACTION(("current",))}, ("action", "target")),
        _object({"action": ACTION(("inspect", "initialize", "fetch")), "target": ACTION(("candidate",)),
                 "owner": REPO_PART, "name": REPO_PART, "expected_repository_id": REPO_ID},
                ("action", "target", "owner", "name", "expected_repository_id")),
        _object({"action": ACTION(("learning_snapshot",))}, ("action",))]),
    "channel_bookmarks": _schema("channel_bookmarks", "List, add, or delete Slack bookmarks in the trusted current channel. Signatures: list(); add(title, url); delete(bookmark_id).", [
        _object({"action": ACTION(("list",))}, ("action",)),
        _object({"action": ACTION(("add",)), "title": {"type": "string", "minLength": 1, "maxLength": 300},
                 "url": {"type": "string", "minLength": 1, "maxLength": 2048}}, ("action", "title", "url")),
        _object({"action": ACTION(("delete",)), "bookmark_id": {"type": "string", "minLength": 1, "maxLength": 128}},
                ("action", "bookmark_id"))]),
    "project_git": _schema("project_git", "Apply one direct bounded ProjectGit capability to the trusted current repository. Signatures: help(); run(expected_repository_id, argv); commit(expected_repository_id, paths, message, expected_head [full SHA], expected_branch); remote_ref(expected_repository_id, branch); push(expected_repository_id, branch, commit, expected_base); delete_remote_branch(expected_repository_id, branch, expected_sha); checkout_default(expected_repository_id, expected_branch, expected_head [full SHA or null for canonical unborn HEAD], expected_target).", [
        _object({"action": ACTION(("help",))}, ("action",)),
        _object({"action": ACTION(("run",)), "expected_repository_id": REPO_ID,
                 "argv": {"type": "array", "items": {"type": "string", "minLength": 1, "maxLength": 4096},
                          "minItems": 1, "maxItems": 64}}, ("action", "expected_repository_id", "argv")),
        _object({"action": ACTION(("commit",)), "expected_repository_id": REPO_ID,
                 "paths": {"type": "array", "items": {"type": "string", "minLength": 1, "maxLength": 4096},
                           "minItems": 1, "maxItems": 256}, "message": {"type": "string", "minLength": 1, "maxLength": 16384},
                 "expected_head": SHA, "expected_branch": BRANCH},
                ("action", "expected_repository_id", "paths", "message", "expected_head", "expected_branch")),
        _object({"action": ACTION(("remote_ref",)), "expected_repository_id": REPO_ID, "branch": BRANCH},
                ("action", "expected_repository_id", "branch")),
        _object({"action": ACTION(("push",)), "expected_repository_id": REPO_ID, "branch": BRANCH,
                 "commit": SHA, "expected_base": SHA},
                ("action", "expected_repository_id", "branch", "commit", "expected_base")),
        _object({"action": ACTION(("delete_remote_branch",)), "expected_repository_id": REPO_ID,
                 "branch": BRANCH, "expected_sha": SHA},
                ("action", "expected_repository_id", "branch", "expected_sha")),
        _object({"action": ACTION(("checkout_default",)), "expected_repository_id": REPO_ID,
                   "expected_branch": BRANCH, "expected_head": NULLABLE_SHA,
                   "expected_target": SHA},
                 ("action", "expected_repository_id", "expected_branch", "expected_head", "expected_target"))]),
    "project_github": _schema("project_github", "Return static policy or apply one direct exact-current-repository GitHub capability. Signatures: help(); run(expected_repository_id, argv; optional nullable stdin); comment_delete(expected_repository_id, comment_kind, parent_number, comment_id).", [
        _object({"action": ACTION(("help",))}, ("action",)),
        _object({"action": ACTION(("run",)), "expected_repository_id": REPO_ID,
                 "argv": {"type": "array", "items": {"type": "string", "minLength": 1, "maxLength": 4096},
                          "minItems": 1, "maxItems": 64},
                 "stdin": {"oneOf": [{"type": "string", "maxLength": 65536}, {"type": "null"}]}},
                ("action", "expected_repository_id", "argv")),
        _object({"action": ACTION(("comment_delete",)), "expected_repository_id": REPO_ID,
                  "comment_kind": ACTION(("issue", "review")),
                  "parent_number": {"type": "integer", "minimum": 1, "maximum": 999999999},
                  "comment_id": {"type": "integer", "minimum": 1, "maximum": 999999999}},
                 ("action", "expected_repository_id", "comment_kind", "parent_number", "comment_id"))]),
    "risk_report": _schema("risk_report", "Create one fixed-admin risk report for the host-derived Slack event. Signature: create(category, summary).", [
        _object({"action": ACTION(("create",)), "category": ACTION(tuple(item.value for item in github.RiskCategory)),
                  "summary": {"type": "string", "minLength": 1, "maxLength": 1000,
                              "description": "At most 1000 UTF-8 bytes; the host rechecks encoded size."}},
                 ("action", "category", "summary"))]),
}


def pre_gateway_dispatch(*, session_store: Any = None, event: Any = None, **_: Any) -> None:
    """Cache only a usable session resolver and the host event message identity."""
    resolver = None
    if callable(session_store):
        resolver = session_store
    elif callable(getattr(session_store, "lookup_by_session_id", None)):
        resolver = session_store.lookup_by_session_id
    message_id = event.get("message_id") if isinstance(event, Mapping) else getattr(event, "message_id", None)
    source = event.get("source") if isinstance(event, Mapping) else getattr(event, "source", None)
    if message_id is None:
        message_id = source.get("message_id") if isinstance(source, Mapping) else getattr(source, "message_id", None)
    trusted_id = str(message_id) if isinstance(message_id, (str, int)) and str(message_id) else None
    _TRUSTED_DISPATCH.set((resolver, trusted_id))


def _field(value: Any, name: str) -> Any:
    return value.get(name) if isinstance(value, Mapping) else getattr(value, name, None)


def _trusted_origin(session_id: Any) -> project.TrustedOrigin:
    resolver, _ = _TRUSTED_DISPATCH.get()
    if not isinstance(session_id, str) or not session_id or not callable(resolver):
        raise ContractError("trusted session context is unavailable", "trusted_context_unavailable")
    try:
        entry = resolver(session_id)
    except Exception:
        raise ContractError("trusted session context is unavailable", "trusted_context_unavailable") from None
    origin = _field(entry, "origin")
    platform = _field(origin, "platform")
    platform = getattr(platform, "value", platform)
    workspace, channel = _field(origin, "scope_id"), _field(origin, "chat_id")
    if platform != "slack" or not isinstance(workspace, str) or not isinstance(channel, str):
        raise ContractError("trusted Slack session origin is required", "trusted_context_unavailable")
    configured = os.environ.get("PEIRCE_SLACK_WORKSPACE_ID", "").strip()
    if not configured or workspace != configured:
        raise ContractError("trusted Slack workspace does not match configuration", "trusted_context_unavailable")
    return project.TrustedOrigin(workspace, channel)


def _runtime(origin: project.TrustedOrigin, capability: str) -> Any:
    if capability not in {"access", "gateway", "bookmarks", "git", "github", "risk"}:
        raise ContractError("runtime capability is unavailable", "runtime_unavailable")
    if _RUNTIME_FACTORY is not None:
        return _RUNTIME_FACTORY(origin=origin, capability=capability)
    broker = host_boundary.EnvironmentBroker()
    if capability == "access":
        return broker
    if capability == "bookmarks":
        return project.ChannelBookmarks(broker.bookmark_transport)
    if capability == "risk":
        admin_id, state_root = broker.require("PEIRCE_ADMIN_REPOSITORY_ID", "PEIRCE_PROJECT_STATE_ROOT")
        if admin_id != host_boundary.FIXED_ADMIN_REPOSITORY_ID:
            raise ContractError("fixed admin repository identity does not match source contract")
        return github.RiskReporter(
            admin_id, broker.token_reader, cli_runner.run_argv, state_root,
            provider_observer=broker.observe)
    (installation, workspace, source_channel, source_id, admin_channel, admin_id,
     workspace_root, state_root, db_path) = broker.require(
        "GITHUB_APP_INSTALLATION_ID", "PEIRCE_SLACK_WORKSPACE_ID", "PEIRCE_SOURCE_CHANNEL_ID",
        "PEIRCE_SOURCE_REPOSITORY_ID", "PEIRCE_ADMIN_CHANNEL_ID", "PEIRCE_ADMIN_REPOSITORY_ID",
        "PEIRCE_PROJECT_WORKSPACE_ROOT", "PEIRCE_PROJECT_STATE_ROOT", "HERMES_PROJECTS_DB")
    if origin.workspace_id != workspace:
        raise ContractError("trusted Slack workspace does not match configuration")
    if (source_id != host_boundary.FIXED_SOURCE_REPOSITORY_ID
            or admin_id != host_boundary.FIXED_ADMIN_REPOSITORY_ID):
        raise ContractError("fixed repository identity does not match source contract")
    store = registry.ProjectRegistry(db_path, workspace_root=workspace_root, state_root=state_root)
    fixed = project.build_peirce_isolated_projects(
        store, workspace, source_channel, source_id, admin_channel, admin_id, installation)
    gate = project.ProjectGateway(
        store, broker.observe, fixed, state_root=state_root,
        token_reader=broker.token_reader, process_runner=cli_runner.run_argv,
        protected_profile_root=Path(db_path).parent)
    if capability == "git":
        return ProjectGit(gate)
    if capability == "github":
        return github.ProjectGitHub(gate, broker.comment_api_transport)
    return gate


def _plain(value: Any) -> Any:
    if is_dataclass(value):
        return {field.name: _plain(getattr(value, field.name)) for field in fields(value)}
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Mapping):
        return {str(key): _plain(child) for key, child in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(child) for child in value]
    if isinstance(value, Path):
        return str(value)
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


def _arguments(args: Any, kwargs: Mapping[str, Any]) -> dict[str, Any]:
    if isinstance(args, Mapping):
        values = dict(args)
    else:
        values = next((dict(kwargs[key]) for key in ("arguments", "tool_args", "args")
                       if isinstance(kwargs.get(key), Mapping)), {})
    if "session_id" in values:
        raise ContractError("session identity is host supplied")
    return values


def _envelope(call: Callable[[], Any]) -> str:
    try:
        payload = {"ok": True, "result": _plain(call())}
    except ContractError as exc:
        payload = {"ok": False, "error": {"code": exc.code}, "message": str(exc)}
    except (ValueError, TypeError) as exc:
        payload = {"ok": False, "error": {"code": "request_rejected"}, "message": str(exc)}
    except Exception:
        payload = {"ok": False, "error": {"code": "request_failed"}, "message": "request failed"}
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _invoke(implementation: Callable[[dict[str, Any], project.TrustedOrigin], Any],
            args: Any = None, **kwargs: Any) -> str:
    def call() -> Any:
        values = _arguments(args, kwargs)
        return implementation(values, _trusted_origin(kwargs.get("session_id")))
    return _envelope(call)


def repository_access(args: Any = None, **kwargs: Any) -> str:
    def implementation(a: dict[str, Any], origin: project.TrustedOrigin) -> Any:
        if set(a) != {"action", "owner", "name"} or a.get("action") != "observe":
            raise ContractError("invalid repository access request")
        broker = _runtime(origin, "access")
        return broker.access_reader(project.RepositoryLocator(a["owner"], a["name"]))
    return _invoke(implementation, args, **kwargs)


def project_association(args: Any = None, **kwargs: Any) -> str:
    def implementation(a: dict[str, Any], origin: project.TrustedOrigin) -> Any:
        action = a.get("action")
        gate = _runtime(origin, "gateway")
        if action == "show" and set(a) == {"action"}: return gate.show(origin)
        if action == "set" and set(a) == {"action", "expected_repository_id", "owner", "name", "repository_id"}:
            return gate.set(origin, project.CanonicalCandidate(a["owner"], a["name"], a["repository_id"]),
                            a["expected_repository_id"])
        if action == "clear" and set(a) == {"action", "expected_repository_id"}:
            return gate.clear(origin, a["expected_repository_id"])
        raise ContractError("invalid project association request")
    return _invoke(implementation, args, **kwargs)


def project_workspace(args: Any = None, **kwargs: Any) -> str:
    def implementation(a: dict[str, Any], origin: project.TrustedOrigin) -> Any:
        gate = _runtime(origin, "gateway")
        if a.get("action") == "learning_snapshot" and set(a) == {"action"}:
            return gate.learning_snapshot(origin)
        if a.get("action") not in {"inspect", "initialize", "fetch"} or a.get("target") not in {"current", "candidate"}:
            raise ContractError("invalid project workspace request")
        if a["target"] == "current" and set(a) == {"action", "target"}:
            with gate.locked_current_channel_route(origin) as route:
                if route is None:
                    raise ContractError("current project is unavailable", "not_found")
                methods = {"inspect": gate.inspect_workspace, "initialize": gate.initialize_workspace,
                           "fetch": gate.fetch_workspace}
                return methods[a["action"]](route.repository)
        elif a["target"] == "candidate" and set(a) == {"action", "target", "owner", "name", "expected_repository_id"}:
            try:
                observed = project._observation(gate.provider_reader(project.CanonicalCandidate(
                    a["owner"], a["name"], a["expected_repository_id"])))
            except Exception:
                raise ContractError("candidate repository observation failed") from None
            if observed.repository_id != a["expected_repository_id"]:
                raise ContractError("observed repository ID does not match expectation")
            facts = gate._transient_facts(observed)
        else: raise ContractError("invalid project workspace request")
        methods = {"inspect": gate.inspect_workspace, "initialize": gate.initialize_workspace,
                   "fetch": gate.fetch_workspace}
        return methods[a["action"]](facts)
    return _invoke(implementation, args, **kwargs)


def channel_bookmarks(args: Any = None, **kwargs: Any) -> str:
    def implementation(a: dict[str, Any], origin: project.TrustedOrigin) -> Any:
        client = _runtime(origin, "bookmarks")
        if a == {"action": "list"}: return client.list_bookmarks(origin)
        if a.get("action") == "add" and set(a) == {"action", "title", "url"}: return client.add_bookmark(origin, a["title"], a["url"])
        if a.get("action") == "delete" and set(a) == {"action", "bookmark_id"}: return client.delete_bookmark(origin, a["bookmark_id"])
        raise ContractError("invalid channel bookmark request")
    return _invoke(implementation, args, **kwargs)


def project_git(args: Any = None, **kwargs: Any) -> str:
    def call() -> Any:
        a = _arguments(args, kwargs)
        if a == {"action": "help"}:
            return git_policy_help()
        origin = _trusted_origin(kwargs.get("session_id"))
        client = _runtime(origin, "git")
        action = a.pop("action", None)
        methods = {"run": "run", "commit": "commit", "remote_ref": "remote_ref", "push": "push",
                   "delete_remote_branch": "delete_remote_branch", "checkout_default": "checkout_default"}
        if action not in methods: raise ContractError("invalid project Git request")
        expected_head = a.get("expected_head")
        if action == "commit" and (not isinstance(expected_head, str)
                                    or not re.fullmatch(SHA["pattern"], expected_head)):
            raise ContractError("commit expected HEAD must be a full lowercase SHA")
        if action == "checkout_default":
            if "expected_head" not in a:
                raise ContractError("checkout expected HEAD is required")
            if expected_head is not None and (not isinstance(expected_head, str)
                    or not re.fullmatch(SHA["pattern"], expected_head)):
                raise ContractError("checkout expected HEAD must be null or a full lowercase SHA")
        return getattr(client, methods[action])(origin, **a)
    return _envelope(call)


def project_github(args: Any = None, **kwargs: Any) -> str:
    def call() -> Any:
        a = _arguments(args, kwargs)
        if a == {"action": "help"}:
            return github.github_policy_help()
        origin = _trusted_origin(kwargs.get("session_id"))
        client = _runtime(origin, "github")
        action = a.pop("action", None)
        if action == "run": return client.run(origin, **a)
        if action == "comment_delete": return client.comment_delete(origin, **a)
        raise ContractError("invalid project GitHub request")
    return _envelope(call)


def risk_report(args: Any = None, **kwargs: Any) -> str:
    def implementation(a: dict[str, Any], origin: project.TrustedOrigin) -> Any:
        _, event_id = _TRUSTED_DISPATCH.get()
        if not event_id: raise ContractError("trusted event identity is unavailable", "trusted_context_unavailable")
        event = github.TrustedRiskEvent(github.RiskSource.SLACK, origin.workspace_id, origin.channel_id, event_id)
        reporter = _runtime(origin, "risk")
        if a.get("action") == "create" and set(a) == {"action", "category", "summary"}:
            current = None
            try:
                current = _runtime(origin, "gateway").show(origin)
            except Exception:
                pass
            return reporter.create(github.RiskCategory(a["category"]), event, a["summary"], current)
        raise ContractError("invalid risk report request")
    return _invoke(implementation, args, **kwargs)


def register(ctx: Any) -> None:
    ctx.register_hook("pre_gateway_dispatch", pre_gateway_dispatch)
    for name in TOOL_NAMES:
        schema = SCHEMAS[name]
        ctx.register_tool(name=name, toolset=TOOLSET_NAME, schema=schema,
                          handler=globals()[name], description=schema["description"], requires_env=[])


validate_production_environment = host_boundary.validate_production_environment
EnvironmentBroker = host_boundary.EnvironmentBroker

__all__ = [*TOOL_NAMES, "register", "pre_gateway_dispatch", "SCHEMAS", "TOOL_NAMES",
           "EnvironmentBroker", "validate_production_environment"]
