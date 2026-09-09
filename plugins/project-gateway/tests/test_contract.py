# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

from contextlib import contextmanager
import io
import json
import os
from pathlib import Path
import tempfile
from types import MappingProxyType, SimpleNamespace
import unittest
from unittest import mock
import urllib.error
import urllib.request


from _package import ENTRYPOINT, PLUGIN, gateway


class FakeContext:
    def __init__(self):
        self.tools = {}
        self.hooks = []

    def register_tool(self, **kwargs):
        self.tools[kwargs["name"]] = kwargs

    def register_hook(self, name, callback):
        self.hooks.append((name, callback))


class ContractTests(unittest.TestCase):
    def test_registration_is_exact_and_has_no_union_environment_gate(self):
        context = FakeContext()
        with mock.patch.dict(os.environ, {}, clear=True):
            gateway.register(context)
        self.assertEqual(len(gateway.TOOL_NAMES), 7)
        self.assertEqual(tuple(context.tools), gateway.TOOL_NAMES)
        self.assertEqual([item[0] for item in context.hooks], ["pre_gateway_dispatch"])
        self.assertTrue(all(item["toolset"] == "project_gateway" for item in context.tools.values()))
        self.assertTrue(all(item["requires_env"] == [] for item in context.tools.values()))
        self.assertTrue(all(item["schema"] is gateway.SCHEMAS[name]
                            for name, item in context.tools.items()))

    def test_help_is_session_and_environment_independent(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            result = json.loads(gateway.project_github({"action": "help"}))
            git_result = json.loads(gateway.project_git({"action": "help"}))
        self.assertTrue(result["ok"])
        self.assertTrue(git_result["ok"])
        self.assertEqual(result["result"]["repository_scope"], "exact current repository")
        self.assertEqual(git_result["result"]["scope"], "exact current repository")
        self.assertEqual(git_result["result"]["run"]["local_effects"], [
            "branch", "switch", "checkout", "add", "restore", "clean",
            "merge --no-edit <full-SHA>", "commit --no-edit during merge",
            "merge --abort during merge",
        ])
        self.assertEqual(
            git_result["result"]["publication"],
            "standard fast-forward task work only; remote default update unavailable",
        )
        self.assertIn("commit", git_result["result"]["direct_actions"])
        self.assertIn("checkout_default", git_result["result"]["direct_actions"])
        self.assertEqual(
            git_result["result"]["checkout_default"]["expected_head"],
            "full lowercase SHA; explicit null only for freshly observed canonical unborn default",
        )

    def test_active_git_contracts_describe_detached_merge_and_standard_fast_forward(self):
        repository = PLUGIN.parents[1]
        sources = {
            "plugin": (PLUGIN / "README.md").read_text(encoding="utf-8"),
            "ledger": (repository / "docs" / "access-and-permissions.md").read_text(
                encoding="utf-8"),
            "agents": (repository / "AGENTS.md").read_text(encoding="utf-8"),
        }
        for name, text in sources.items():
            lower = text.lower()
            with self.subTest(source=name):
                self.assertIn("detached head", lower)
                self.assertIn("merge --no-edit", text)
                self.assertIn("commit --no-edit", text)
                self.assertIn("merge --abort", text)
                self.assertIn("merge commits", lower)
                self.assertNotIn("linear task-branch", lower)
                self.assertNotIn("aliases, hooks, merge,", lower)

        plugin = sources["plugin"]
        self.assertIn("full lowercase SHA", plugin)
        self.assertIn("no token and no allowed Git transport protocol", plugin)
        self.assertIn("Human pull-request/default-branch integration", plugin)

    def test_schemas_are_closed_and_have_no_model_supplied_host_identity_or_learning_path(self):
        properties = {
            key for schema in gateway.SCHEMAS.values()
            for key in schema["parameters"]["properties"]
        }
        self.assertTrue(properties.isdisjoint(
            {"workspace_id", "channel_id", "event_id", "destination", "learning_path"}))
        for schema in gateway.SCHEMAS.values():
            self.assertIs(schema["parameters"]["additionalProperties"], False)

    def test_schemas_have_strict_sanitizer_compatible_top_level_parameters(self):
        expected_properties = {
            "repository_access": {"action", "owner", "name"},
            "project_association": {
                "action", "expected_repository_id", "owner", "name", "repository_id",
            },
            "project_workspace": {
                "action", "target", "owner", "name", "expected_repository_id",
            },
            "channel_bookmarks": {"action", "title", "url", "bookmark_id"},
            "project_git": {
                "action", "expected_repository_id", "argv", "paths", "message",
                "expected_head", "expected_branch", "branch", "commit", "expected_base",
                "expected_sha", "expected_target",
            },
            "project_github": {
                "action", "expected_repository_id", "argv", "stdin", "comment_kind",
                "parent_number", "comment_id",
            },
            "risk_report": {"action", "category", "summary"},
        }
        expected_required = {
            name: {"action"} for name in gateway.TOOL_NAMES
        }
        expected_required.update({
            "repository_access": {"action", "owner", "name"},
            "risk_report": {"action", "category", "summary"},
        })
        for name, schema in gateway.SCHEMAS.items():
            with self.subTest(tool=name):
                parameters = schema["parameters"]
                self.assertEqual(parameters["type"], "object")
                self.assertEqual(set(parameters["properties"]), expected_properties[name])
                self.assertTrue(parameters["properties"])
                self.assertEqual(set(parameters["required"]), expected_required[name])
                self.assertTrue(
                    {"oneOf", "anyOf", "allOf"}.isdisjoint(parameters), parameters)
                self.assertIs(parameters["additionalProperties"], False)

    def test_representative_action_payloads_fit_flattened_schema_contracts(self):
        sha_a, sha_b = "a" * 40, "b" * 40
        payloads = {
            "repository_access": [
                {"action": "observe", "owner": "acme", "name": "repo"},
            ],
            "project_association": [
                {"action": "show"},
                {"action": "set", "expected_repository_id": None, "owner": "acme",
                 "name": "repo", "repository_id": "33"},
                {"action": "clear", "expected_repository_id": None},
            ],
            "project_workspace": [
                {"action": "inspect", "target": "candidate", "owner": "acme",
                 "name": "repo", "expected_repository_id": "33"},
                {"action": "initialize", "target": "current"},
                {"action": "fetch", "target": "current"},
                {"action": "learning_snapshot"},
            ],
            "channel_bookmarks": [
                {"action": "list"},
                {"action": "add", "title": "Project", "url": "https://example.test"},
                {"action": "delete", "bookmark_id": "B1"},
            ],
            "project_git": [
                {"action": "help"},
                {"action": "run", "expected_repository_id": "33", "argv": ["status"]},
                {"action": "commit", "expected_repository_id": "33", "paths": ["file"],
                 "message": "message", "expected_head": sha_a, "expected_branch": "topic"},
                {"action": "remote_ref", "expected_repository_id": "33", "branch": "topic"},
                {"action": "push", "expected_repository_id": "33", "branch": "topic",
                 "commit": sha_b, "expected_base": sha_a},
                {"action": "delete_remote_branch", "expected_repository_id": "33",
                 "branch": "topic", "expected_sha": sha_b},
                {"action": "checkout_default", "expected_repository_id": "33",
                 "expected_branch": "topic", "expected_head": sha_a,
                 "expected_target": sha_b},
            ],
            "project_github": [
                {"action": "help"},
                {"action": "run", "expected_repository_id": "33",
                 "argv": ["issue", "list"], "stdin": None},
                {"action": "comment_delete", "expected_repository_id": "33",
                 "comment_kind": "issue", "parent_number": 7, "comment_id": 9},
            ],
            "risk_report": [
                {"action": "create", "category": "circumvention", "summary": "summary"},
            ],
        }
        for name, examples in payloads.items():
            parameters = gateway.SCHEMAS[name]["parameters"]
            advertised = set(parameters["properties"])
            required = set(parameters["required"])
            actions = set(parameters["properties"]["action"]["enum"])
            self.assertEqual({payload["action"] for payload in examples}, actions)
            for payload in examples:
                with self.subTest(tool=name, action=payload["action"]):
                    self.assertLessEqual(set(payload), advertised)
                    self.assertLessEqual(required, set(payload))
                    self.assertIn(payload["action"], actions)

    def test_registered_actions_match_the_durable_public_contract(self):
        expected = {
            "repository_access": {"observe"},
            "project_association": {"show", "set", "clear"},
            "project_workspace": {"inspect", "initialize", "fetch", "learning_snapshot"},
            "channel_bookmarks": {"list", "add", "delete"},
            "project_git": {"help", "run", "commit", "remote_ref", "push",
                            "delete_remote_branch", "checkout_default"},
            "project_github": {"help", "run", "comment_delete"},
            "risk_report": {"create"},
        }
        actual = {}
        for name, schema in gateway.SCHEMAS.items():
            actual[name] = set(schema["parameters"]["properties"]["action"]["enum"])
        self.assertEqual(actual, expected)

    def test_manifest_identity_entrypoint_environment_and_tool_parity(self):
        text = (PLUGIN / "plugin.yaml").read_text(encoding="utf-8")
        lines = text.splitlines()

        def scalar(name):
            return next(line.split(":", 1)[1].strip() for line in lines
                        if line.startswith(f"{name}:"))

        env_start = lines.index("requires_env:")
        tools_start = lines.index("provides_tools:")
        required_env = tuple(
            line.strip().split(":", 1)[1].strip()
            for line in lines[env_start + 1:tools_start]
            if line.strip().startswith("- name:")
        )
        tools = tuple(line.strip()[2:] for line in lines[tools_start + 1:]
                      if line.strip().startswith("- "))

        self.assertEqual(scalar("name"), "project-gateway")
        self.assertEqual(scalar("entrypoint"), "__init__.py")
        self.assertEqual(scalar("entrypoint"), ENTRYPOINT)
        self.assertEqual(Path(gateway.__file__).resolve(), (PLUGIN / ENTRYPOINT).resolve())
        self.assertEqual(scalar("kind"), "backend")
        self.assertEqual(scalar("toolset"), gateway.TOOLSET_NAME)
        self.assertEqual(required_env, (
            "GITHUB_APP_ID", "GITHUB_APP_INSTALLATION_ID", "GITHUB_APP_PRIVATE_KEY_PATH",
            "SLACK_BOT_TOKEN", "PEIRCE_SLACK_WORKSPACE_ID", "PEIRCE_SOURCE_CHANNEL_ID",
            "PEIRCE_SOURCE_REPOSITORY_ID", "PEIRCE_ADMIN_CHANNEL_ID",
            "PEIRCE_ADMIN_REPOSITORY_ID", "PEIRCE_PROJECT_WORKSPACE_ROOT",
            "PEIRCE_PROJECT_STATE_ROOT", "HERMES_PROJECTS_DB",
        ))
        self.assertEqual(tools, gateway.TOOL_NAMES)
        self.assertNotIn("enabled:", text)

    def test_active_source_configuration_mapping_and_docs_match_gateway_contract(self):
        repository = PLUGIN.parents[1]
        config = (repository / "config.yaml").read_text(encoding="utf-8")
        self.assertIn("_config_version: 33", config)
        self.assertIn("platforms:\n  slack:\n    enabled: false", config)
        self.assertNotIn("home_channel", config)
        self.assertIn(
            "slack: [terminal, file, web, session_search, memory, skills, project_gateway, no_mcp]",
            config,
        )
        enabled = config.split("plugins:\n  enabled:\n", 1)[1].split("\n\nagent:", 1)[0]
        self.assertEqual(enabled.strip(), "- project-gateway")

        mapping = json.loads((repository / "config" / "channel-projects.yaml").read_text())
        self.assertEqual(mapping, {
            "schema_version": 1,
            "fixed_projects": {
                "source": {
                    "workspace_id_env": "PEIRCE_SLACK_WORKSPACE_ID",
                    "channel_id_env": "PEIRCE_SOURCE_CHANNEL_ID",
                    "repository_id": "101",
                    "owner": "peirce-example", "name": "peirce",
                    "worktree": "/srv/hermes/project-state/workspace/projects/peirce",
                    "gitdir": "/srv/hermes/project-state/gateway/reserved/peirce.git",
                    "url": "https://github.com/peirce-example/peirce.git",
                    "default_branch": "main",
                },
                "admin": {
                    "workspace_id_env": "PEIRCE_SLACK_WORKSPACE_ID",
                    "channel_id_env": "PEIRCE_ADMIN_CHANNEL_ID",
                    "repository_id": "202",
                    "owner": "peirce-example", "name": "peirce-admin",
                    "worktree": "/srv/hermes/project-state/workspace/projects/peirce-admin",
                    "gitdir": "/srv/hermes/project-state/gateway/reserved/peirce-admin.git",
                    "url": "https://github.com/peirce-example/peirce-admin.git",
                    "default_branch": "main",
                },
            },
        })
        self.assertEqual(
            mapping["fixed_projects"]["source"]["repository_id"],
            gateway.host_boundary.FIXED_SOURCE_REPOSITORY_ID,
        )
        self.assertEqual(
            mapping["fixed_projects"]["admin"]["repository_id"],
            gateway.host_boundary.FIXED_ADMIN_REPOSITORY_ID,
        )

    def test_fixed_mapping_roots_match_config_and_runtime_builder(self):
        repository = PLUGIN.parents[1]
        config = (repository / "config.yaml").read_text(encoding="utf-8")
        terminal = config.split("terminal:\n", 1)[1].split("\ngateway:", 1)[0]
        configured_cwd = next(
            line.split(":", 1)[1].strip() for line in terminal.splitlines()
            if line.startswith("  cwd:")
        )
        configured_volume = next(
            line.strip()[2:].strip().strip('"') for line in terminal.splitlines()
            if line.strip().startswith("- ")
        )
        configured_bind_root = Path(configured_volume.split(":", 1)[0])
        self.assertEqual(Path(configured_cwd), configured_bind_root)

        mapping = json.loads((repository / "config" / "channel-projects.yaml").read_text())
        source_mapping = mapping["fixed_projects"]["source"]
        admin_mapping = mapping["fixed_projects"]["admin"]
        configured_state_root = Path(source_mapping["gitdir"]).parents[1]
        self.assertEqual(Path(admin_mapping["gitdir"]).parents[1], configured_state_root)

        workspace_root = configured_bind_root / "projects"
        project_registry = gateway.registry.ProjectRegistry(
            configured_state_root / "projects.db",
            workspace_root=workspace_root,
            state_root=configured_state_root,
        )
        fixed = gateway.project.build_peirce_isolated_projects(
            project_registry,
            "workspace-example",
            "source-channel",
            gateway.host_boundary.FIXED_SOURCE_REPOSITORY_ID,
            "admin-channel",
            gateway.host_boundary.FIXED_ADMIN_REPOSITORY_ID,
            "7",
        )

        for layout, route in zip(("source", "admin"), fixed):
            with self.subTest(layout=layout):
                mapped = mapping["fixed_projects"][layout]
                mapped_worktree = Path(mapped["worktree"])
                mapped_gitdir = Path(mapped["gitdir"])
                self.assertEqual(
                    mapped_worktree.relative_to(configured_bind_root),
                    Path("projects") / route.repository.name,
                )
                self.assertEqual(mapped_worktree, Path(route.repository.worktree))
                self.assertEqual(mapped_gitdir, Path(route.repository.trusted_gitdir))

        manifests = {path.parent.name for path in (repository / "plugins").glob("*/plugin.yaml")}
        self.assertEqual(manifests, {"project-gateway"})
        self.assertFalse((repository / "plugins" / "research-github").exists())

        expected_actions = {
            "repository_access": "`observe`",
            "project_association": "`show`, `set`, `clear`",
            "project_workspace": "`inspect`, `initialize`, `fetch`, `learning_snapshot`",
            "channel_bookmarks": "`list`, `add`, `delete`",
            "project_git": ("`help`, `run`, `commit`, `remote_ref`, `push`, "
                            "`delete_remote_branch`, `checkout_default`"),
            "project_github": "`help`, `run`, `comment_delete`",
            "risk_report": "`create`",
        }
        plugin_contract = (PLUGIN / "README.md").read_text(encoding="utf-8")
        headings = tuple(
            line.removeprefix("### `").removesuffix("`")
            for line in plugin_contract.splitlines() if line.startswith("### `")
        )
        self.assertEqual(headings, gateway.TOOL_NAMES)
        ledger = (repository / "docs" / "access-and-permissions.md").read_text(
            encoding="utf-8")
        ledger_actions = {}
        for line in ledger.splitlines():
            cells = [cell.strip() for cell in line.split("|")]
            if len(cells) >= 4 and cells[1].startswith("`"):
                ledger_actions[cells[1].strip("`")] = cells[2]
        self.assertEqual(ledger_actions, expected_actions)
        for retired in ("project_management", "git_exec", "gh_exec"):
            self.assertNotIn(f"`{retired}`", plugin_contract)
            self.assertNotIn(f"`{retired}`", ledger)

    def test_slack_visibility_policy_is_quiet_balanced_and_documented(self):
        repository = PLUGIN.parents[1]
        config = (repository / "config.yaml").read_text(encoding="utf-8")
        readme = (repository / "docs" / "using-peirce.md").read_text(encoding="utf-8")

        self.assertIn("  gateway_notify_interval: 0", config)
        display_config = config.split("\ndisplay:\n", 1)[1].split("\n\nmemory:", 1)[0]
        top_level_display = display_config.split("  platforms:\n", 1)[0]
        command_progress = tuple(
            line.strip() for line in top_level_display.splitlines()
            if line.startswith("  tool_progress_command:")
        )
        self.assertTrue(
            not command_progress or command_progress == ("tool_progress_command: false",),
            command_progress,
        )
        slack_config = config.split("    slack:\n", 1)[1].split("\n\nmemory:", 1)[0]
        expected_slack_config = {
            "live_status": "verb",
            "tool_preview_length": "100",
            "tool_progress": '"off"',
            "tool_progress_grouping": "accumulate",
            "interim_assistant_messages": "true",
            "long_running_notifications": '"off"',
            "cleanup_progress": "true",
            "streaming": "false",
            "show_reasoning": "false",
            "thinking_progress": "false",
        }
        for key, value in expected_slack_config.items():
            with self.subTest(config_key=key):
                self.assertIn(f"      {key}: {value}", slack_config)
        self.assertNotIn("status_phrases:", slack_config)
        self.assertNotIn("      live_status: full", slack_config)
        self.assertNotIn("      tool_progress: new", slack_config)

        readme_flat = " ".join(readme.split())
        for phrase in (
            "persistent tool-progress messages and command/path previews are absent",
            "Full-command progress is disabled",
            "Verb-only ephemeral status updates contain no arguments",
            "Natural interim commentary",
            "dormant defense-in-depth bound",
            "any preview-capable path, including generic tool previews",
            "not observed in ordinary turns",
            "such a path is enabled later",
            "truncation is not redaction",
            "safe for persistent Slack history",
        ):
            with self.subTest(readme_phrase=phrase):
                self.assertIn(phrase, readme_flat)
        self.assertNotIn("normal terminal progress shows", readme_flat)
        self.assertNotIn("multiline commands may append", readme_flat)

    def test_public_snapshot_privacy_guards(self):
        repository = PLUGIN.parents[1]
        config = (repository / "config.yaml").read_text(encoding="utf-8")
        self.assertIn("platforms:\n  slack:\n    enabled: false", config)
        expected_starters = {
            "MEMORY.md": (
                "# Shared memory\n\n"
                "This public starter is intentionally empty. Add only reviewed, reusable facts\n"
                "that are safe to share; this file is not a raw runtime-memory export.\n"
            ),
            "USER.md": (
                "# Profile-wide user memory\n\n"
                "This public starter is intentionally empty. Do not add personal preferences or\n"
                "private user data without an explicit, reviewed, privacy-safe source change.\n"
            ),
        }
        for filename, expected in expected_starters.items():
            text = (repository / "memories" / filename).read_text(encoding="utf-8")
            self.assertEqual(text, expected)

        guidance = (repository / "skills" / "peirce-self-development" / "SKILL.md").read_text(
            encoding="utf-8")
        self.assertIn("Before pushing a", guidance)
        self.assertIn("creating a pull request", guidance)
        self.assertIn("raw memory-sync target", guidance)
        self.assertIn("not connected to live Peirce", guidance)

    def test_scoped_slack_disabled_check_rejects_unrelated_disabled_setting(self):
        repository = PLUGIN.parents[1]
        config = (repository / "config.yaml").read_text(encoding="utf-8")
        scoped = "platforms:\n  slack:\n    enabled: false"
        mutated = config.replace(
            scoped, "platforms:\n  slack:\n    enabled: true", 1
        ) + "\nunrelated_feature:\n  enabled: false\n"
        self.assertNotIn(scoped, mutated)

    def test_global_skill_filter_applies_without_platform_context(self):
        repository = PLUGIN.parents[1]
        config = (repository / "config.yaml").read_text(encoding="utf-8")
        skills_config = config.split("\nskills:\n", 1)[1].split("\n\ncurator:", 1)[0]
        self.assertIn("  creation_nudge_interval: 20\n", skills_config)
        self.assertNotIn("platform_disabled:", skills_config)
        disabled_text = skills_config.split("  disabled:\n", 1)[1]
        disabled = tuple(
            line.removeprefix("    - ")
            for line in disabled_text.splitlines()
            if line.startswith("    - ")
        )
        self.assertEqual(disabled, (
            "airtable", "apple-notes", "apple-reminders", "architecture-diagram",
            "ascii-art", "ascii-video", "baoyu-infographic", "blogwatcher",
            "claude-code", "claude-design", "codebase-inspection", "codex",
            "comfyui", "computer-use", "design-md", "docx", "dogfood",
            "evaluating-llms-harness", "excalidraw", "findmy", "gif-search",
            "github-auth", "github-code-review", "github-issues",
            "github-pr-workflow", "github-repo-management", "google-workspace",
            "hermes-agent", "hermes-agent-skill-authoring", "himalaya",
            "huggingface-hub", "imessage", "inspecting-hermes-desktop-dom",
            "llama-cpp", "llm-wiki", "manim-video", "maps", "nano-pdf",
            "node-inspect-debugger", "notion", "obsidian", "ocr-and-documents",
            "opencode", "openhue", "p5js", "plan", "polymarket",
            "popular-web-designs", "powerpoint", "pretext", "python-debugpy",
            "requesting-code-review", "research-paper-writing", "serving-llms-vllm",
            "simplify-code", "sketch", "songsee", "songwriting-and-ai-music",
            "systematic-debugging", "teams-meeting-pipeline",
            "test-driven-development", "touchdesigner-mcp", "weights-and-biases",
            "xlsx", "xurl", "youtube-content",
        ))
        retained = {
            "humanizer", "arxiv", "grounded-citations", "pdf", "spike",
            "using-peirce", "peirce-self-development",
        }
        self.assertTrue(retained.isdisjoint(disabled))

    def test_seed_skill_is_indexable_and_progressively_disclosed(self):
        repository = PLUGIN.parents[1]
        skill_path = repository / "skills" / "peirce-self-development" / "SKILL.md"
        content = skill_path.read_text(encoding="utf-8")
        opening, metadata_text, body = content.split("---", 2)
        self.assertEqual(opening, "")
        metadata = dict(line.split(":", 1) for line in metadata_text.strip().splitlines())
        metadata = {key.strip(): value.strip() for key, value in metadata.items()}
        self.assertEqual(metadata["name"], skill_path.parent.name)
        self.assertTrue(metadata["description"])
        self.assertIn("self-development", metadata["description"].lower())
        self.assertIn("explicitly configured", metadata["description"].lower())

        index_payload = json.dumps({metadata["name"]: metadata["description"]})
        distinctive_guidance = "Judge conflicts explicitly."
        self.assertIn(distinctive_guidance, body)
        self.assertNotIn(distinctive_guidance, index_payload)
        self.assertIn(distinctive_guidance, content)

        initial_context_sources = (
            (repository / "SOUL.md").read_text(encoding="utf-8"),
            (repository / "config.yaml").read_text(encoding="utf-8"),
            (PLUGIN / "plugin.yaml").read_text(encoding="utf-8"),
        )
        self.assertTrue(all(distinctive_guidance not in source
                            for source in initial_context_sources))

    def test_trusted_origin_comes_only_from_session_store(self):
        entry = SimpleNamespace(origin=SimpleNamespace(
            platform="slack", scope_id="W1", chat_id="C1"))
        gateway.pre_gateway_dispatch(session_store=lambda value: entry,
                                     event={"message_id": "E1"})
        with mock.patch.dict(os.environ, {"PEIRCE_SLACK_WORKSPACE_ID": "W1"}, clear=True):
            origin = gateway._trusted_origin("session")
            self.assertEqual((origin.workspace_id, origin.channel_id), ("W1", "C1"))
            result = json.loads(gateway.project_github(
                {"action": "help", "workspace_id": "W2"}, session_id="session"))
            self.assertFalse(result["ok"])

    def test_revised_workspace_git_and_comment_handlers_dispatch_exact_arguments(self):
        entry = SimpleNamespace(origin=SimpleNamespace(
            platform="slack", scope_id="W1", chat_id="C1"))
        gateway.pre_gateway_dispatch(session_store=lambda value: entry,
                                     event={"message_id": "E1"})
        calls = []
        current_locked = False
        @contextmanager
        def current_route(origin):
            nonlocal current_locked
            current_locked = True
            try:
                yield SimpleNamespace(repository="facts")
            finally:
                current_locked = False
        def initialize(facts):
            self.assertTrue(current_locked)
            calls.append(("initialize", facts))
            return "initialized"
        gate = SimpleNamespace(
            show=lambda origin: SimpleNamespace(repository="facts"),
            locked_current_channel_route=current_route,
            initialize_workspace=initialize,
            fetch_workspace=lambda facts: calls.append(("fetch", facts)) or "fetched",
            inspect_workspace=lambda facts: calls.append(("inspect", facts)) or "inspected",
        )
        git_client = SimpleNamespace(checkout_default=lambda origin, **kwargs:
            calls.append(("checkout", kwargs)) or "checked_out")
        github_client = SimpleNamespace(comment_delete=lambda origin, **kwargs:
            calls.append(("comment_delete", kwargs)) or "deleted")

        def runtime(*, capability, **_):
            return {"gateway": gate, "git": git_client, "github": github_client}[capability]

        prior = gateway._RUNTIME_FACTORY
        gateway._RUNTIME_FACTORY = runtime
        try:
            with mock.patch.dict(os.environ, {"PEIRCE_SLACK_WORKSPACE_ID": "W1"}, clear=True):
                initialized = json.loads(gateway.project_workspace(
                    {"action": "initialize", "target": "current"}, session_id="session"))
                checked_out = json.loads(gateway.project_git({
                    "action": "checkout_default", "expected_repository_id": "33",
                    "expected_branch": "hermes/task", "expected_head": "a" * 40,
                    "expected_target": "b" * 40,
                }, session_id="session"))
                deleted = json.loads(gateway.project_github({
                    "action": "comment_delete", "expected_repository_id": "33",
                    "comment_kind": "review", "parent_number": 7, "comment_id": 9,
                }, session_id="session"))
        finally:
            gateway._RUNTIME_FACTORY = prior
        self.assertTrue(initialized["ok"] and checked_out["ok"] and deleted["ok"])
        self.assertEqual(calls, [
            ("initialize", "facts"),
            ("checkout", {"expected_repository_id": "33", "expected_branch": "hermes/task",
                          "expected_head": "a" * 40, "expected_target": "b" * 40}),
            ("comment_delete", {"expected_repository_id": "33", "comment_kind": "review",
                                "parent_number": 7, "comment_id": 9}),
        ])

    def test_checkout_default_alone_accepts_nullable_expected_head(self):
        expected_head = gateway.SCHEMAS["project_git"]["parameters"]["properties"][
            "expected_head"]

        self.assertEqual(expected_head, {
            "oneOf": [gateway.SHA, {"type": "null"}],
        })
        for schema in gateway.SCHEMAS.values():
            for property_schema in schema["parameters"]["properties"].values():
                self.assertFalse(any("oneOf" in choice
                                     for choice in property_schema.get("oneOf", [])))

        entry = SimpleNamespace(origin=SimpleNamespace(
            platform="slack", scope_id="W1", chat_id="C1"))
        gateway.pre_gateway_dispatch(session_store=lambda value: entry,
                                     event={"message_id": "E1"})
        calls = []
        client = SimpleNamespace(
            checkout_default=lambda origin, **kwargs:
                calls.append(("checkout_default", kwargs)) or "checked_out",
            commit=lambda origin, **kwargs:
                calls.append(("commit", kwargs)) or "committed",
        )
        prior = gateway._RUNTIME_FACTORY
        gateway._RUNTIME_FACTORY = lambda **kwargs: client
        try:
            with mock.patch.dict(os.environ, {"PEIRCE_SLACK_WORKSPACE_ID": "W1"}, clear=True):
                unborn = json.loads(gateway.project_git({
                    "action": "checkout_default", "expected_repository_id": "33",
                    "expected_branch": "main", "expected_head": None,
                    "expected_target": "b" * 40,
                }, session_id="session"))
                invalid_checkout = json.loads(gateway.project_git({
                    "action": "checkout_default", "expected_repository_id": "33",
                    "expected_branch": "main", "expected_head": "bad",
                    "expected_target": "b" * 40,
                }, session_id="session"))
                omitted_checkout = json.loads(gateway.project_git({
                    "action": "checkout_default", "expected_repository_id": "33",
                    "expected_branch": "main", "expected_target": "b" * 40,
                }, session_id="session"))
                invalid_commit = json.loads(gateway.project_git({
                    "action": "commit", "expected_repository_id": "33", "paths": ["file"],
                    "message": "message", "expected_head": None,
                    "expected_branch": "topic",
                }, session_id="session"))
                valid_commit = json.loads(gateway.project_git({
                    "action": "commit", "expected_repository_id": "33", "paths": ["file"],
                    "message": "message", "expected_head": "a" * 40,
                    "expected_branch": "topic",
                }, session_id="session"))
        finally:
            gateway._RUNTIME_FACTORY = prior
        self.assertTrue(unborn["ok"], unborn)
        self.assertFalse(invalid_checkout["ok"], invalid_checkout)
        self.assertFalse(omitted_checkout["ok"], omitted_checkout)
        self.assertFalse(invalid_commit["ok"], invalid_commit)
        self.assertTrue(valid_commit["ok"], valid_commit)
        self.assertEqual(calls, [
            ("checkout_default", {"expected_repository_id": "33", "expected_branch": "main",
                                  "expected_head": None, "expected_target": "b" * 40}),
            ("commit", {"expected_repository_id": "33", "paths": ["file"],
                        "message": "message", "expected_head": "a" * 40,
                        "expected_branch": "topic"}),
        ])

    def test_every_registered_action_dispatches_through_its_public_handler(self):
        entry = SimpleNamespace(origin=SimpleNamespace(
            platform="slack", scope_id="W1", chat_id="C1"))
        gateway.pre_gateway_dispatch(session_store=lambda value: entry,
                                     event={"message_id": "E1"})
        records = []

        def recorded(name):
            def call(*args, **kwargs):
                records.append((name, args, kwargs))
                return {"method": name}
            return call

        @contextmanager
        def current_route(_origin):
            yield SimpleNamespace(repository="facts")

        gate = SimpleNamespace(
            show=recorded("association.show"), set=recorded("association.set"),
            clear=recorded("association.clear"),
            locked_current_channel_route=current_route,
            inspect_workspace=recorded("workspace.inspect"),
            initialize_workspace=recorded("workspace.initialize"),
            fetch_workspace=recorded("workspace.fetch"),
            learning_snapshot=recorded("workspace.learning_snapshot"),
        )
        bookmarks = SimpleNamespace(
            list_bookmarks=recorded("bookmarks.list"),
            add_bookmark=recorded("bookmarks.add"),
            delete_bookmark=recorded("bookmarks.delete"),
        )
        git_client = SimpleNamespace(**{
            name: recorded(f"git.{name}") for name in
            ("run", "commit", "remote_ref", "push", "delete_remote_branch", "checkout_default")
        })
        github_client = SimpleNamespace(
            run=recorded("github.run"), comment_delete=recorded("github.comment_delete"))
        risk_client = SimpleNamespace(create=recorded("risk.create"))
        broker = SimpleNamespace(access_reader=recorded("access.observe"))

        def runtime(*, capability, **_):
            return {
                "access": broker, "gateway": gate, "bookmarks": bookmarks,
                "git": git_client, "github": github_client, "risk": risk_client,
            }[capability]

        sha_a, sha_b = "a" * 40, "b" * 40
        calls = (
            (gateway.repository_access, {"action": "observe", "owner": "acme", "name": "repo"}),
            (gateway.project_association, {"action": "show"}),
            (gateway.project_association, {"action": "set", "expected_repository_id": None,
                "owner": "acme", "name": "repo", "repository_id": "33"}),
            (gateway.project_association, {"action": "clear", "expected_repository_id": "33"}),
            (gateway.project_workspace, {"action": "inspect", "target": "current"}),
            (gateway.project_workspace, {"action": "initialize", "target": "current"}),
            (gateway.project_workspace, {"action": "fetch", "target": "current"}),
            (gateway.project_workspace, {"action": "learning_snapshot"}),
            (gateway.channel_bookmarks, {"action": "list"}),
            (gateway.channel_bookmarks, {"action": "add", "title": "Project", "url": "https://example.test"}),
            (gateway.channel_bookmarks, {"action": "delete", "bookmark_id": "B1"}),
            (gateway.project_git, {"action": "run", "expected_repository_id": "33", "argv": ["status"]}),
            (gateway.project_git, {"action": "commit", "expected_repository_id": "33",
                "paths": ["file"], "message": "message", "expected_head": sha_a,
                "expected_branch": "topic"}),
            (gateway.project_git, {"action": "remote_ref", "expected_repository_id": "33", "branch": "topic"}),
            (gateway.project_git, {"action": "push", "expected_repository_id": "33",
                "branch": "topic", "commit": sha_b, "expected_base": sha_a}),
            (gateway.project_git, {"action": "delete_remote_branch", "expected_repository_id": "33",
                "branch": "topic", "expected_sha": sha_b}),
            (gateway.project_git, {"action": "checkout_default", "expected_repository_id": "33",
                "expected_branch": "topic", "expected_head": sha_a, "expected_target": sha_b}),
            (gateway.project_github, {"action": "run", "expected_repository_id": "33",
                "argv": ["issue", "list"], "stdin": None}),
            (gateway.project_github, {"action": "comment_delete", "expected_repository_id": "33",
                "comment_kind": "issue", "parent_number": 7, "comment_id": 9}),
            (gateway.risk_report, {"action": "create", "category": "circumvention",
                "summary": "summary"}),
        )
        prior = gateway._RUNTIME_FACTORY
        gateway._RUNTIME_FACTORY = runtime
        try:
            with mock.patch.dict(os.environ, {"PEIRCE_SLACK_WORKSPACE_ID": "W1"}, clear=True):
                results = [json.loads(handler(payload, session_id="session"))
                           for handler, payload in calls]
        finally:
            gateway._RUNTIME_FACTORY = prior
        self.assertTrue(all(result["ok"] for result in results), results)
        self.assertEqual({record[0] for record in records}, {
            "access.observe", "association.show", "association.set", "association.clear",
            "workspace.inspect", "workspace.initialize", "workspace.fetch",
            "workspace.learning_snapshot", "bookmarks.list", "bookmarks.add", "bookmarks.delete",
            "git.run", "git.commit", "git.remote_ref", "git.push", "git.delete_remote_branch",
            "git.checkout_default", "github.run", "github.comment_delete", "risk.create",
        })

    def test_candidate_workspace_uses_immutable_id_observation_not_access_capability(self):
        entry = SimpleNamespace(origin=SimpleNamespace(
            platform="slack", scope_id="W1", chat_id="C1"))
        gateway.pre_gateway_dispatch(session_store=lambda value: entry,
                                     event={"message_id": "E1"})
        observed = gateway.project.ProviderObservation(
            "33", "7", "new-owner", "new-name",
            "https://github.com/new-owner/new-name.git", "trunk")
        candidates = []
        gate = SimpleNamespace(
            provider_reader=lambda candidate: candidates.append(candidate) or observed,
            _transient_facts=lambda value: "fresh-facts",
            inspect_workspace=lambda facts: {"facts": facts},
            initialize_workspace=lambda facts: {"facts": facts},
            fetch_workspace=lambda facts: {"facts": facts},
        )
        prior = gateway._RUNTIME_FACTORY
        gateway._RUNTIME_FACTORY = lambda **kwargs: gate
        try:
            with mock.patch.dict(os.environ, {"PEIRCE_SLACK_WORKSPACE_ID": "W1"}, clear=True):
                result = json.loads(gateway.project_workspace({
                    "action": "inspect", "target": "candidate", "owner": "old-owner",
                    "name": "old-name", "expected_repository_id": "33",
                }, session_id="session"))
        finally:
            gateway._RUNTIME_FACTORY = prior
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["result"], {"facts": "fresh-facts"})
        self.assertEqual(candidates[0].repository_id, "33")

    def test_risk_report_create_is_independent_of_registry_failure(self):
        entry = SimpleNamespace(origin=SimpleNamespace(
            platform="slack", scope_id="W1", chat_id="C1"))
        gateway.pre_gateway_dispatch(session_store=lambda value: entry,
                                     event={"message_id": "E1"})
        created = []
        reporter = SimpleNamespace(create=lambda *args:
            created.append(args) or {"state": "created"})

        def runtime(*, capability, **_):
            if capability == "risk":
                return reporter
            raise RuntimeError("registry unavailable")

        prior = gateway._RUNTIME_FACTORY
        gateway._RUNTIME_FACTORY = runtime
        try:
            with mock.patch.dict(os.environ, {"PEIRCE_SLACK_WORKSPACE_ID": "W1"}, clear=True):
                result = json.loads(gateway.risk_report({
                    "action": "create", "category": "circumvention", "summary": "summary",
                }, session_id="session"))
        finally:
            gateway._RUNTIME_FACTORY = prior
        self.assertTrue(result["ok"], result)
        self.assertEqual(len(created), 1)
        self.assertIsNone(created[0][-1])

    def test_production_environment_validator_returns_names_not_values(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            values = {
                "GITHUB_APP_ID": "1", "GITHUB_APP_INSTALLATION_ID": "2",
                "GITHUB_APP_PRIVATE_KEY_PATH": str(root / "key.pem"),
                "SLACK_BOT_TOKEN": "secret-token", "PEIRCE_SLACK_WORKSPACE_ID": "W1",
                "PEIRCE_SOURCE_CHANNEL_ID": "C1",
                "PEIRCE_SOURCE_REPOSITORY_ID": "101",
                "PEIRCE_ADMIN_CHANNEL_ID": "C2",
                "PEIRCE_ADMIN_REPOSITORY_ID": "202",
                "PEIRCE_PROJECT_WORKSPACE_ROOT": str(root / "workspace"),
                "PEIRCE_PROJECT_STATE_ROOT": str(root / "state"),
                "HERMES_PROJECTS_DB": str(root / "profile" / "projects.db"),
            }
            result = gateway.validate_production_environment(values)
            self.assertTrue(result["ok"])
            self.assertNotIn("secret-token", repr(result))
            values["PEIRCE_SOURCE_REPOSITORY_ID"] = "10"
            result = gateway.validate_production_environment(values)
            self.assertFalse(result["ok"])
            self.assertIn("PEIRCE_SOURCE_REPOSITORY_ID", result["invalid"])
            values["PEIRCE_SOURCE_REPOSITORY_ID"] = "101"
            values["PEIRCE_ADMIN_CHANNEL_ID"] = "C1"
            result = gateway.validate_production_environment(values)
            self.assertFalse(result["ok"])
            self.assertIn("PEIRCE_ADMIN_CHANNEL_ID", result["invalid"])
            values["PEIRCE_ADMIN_CHANNEL_ID"] = "C2"
            values["PEIRCE_PROJECT_WORKSPACE_ROOT"] = str(root / "profile" / "workspace")
            result = gateway.validate_production_environment(values)
            self.assertFalse(result["ok"])
            self.assertIn("HERMES_PROJECTS_DB", result["invalid"])
            values["PEIRCE_PROJECT_WORKSPACE_ROOT"] = str(root / "workspace")
            values["PEIRCE_PROJECT_STATE_ROOT"] = str(root / "profile" / "state")
            result = gateway.validate_production_environment(values)
            self.assertFalse(result["ok"])
            self.assertIn("PEIRCE_PROJECT_STATE_ROOT", result["invalid"])

    def test_repository_access_has_no_workspace_or_state_prerequisite(self):
        origin = gateway.project.TrustedOrigin("W1", "C1")
        with mock.patch.object(gateway.host_boundary.EnvironmentBroker, "access_reader",
                               return_value="observed") as reader:
            broker = gateway._runtime(origin, "access")
            self.assertEqual(broker.access_reader(
                gateway.project.RepositoryLocator("acme", "repo")), "observed")
        reader.assert_called_once()

    def test_production_session_store_and_runtime_composition_cover_each_capability_family(self):
        class SessionStore:
            def __init__(self):
                self.lookups = []

            def lookup_by_session_id(self, session_id):
                self.lookups.append(session_id)
                return SimpleNamespace(origin=SimpleNamespace(
                    platform="slack", scope_id="W1", chat_id="C1"))

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace, state, profile = root / "workspace", root / "state", root / "profile"
            for directory in (workspace, state, profile):
                directory.mkdir(mode=0o700)
            environment = {
                "GITHUB_APP_INSTALLATION_ID": "22",
                "PEIRCE_SLACK_WORKSPACE_ID": "W1",
                "PEIRCE_SOURCE_CHANNEL_ID": "C1",
                "PEIRCE_SOURCE_REPOSITORY_ID": "101",
                "PEIRCE_ADMIN_CHANNEL_ID": "C2",
                "PEIRCE_ADMIN_REPOSITORY_ID": "202",
                "PEIRCE_PROJECT_WORKSPACE_ROOT": str(workspace),
                "PEIRCE_PROJECT_STATE_ROOT": str(state),
                "HERMES_PROJECTS_DB": str(profile / "projects.db"),
            }
            store = SessionStore()
            gateway.pre_gateway_dispatch(session_store=store, event={"message_id": "E1"})
            prior = gateway._RUNTIME_FACTORY
            gateway._RUNTIME_FACTORY = None
            patches = (
                mock.patch.object(gateway.host_boundary.EnvironmentBroker, "access_reader",
                                  return_value={"repository_id": "55"}),
                mock.patch.object(gateway.project.ChannelBookmarks, "list_bookmarks",
                                  return_value={"state": "observed"}),
                mock.patch.object(gateway.ProjectGit, "run", return_value={"state": "observed"}),
                mock.patch.object(gateway.github.ProjectGitHub, "run",
                                  return_value={"state": "observed"}),
                mock.patch.object(gateway.github.RiskReporter, "create",
                                  return_value={"state": "created"}),
            )
            try:
                with mock.patch.dict(os.environ, environment, clear=True):
                    with patches[0] as access, patches[1] as bookmarks, patches[2] as git_run, \
                            patches[3] as github_run, patches[4] as risk_create:
                        calls = (
                            gateway.repository_access(
                                {"action": "observe", "owner": "acme", "name": "repo"},
                                session_id="session"),
                            gateway.project_association({"action": "show"}, session_id="session"),
                            gateway.channel_bookmarks({"action": "list"}, session_id="session"),
                            gateway.project_git({"action": "run", "expected_repository_id": "101",
                                                 "argv": ["status"]}, session_id="session"),
                            gateway.project_github({"action": "run", "expected_repository_id": "101",
                                                    "argv": ["issue", "list"], "stdin": None},
                                                   session_id="session"),
                            gateway.risk_report({"action": "create", "category": "circumvention",
                                                 "summary": "summary"}, session_id="session"),
                        )
            finally:
                gateway._RUNTIME_FACTORY = prior

        self.assertTrue(all(json.loads(value)["ok"] for value in calls), calls)
        self.assertEqual(store.lookups, ["session"] * len(calls))
        for patched in (access, bookmarks, git_run, github_run, risk_create):
            patched.assert_called_once()

    def test_production_runtime_wires_both_fixed_routes_with_exact_identity_and_paths(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace, state, profile = root / "workspace", root / "state", root / "profile"
            for directory in (workspace, state, profile):
                directory.mkdir(mode=0o700)
            environment = {
                "GITHUB_APP_INSTALLATION_ID": "22",
                "PEIRCE_SLACK_WORKSPACE_ID": "W1",
                "PEIRCE_SOURCE_CHANNEL_ID": "C1",
                "PEIRCE_SOURCE_REPOSITORY_ID": "101",
                "PEIRCE_ADMIN_CHANNEL_ID": "C2",
                "PEIRCE_ADMIN_REPOSITORY_ID": "202",
                "PEIRCE_PROJECT_WORKSPACE_ROOT": str(workspace),
                "PEIRCE_PROJECT_STATE_ROOT": str(state),
                "HERMES_PROJECTS_DB": str(profile / "projects.db"),
            }
            expected = {
                "C1": ("101", "peirce", workspace / "peirce",
                       state / "reserved" / "peirce.git"),
                "C2": ("202", "peirce-admin", workspace / "peirce-admin",
                       state / "reserved" / "peirce-admin.git"),
            }
            prior = gateway._RUNTIME_FACTORY
            gateway._RUNTIME_FACTORY = None
            try:
                with mock.patch.dict(os.environ, environment, clear=True):
                    for channel_id, (repository_id, name, worktree, gitdir) in expected.items():
                        with self.subTest(channel_id=channel_id):
                            origin = gateway.project.TrustedOrigin("W1", channel_id)
                            route = gateway._runtime(origin, "gateway").show(origin)
                            self.assertIsNotNone(route)
                            self.assertTrue(route.fixed)
                            self.assertEqual(route.origin, origin)
                            self.assertEqual(route.repository, gateway.registry.RepositoryFacts(
                                repository_id, name, "22", "peirce-example", name,
                                str(worktree), f"https://github.com/peirce-example/{name}.git",
                                "main", str(gitdir),
                            ))
            finally:
                gateway._RUNTIME_FACTORY = prior
            self.assertFalse((profile / "projects.db").exists())

            mismatches = (
                ("PEIRCE_SOURCE_REPOSITORY_ID", "gateway", "C1"),
                ("PEIRCE_ADMIN_REPOSITORY_ID", "gateway", "C2"),
                ("PEIRCE_ADMIN_REPOSITORY_ID", "risk", "C2"),
            )
            for env_name, capability, channel_id in mismatches:
                with self.subTest(mismatched=env_name):
                    invalid = dict(environment)
                    invalid[env_name] = "10"
                    with mock.patch.dict(os.environ, invalid, clear=True), \
                            self.assertRaises(gateway.ContractError):
                        gateway._runtime(
                            gateway.project.TrustedOrigin("W1", channel_id), capability)

    def test_environment_broker_uses_exact_github_transport_contract(self):
        with tempfile.TemporaryDirectory() as temporary:
            key = Path(temporary) / "app.pem"
            calls = []
            jwt_calls = []

            def transport(method, url, **kwargs):
                calls.append((method, url, kwargs))
                if url.endswith("/installation"):
                    return {"status_code": 200, "data": {"id": 22}}
                if url.endswith("/access_tokens"):
                    return {"status_code": 201, "data": {
                        "token": "installation-token", "expires_at": "2099-01-01T00:00:00Z",
                        "permissions": {"metadata": "read"},
                        "repository_selection": "selected",
                        "repositories": [{"id": 33, "name": "repo", "full_name": "acme/repo"}],
                    }}
                if url.endswith("/repos/acme/repo"):
                    return {"status_code": 200, "data": {
                        "id": 33, "owner": {"login": "acme"}, "name": "repo",
                        "full_name": "acme/repo", "clone_url": "https://github.com/acme/repo.git",
                        "default_branch": "main",
                    }}
                if url.endswith("/repositories/33"):
                    return {"status_code": 200, "data": {
                        "id": 33, "owner": {"login": "acme"}, "name": "repo",
                        "full_name": "acme/repo", "clone_url": "https://github.com/acme/repo.git",
                        "default_branch": "main",
                    }}
                return {"status_code": 200, "data": {}}

            def encode(payload, private_key, algorithm):
                jwt_calls.append((payload, private_key, algorithm))
                return "app-jwt"

            broker = gateway.EnvironmentBroker({
                "GITHUB_APP_ID": "11", "GITHUB_APP_INSTALLATION_ID": "22",
                "GITHUB_APP_PRIVATE_KEY_PATH": str(key),
            }, http_transport=transport, jwt_encoder=encode, clock=lambda: 1000)
            with mock.patch.object(broker, "_private_key", return_value=b"private-key"):
                observed = broker.access_reader(SimpleNamespace(owner="acme", name="repo"))
                refreshed = broker.observe(SimpleNamespace(repository_id="33", owner="acme", name="repo"))
            self.assertEqual((observed.repository_id, observed.installation_id), ("33", "22"))
            self.assertEqual(observed.url, "https://github.com/acme/repo.git")
            self.assertEqual(refreshed, observed)
            self.assertEqual(jwt_calls[0], ({"iat": 970, "exp": 1540, "iss": "11"},
                                            b"private-key", "RS256"))
            self.assertTrue(all(call[1].startswith("https://api.github.com/") for call in calls))
            self.assertTrue(all(call[2]["allow_redirects"] is False
                                and call[2]["trust_env"] is False for call in calls))
            self.assertTrue(all(call[2]["headers"]["X-GitHub-Api-Version"] == "2026-03-10"
                                 for call in calls))
            repository_calls = [call for call in calls
                                if call[1].endswith(("/repos/acme/repo", "/repositories/33"))]
            self.assertTrue(all(call[2]["headers"]["Authorization"] ==
                                "Bearer installation-token" for call in repository_calls))
            installation_calls = [call for call in calls if call[1].endswith("/installation")]
            self.assertTrue(all(call[2]["headers"]["Authorization"] == "Bearer app-jwt"
                                for call in installation_calls))

    def test_default_http_adapter_is_bounded_proxy_free_non_redirecting_and_closes(self):
        class Response:
            def __init__(self, payload, status=200):
                self.payload = payload
                self.status = status
                self.closed = False
                self.read_limits = []

            def read(self, limit):
                self.read_limits.append(limit)
                return self.payload

            def close(self):
                self.closed = True

        success = Response(b'{"ok":true}')
        opener = SimpleNamespace(open=mock.Mock(return_value=success))
        with mock.patch.object(urllib.request, "build_opener", return_value=opener) as build:
            result = gateway.host_boundary._stdlib_http_request(
                "POST", "https://api.example.test/value",
                headers={"Content-Type": "application/json"}, json_body={"value": "sent"})
        self.assertEqual(result, {"status_code": 200, "data": {"ok": True}})
        self.assertTrue(success.closed)
        self.assertEqual(success.read_limits, [gateway.host_boundary.MAX_PROVIDER_RESPONSE_BYTES + 1])
        opener.open.assert_called_once()
        self.assertEqual(opener.open.call_args.kwargs, {"timeout": 10.0})
        request = opener.open.call_args.args[0]
        self.assertEqual((request.method, request.full_url),
                         ("POST", "https://api.example.test/value"))
        self.assertEqual(request.data, b'{"value":"sent"}')
        self.assertEqual(request.headers["Content-type"], "application/json")
        handlers = build.call_args.args
        proxy = next(item for item in handlers if isinstance(item, urllib.request.ProxyHandler))
        redirect = next(item for item in handlers
                        if isinstance(item, urllib.request.HTTPRedirectHandler))
        self.assertEqual(proxy.proxies, {})
        self.assertIsNone(redirect.redirect_request(None, None, 302, "Found", {},
                                                    "https://redirect.example.test"))

        for payload, max_bytes in ((b"12345", 4), (b"{", 1024)):
            with self.subTest(payload=payload):
                response = Response(payload)
                fake = SimpleNamespace(open=mock.Mock(return_value=response))
                with mock.patch.object(urllib.request, "build_opener", return_value=fake), \
                        self.assertRaises(gateway.host_boundary.BoundaryError):
                    gateway.host_boundary._stdlib_http_request(
                        "GET", "https://api.example.test/value", headers={}, max_bytes=max_bytes)
                self.assertTrue(response.closed)
                self.assertEqual(response.read_limits, [max_bytes + 1])

        empty = Response(b"", status=204)
        empty_opener = SimpleNamespace(open=mock.Mock(return_value=empty))
        with mock.patch.object(urllib.request, "build_opener", return_value=empty_opener):
            result = gateway.host_boundary._stdlib_http_request(
                "DELETE", "https://api.example.test/value", headers={})
        self.assertEqual(result, {"status_code": 204, "data": None})
        self.assertTrue(empty.closed)
        self.assertIsNone(empty_opener.open.call_args.args[0].data)

        provider_error = urllib.error.HTTPError(
            "https://api.example.test/value", 422, "Rejected", {},
            io.BytesIO(b'{"message":"invalid"}'))
        failing_opener = SimpleNamespace(open=mock.Mock(side_effect=provider_error))
        with mock.patch.object(urllib.request, "build_opener", return_value=failing_opener):
            result = gateway.host_boundary._stdlib_http_request(
                "GET", "https://api.example.test/value", headers={})
        self.assertEqual(result, {"status_code": 422, "data": {"message": "invalid"}})
        self.assertTrue(provider_error.fp.closed)

        for unsafe in ({"allow_redirects": True}, {"trust_env": True}):
            with self.subTest(unsafe=unsafe), \
                    mock.patch.object(urllib.request, "build_opener") as build, \
                    self.assertRaises(gateway.host_boundary.BoundaryError):
                gateway.host_boundary._stdlib_http_request(
                    "GET", "https://api.example.test/value", headers={}, **unsafe)
            build.assert_not_called()

    def test_real_github_and_risk_results_serialize_mapping_proxies(self):
        process = MappingProxyType({"state": "exited", "uncertain": False})
        evidence = (MappingProxyType({"kind": "direct"}),)
        for value in (
            gateway.github.GitHubResult("applied", "update", "33", process, evidence),
            gateway.github.RiskReportResult("created", "create", "44", process, evidence),
        ):
            with self.subTest(type=type(value).__name__):
                result = json.loads(gateway._envelope(lambda: value))
                self.assertTrue(result["ok"])
                self.assertEqual(result["result"]["process"]["state"], "exited")
                self.assertEqual(result["result"]["evidence"], [{"kind": "direct"}])

    def test_environment_broker_narrows_token_and_slack_operations(self):
        with tempfile.TemporaryDirectory() as temporary:
            key = Path(temporary) / "app.pem"
            calls = []

            def transport(method, url, **kwargs):
                calls.append((method, url, kwargs))
                if "slack.com" in url:
                    return {"status_code": 200, "data": {"ok": True, "bookmarks": []}}
                return {"status_code": 201, "data": {"token": "installation-token"}}

            broker = gateway.EnvironmentBroker({
                "GITHUB_APP_ID": "11", "GITHUB_APP_INSTALLATION_ID": "22",
                "GITHUB_APP_PRIVATE_KEY_PATH": str(key), "SLACK_BOT_TOKEN": "slack-secret",
            }, http_transport=transport, jwt_encoder=lambda *args, **kwargs: "app-jwt")
            with mock.patch.object(broker, "_private_key", return_value=b"private-key"):
                raw = broker.token_reader({"permissions": {"metadata": "read"},
                                           "repository_ids": [33]})
            self.assertEqual(raw, {"token": "installation-token"})
            self.assertEqual(calls[0][2]["json_body"], {
                "permissions": {"metadata": "read"}, "repository_ids": [33]})
            value = broker.bookmark_transport("list", {"channel_id": "C1"})
            self.assertEqual(value, {"ok": True, "bookmarks": []})
            self.assertTrue(calls[1][1].endswith("/bookmarks.list"))
            self.assertEqual(calls[1][2]["json_body"], {"channel_id": "C1"})
            self.assertNotIn("slack-secret", repr(value))

    def test_environment_broker_accepts_documented_token_response_without_repository_echo(self):
        data = {
            "token": "installation-token", "expires_at": "2099-01-01T00:00:00Z",
            "permissions": {"metadata": "read"}, "repository_selection": "selected",
        }
        self.assertEqual(gateway.EnvironmentBroker._installation_token(
            data, {"metadata": "read"}, repository_id="33", owner="acme", name="repo"),
            "installation-token")

    def test_comment_transport_accepts_only_typed_comment_and_parent_paths(self):
        calls = []
        broker = gateway.EnvironmentBroker({}, http_transport=lambda method, url, **kwargs:
            calls.append((method, url)) or {"status_code": 204, "data": None})
        allowed = (
            "/repos/acme/repo/issues/7", "/repos/acme/repo/issues/comments/9",
            "/repos/acme/repo/pulls/7", "/repos/acme/repo/pulls/comments/9",
        )
        for path in allowed:
            with self.subTest(path=path):
                broker.comment_api_transport("GET", path, "token", "2026-03-10")
        for path in ("/repos/acme/repo/pulls/7/reviews/9",
                     "/repos/acme/repo/issues/7/comments/9"):
            with self.subTest(path=path), self.assertRaises(gateway.host_boundary.BoundaryError):
                broker.comment_api_transport("DELETE", path, "token", "2026-03-10")
        self.assertEqual(len(calls), len(allowed))


if __name__ == "__main__":
    unittest.main()
