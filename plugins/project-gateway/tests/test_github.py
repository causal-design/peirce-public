# SPDX-License-Identifier: AGPL-3.0-only
"""Provider-free public contract tests for GitHub capabilities."""

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock


from _package import github, host_boundary, project, registry


class GitHubTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir="/private/tmp")
        self.root = Path(self.temporary.name)
        self.root.chmod(0o700)
        self.state = self.root / "state"
        facts = registry.RepositoryFacts(
            "11", "repo", "7", "owner", "repo", str(self.root / "worktree"),
            "https://github.com/owner/repo.git", "main",
            str(self.state / "git" / "11"),
        )
        self.origin = project.TrustedOrigin("W1", "C1")
        store = registry.ProjectRegistry(self.root / "projects.db",
            workspace_root=self.root / "workspaces", state_root=self.state)
        self.observed = project.ProviderObservation(
            "11", "7", "owner", "repo", "https://github.com/owner/repo.git", "main")
        self.gateway = project.ProjectGateway(store, lambda _: self.observed,
            (project.FixedProject(self.origin, facts),), state_root=self.state)
        self.process_calls = []
        self.gateway.process_runner = self.runner
        self.gateway.token_reader = lambda request: self.token(
            str(request["repository_ids"][0]), "owner", "repo", request["permissions"])
        self.transport_calls = []
        self.gh = github.ProjectGitHub(self.gateway, self.transport)

    def tearDown(self):
        self.temporary.cleanup()

    @staticmethod
    def token(repository_id, owner, name, permissions, token="secret-token"):
        return {"token": token,
            "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat(),
            "permissions": permissions, "repository_selection": "selected",
            "repositories": [{"id": int(repository_id), "name": name,
                               "full_name": f"{owner}/{name}"}]}

    @staticmethod
    def admin_observer(_candidate):
        return project.ProviderObservation(
            "99", "7", github.ADMIN_OWNER, github.ADMIN_NAME,
            f"https://github.com/{github.ADMIN_OWNER}/{github.ADMIN_NAME}.git", "main")

    def runner(self, argv, **kwargs):
        self.process_calls.append((argv, kwargs))
        return {"state": "exited", "exit_code": 0, "stdout": "ok secret-token",
                "stderr": "", "uncertain": False, "stdout_truncated": False,
                "stderr_truncated": False, "uncertainty_facts": {}}

    def transport(self, method, path, token, api_version):
        self.assertEqual(api_version, github.GITHUB_API_VERSION)
        self.transport_calls.append((method, path, token, api_version))
        base = "https://api.github.com/repos/owner/repo"
        if method == "GET" and path.endswith("/issues/7"):
            return {"status_code": 200, "data": {"number": 7,
                "url": base + "/issues/7", "repository_url": base}}
        if method == "GET" and path.endswith("/issues/comments/9"):
            count = sum(call[:2] == ("GET", path) for call in self.transport_calls)
            if count > 1:
                return {"status_code": 404, "error": "not found"}
            return {"status_code": 200, "data": {"id": 9, "issue_url": base + "/issues/7"}}
        if method == "DELETE":
            return {"status_code": 204, "data": None}
        raise AssertionError((method, path))

    def test_help_is_route_and_transport_independent_and_copied(self):
        value = self.gh.help()
        value["high_level"]["issue"].append("hostile")
        self.assertNotIn("hostile", self.gh.help()["high_level"]["issue"])
        self.assertFalse(self.process_calls)
        self.assertFalse(self.transport_calls)
        self.assertNotIn("preview", repr(value).lower())
        self.assertEqual(value["permissions"]["contents"], "read")
        self.assertEqual(set(value["comment_delete"]["comment_kinds"]), {"issue", "review"})
        self.assertEqual(value["comment_delete"]["arguments"],
                         ["comment_kind", "parent_number", "comment_id"])

    def test_every_high_level_entry_has_a_closed_public_form(self):
        commands = {
            ("issue", "list"): [], ("issue", "view"): ["1"],
            ("issue", "create"): [], ("issue", "edit"): ["1"],
            ("issue", "close"): ["1"], ("issue", "reopen"): ["1"],
            ("issue", "comment"): ["1"], ("pr", "list"): [],
            ("pr", "view"): ["1"], ("pr", "create"): ["--head", "hermes/task"],
            ("pr", "edit"): ["1"], ("pr", "close"): ["1"],
            ("pr", "reopen"): ["1"], ("pr", "comment"): ["1"],
            ("pr", "checks"): ["1"], ("pr", "diff"): [],
            ("pr", "status"): [], ("repo", "view"): [],
        }
        for command, args in commands.items():
            with self.subTest(command=command):
                result = self.gh.run(self.origin, "11", [*command, *args])
                self.assertEqual(result.repository_id, "11")
        self.assertEqual(len(self.process_calls), len(commands))

    def test_close_and_reopen_cannot_also_comment(self):
        for command in (("issue", "close"), ("issue", "reopen"),
                        ("pr", "close"), ("pr", "reopen")):
            with self.subTest(command=command), self.assertRaises(github.GitHubError):
                self.gh.run(self.origin, "11", [*command, "1", "--comment", "second effect"])

    def test_selectors_and_all_comment_delete_suffixes_reject_before_provider(self):
        self.gateway.provider_reader = lambda _: self.fail("provider called")
        rejected = (["issue", "list", "--repo", "other/repo"],
            ["api", "repos/owner/repo/compare/fork:main...main"],
            ["api", "repos/owner/repo/compare/main...fork:main"],
            ["api", "repos/owner/repo/issues/comments/9", "-X", "DELETE"],
            ["api", "repos/owner/repo/issues/7/comments/9", "-X", "DELETE"],
            ["api", "repos/owner/repo/pulls/comments/9", "-X", "DELETE"],
            ["api", "repos/owner/repo/pulls/7/reviews/comments/9", "-X", "DELETE"],
            ["api", "repos/owner/repo/pulls/7/reviews/9", "-X", "DELETE"],
            ["api", "repos/owner/repo/issues/7/transfer", "-X", "POST",
             "--field", "new_owner=other", "--field", "new_repo=target"],
            ["api", "repos/owner/repo/issues", "--cache", "1h"])
        for argv in rejected:
            with self.subTest(argv=argv), self.assertRaises(github.GitHubError):
                self.gh.run(self.origin, "11", list(argv))

    def test_every_plan_forbidden_api_write_family_rejects_before_provider(self):
        provider_calls = []
        self.gateway.provider_reader = lambda candidate: provider_calls.append(candidate) or self.observed
        expected_families = (
            "contents", "files", "git", "data", "ref", "refs", "merge", "merges",
            "forks", "branches", "branch", "protection", "rulesets", "releases",
            "deployments", "collaborators", "teams", "keys", "hooks", "actions",
            "secrets", "variables", "workflows", "environments", "pages", "admin",
            "administration", "settings",
        )
        help_policy = github.github_policy_help()
        self.assertEqual(github.FORBIDDEN_FAMILIES, expected_families)
        self.assertEqual(help_policy["forbidden"][:len(expected_families)],
                         list(expected_families))
        suffixes = tuple(f"{family}/target" for family in expected_families) + (
            "pulls/1/merge", "pulls/1/update-branch", "issues/1/transfer",
        )
        for suffix in suffixes:
            argv = ["api", f"repos/owner/repo/{suffix}", "-X", "POST"]
            with self.subTest(suffix=suffix), self.assertRaises(github.GitHubError):
                self.gh.run(self.origin, "11", argv)
        self.assertEqual(provider_calls, [])
        self.assertFalse(self.process_calls)

    def test_exact_commit_status_write_uses_collaboration_scope_and_bounded_stdin(self):
        requests = []

        def token(request):
            requests.append(request)
            return self.token("11", "owner", "repo", request["permissions"])

        self.gateway.token_reader = token
        sha = "a" * 40
        body = json.dumps({"state": "success", "context": "provider-free"})
        result = self.gh.run(self.origin, "11", [
            "api", f"repos/owner/repo/statuses/{sha}", "-X", "POST", "--input", "-",
        ], stdin=body)

        self.assertEqual((result.state, result.effect, result.repository_id),
                         ("succeeded", "create", "11"))
        self.assertEqual(requests, [{
            "permissions": {
                "metadata": "read", "contents": "read", "issues": "write",
                "pull_requests": "write", "checks": "read", "statuses": "write",
            },
            "repository_ids": [11],
            "installation_id": 7,
        }])
        self.assertEqual(len(self.process_calls), 1)
        argv, options = self.process_calls[0]
        self.assertEqual(argv[2], f"repos/owner/repo/statuses/{sha}")
        self.assertEqual(options["stdin"], body)
        self.assertEqual(options["max_stdin_bytes"], github.MAX_STDIN_BYTES)

    def test_stdin_backed_api_fields_reject_before_provider(self):
        self.gateway.provider_reader = lambda _: self.fail("provider called")
        with self.assertRaises(github.GitHubError):
            self.gh.run(self.origin, "11", [
                "api", "repos/owner/repo/pulls", "-F", "head=@-",
                "-f", "base=main", "-f", "title=x"], stdin="attacker:branch")
        self.assertFalse(self.process_calls)

    def test_api_reads_high_risk_but_writes_do_not(self):
        self.assertEqual(self.gh.run(self.origin, "11",
            ["api", "repos/owner/repo/actions"]).state, "succeeded")
        for method in ("POST", "PATCH", "PUT", "DELETE"):
            with self.subTest(method=method), self.assertRaises(github.GitHubError):
                self.gh.run(self.origin, "11",
                    ["api", "repos/owner/repo/contents/file", "-X", method])

    def test_same_id_rename_supplies_fresh_url_environment_and_token(self):
        self.observed = project.ProviderObservation(
            "11", "8", "new-owner", "new-name",
            "https://github.com/new-owner/new-name.git", "trunk")
        self.gateway.token_reader = lambda request: self.token(
            "11", "new-owner", "new-name", request["permissions"])
        result = self.gh.run(self.origin, "11", ["api", "repos/owner/repo/issues"])
        argv, options = self.process_calls[-1]
        self.assertEqual(argv[2], "repos/new-owner/new-name/issues")
        self.assertEqual(argv[-2:], ["--header",
            "X-GitHub-Api-Version: 2026-03-10"])
        self.assertEqual(options["env"]["GH_REPO"], "new-owner/new-name")
        self.assertEqual(result.repository_id, "11")
        self.assertNotIn("secret-token", str(result.process))

    def test_api_version_header_is_not_added_to_high_level_commands(self):
        self.gh.run(self.origin, "11", ["issue", "list"])
        self.assertNotIn("--header", self.process_calls[-1][0])

    def test_different_id_rejects_before_token_and_process(self):
        self.observed = project.ProviderObservation(
            "12", "7", "owner", "repo", "https://github.com/owner/repo.git", "main")
        self.gateway.token_reader = lambda _: self.fail("token called")
        with self.assertRaises(github.GitHubError):
            self.gh.run(self.origin, "11", ["issue", "list"])
        self.assertFalse(self.process_calls)

    def test_mutation_timeout_is_unknown_and_one_shot(self):
        self.gateway.process_runner = lambda argv, **kwargs: self.process_calls.append(argv) or {
            "state": "timed_out", "exit_code": None, "uncertain": True,
            "stdout_truncated": False, "stderr_truncated": False}
        result = self.gh.run(self.origin, "11", ["issue", "create", "--title", "x"])
        self.assertTrue(result.uncertain)
        self.assertEqual(result.state, "unknown")
        self.assertEqual(len(self.process_calls), 1)

    def test_comment_delete_revalidates_and_deletes_exactly_once(self):
        result = self.gh.comment_delete(self.origin, "11", "issue", 7, 9)
        self.assertEqual(result.state, "deleted")
        self.assertEqual((result.comment_kind, result.parent_number, result.comment_id),
                         ("issue", 7, 9))
        self.assertEqual(sum(call[0] == "DELETE" for call in self.transport_calls), 1)
        self.assertEqual([call[0] for call in self.transport_calls], ["GET", "GET", "DELETE", "GET"])

    def test_pr_conversation_comment_success(self):
        base = "https://api.github.com/repos/owner/repo"
        calls = []

        def transport(method, path, token, api_version):
            calls.append((method, path))
            if path.endswith("/issues/7"):
                return {"status_code": 200, "data": {"number": 7,
                    "url": base + "/issues/7", "repository_url": base,
                    "pull_request": {"url": base + "/pulls/7"}}}
            if method == "DELETE":
                return {"status_code": 204, "data": None}
            count = sum(call == ("GET", path) for call in calls)
            return ({"status_code": 200, "data": {"id": 9,
                    "issue_url": base + "/issues/7"}} if count == 1
                    else {"status_code": 404, "error": "missing"})

        self.gh.api_transport = transport
        result = self.gh.comment_delete(self.origin, "11", "issue", 7, 9)
        self.assertEqual((result.state, result.comment_kind), ("deleted", "issue"))
        self.assertEqual([path for method, path in calls if method == "DELETE"],
                         ["/repos/owner/repo/issues/comments/9"])

    def test_review_comment_success_uses_typed_endpoint(self):
        base = "https://api.github.com/repos/owner/repo"
        calls = []

        def transport(method, path, token, api_version):
            calls.append((method, path))
            if path.endswith("/pulls/7"):
                return {"status_code": 200, "data": {"number": 7,
                    "url": base + "/pulls/7",
                    "base": {"repo": {"id": 11, "url": base}}}}
            if method == "DELETE":
                return {"status_code": 204, "data": None}
            count = sum(call == ("GET", path) for call in calls)
            return ({"status_code": 200, "data": {"id": 9,
                    "pull_request_url": base + "/pulls/7"}} if count == 1
                    else {"status_code": 404, "error": "missing"})

        self.gh.api_transport = transport
        result = self.gh.comment_delete(self.origin, "11", "review", 7, 9)
        self.assertEqual((result.state, result.comment_kind, result.parent_number),
                         ("deleted", "review", 7))
        self.assertEqual([path for method, path in calls if method == "DELETE"],
                         ["/repos/owner/repo/pulls/comments/9"])

    def test_comment_pre_read_absence_has_no_delete(self):
        self.gh.api_transport = lambda method, path, token, api_version: (
            {"status_code": 200, "data": {"number": 7,
             "url": "https://api.github.com/repos/owner/repo/issues/7",
             "repository_url": "https://api.github.com/repos/owner/repo"}}
            if path.endswith("/issues/7") else {"status_code": 404, "error": "missing"})
        result = self.gh.comment_delete(self.origin, "11", "issue", 7, 9)
        self.assertEqual(result.effect, "no_effect")

    def test_comment_parent_mismatch_rejects_before_delete(self):
        for parent in ({"number": 8}, {"number": 7,
                       "url": "https://api.github.com/repos/owner/repo/issues/7",
                       "repository_url": "https://api.github.com/repos/other/repo"},
                       {"number": 7,
                        "url": "https://api.github.com/repos/owner/repo/issues/7",
                        "repository_url": "https://api.github.com/repos/owner/repo",
                        "pull_request": {"url":
                            "https://api.github.com/repos/owner/repo/pulls/8"}}):
            with self.subTest(parent=parent):
                self.transport_calls.clear()
                self.gh.api_transport = lambda method, path, token, api_version, parent=parent: {
                    "status_code": 200, "data": parent}
                with self.assertRaises(github.GitHubError):
                    self.gh.comment_delete(self.origin, "11", "issue", 7, 9)
                self.assertFalse(any(call[0] == "DELETE" for call in self.transport_calls))

    def test_comment_wrong_kind_rejects_before_provider_or_transport(self):
        self.gateway.provider_reader = lambda _: self.fail("provider called")
        with self.assertRaises(github.GitHubError):
            self.gh.comment_delete(self.origin, "11", "conversation", 7, 9)
        self.assertFalse(self.transport_calls)

    def test_review_parent_mismatch_and_wrong_comment_kind_never_delete(self):
        base = "https://api.github.com/repos/owner/repo"
        parent = {"status_code": 200, "data": {"number": 7,
            "url": base + "/pulls/7", "base": {"repo": {"id": 11, "url": base}}}}
        wrong_kind_comment = {"status_code": 200, "data": {"id": 9,
            "issue_url": base + "/issues/7"}}
        mismatched_parent = {"status_code": 200, "data": {"number": 8,
            "url": base + "/pulls/8", "base": {"repo": {"id": 11, "url": base}}}}
        for label, responses in (("parent", (mismatched_parent,)),
                                 ("kind", (parent, wrong_kind_comment))):
            with self.subTest(label=label):
                calls = []
                values = iter(responses)
                self.gh.api_transport = lambda method, path, token, version: (
                    calls.append(method) or next(values))
                with self.assertRaises(github.GitHubError):
                    self.gh.comment_delete(self.origin, "11", "review", 7, 9)
                self.assertNotIn("DELETE", calls)

    def test_review_preflight_uncertainty_has_no_effect(self):
        base = "https://api.github.com/repos/owner/repo"
        responses = iter(({"status_code": 200, "data": {"number": 7,
            "url": base + "/pulls/7", "base": {"repo": {"id": 11, "url": base}}}},
            RuntimeError("offline")))
        calls = []

        def transport(method, path, token, api_version):
            calls.append(method)
            response = next(responses)
            if isinstance(response, Exception):
                raise response
            return response

        self.gh.api_transport = transport
        result = self.gh.comment_delete(self.origin, "11", "review", 7, 9)
        self.assertEqual((result.state, result.effect, result.uncertain),
                         ("unknown", "no_effect", True))
        self.assertNotIn("DELETE", calls)

    def test_comment_preflight_uncertainty_never_deletes(self):
        base = "https://api.github.com/repos/owner/repo"
        issue = {"status_code": 200, "data": {"number": 7,
            "url": base + "/issues/7", "repository_url": base}}
        cases = {
            "exception": RuntimeError("offline"),
            "server": {"status_code": 503, "error": "later"},
            "malformed": {"status_code": "200", "data": {}},
            "oversize": {"status_code": 200, "error": "x" * (github.MAX_API_RESPONSE_BYTES + 1)},
        }
        for label, failure in cases.items():
            with self.subTest(label=label):
                calls = []
                responses = iter((issue, failure))

                def transport(method, path, token, api_version):
                    calls.append(method)
                    response = next(responses)
                    if isinstance(response, Exception):
                        raise response
                    return response

                self.gh.api_transport = transport
                result = self.gh.comment_delete(self.origin, "11", "issue", 7, 9)
                self.assertEqual((result.state, result.effect, result.uncertain),
                                 ("unknown", "no_effect", True))
                self.assertEqual(calls.count("DELETE"), 0)

    def test_comment_delete_outcomes_are_conservative_and_postchecked(self):
        base = "https://api.github.com/repos/owner/repo"
        issue = {"status_code": 200, "data": {"number": 7,
            "url": base + "/issues/7", "repository_url": base}}
        comment = {"status_code": 200, "data": {"id": 9,
            "issue_url": base + "/issues/7"}}
        missing = {"status_code": 404, "error": "missing"}
        cases = (
            ("delete exception", RuntimeError("offline"), missing, ("unknown", "delete")),
            ("delete 5xx", {"status_code": 502, "error": "later"}, missing,
             ("unknown", "delete")),
            ("204 still present", {"status_code": 204, "data": None}, comment,
             ("unknown", "delete")),
            ("deterministic 4xx", {"status_code": 422, "error": "denied"}, comment,
             ("not_deleted", "no_effect")),
        )
        for label, deletion, post, expected in cases:
            with self.subTest(label=label):
                responses = iter((issue, comment, deletion, post))
                calls = []

                def transport(method, path, token, api_version):
                    self.assertEqual(api_version, github.GITHUB_API_VERSION)
                    calls.append((method, path))
                    response = next(responses)
                    if isinstance(response, Exception):
                        raise response
                    return response

                self.gh.api_transport = transport
                result = self.gh.comment_delete(self.origin, "11", "issue", 7, 9)
                self.assertEqual((result.state, result.effect), expected)
                self.assertEqual(sum(method == "DELETE" for method, _ in calls), 1)

    def test_comment_delete_uses_fresh_renamed_paths_and_exact_api_version(self):
        self.observed = project.ProviderObservation(
            "11", "8", "new-owner", "new-name",
            "https://github.com/new-owner/new-name.git", "trunk")
        self.gateway.token_reader = lambda request: self.token(
            "11", "new-owner", "new-name", request["permissions"])
        calls = []
        base = "https://api.github.com/repos/new-owner/new-name"

        def transport(method, path, token, api_version):
            calls.append((method, path, api_version))
            self.assertTrue(path.startswith("/repos/new-owner/new-name/"))
            if path.endswith("/issues/7"):
                return {"status_code": 200, "data": {"number": 7,
                    "url": base + "/issues/7", "repository_url": base}}
            if method == "DELETE":
                return {"status_code": 204, "data": None}
            get_count = sum(call[0] == "GET" and call[1] == path for call in calls)
            return ({"status_code": 200, "data": {"id": 9,
                    "issue_url": base + "/issues/7"}} if get_count == 1
                    else {"status_code": 404, "error": "missing"})

        self.gh.api_transport = transport
        self.assertEqual(self.gh.comment_delete(
            self.origin, "11", "issue", 7, 9).state, "deleted")
        self.assertTrue(all(version == github.GITHUB_API_VERSION for _, _, version in calls))

    def test_comment_delete_identity_and_token_fail_before_delete(self):
        for label in ("different provider ID", "invalid token"):
            with self.subTest(label=label):
                self.transport_calls.clear()
                if label == "different provider ID":
                    self.observed = project.ProviderObservation(
                        "12", "7", "owner", "repo", "https://github.com/owner/repo.git", "main")
                else:
                    self.observed = project.ProviderObservation(
                        "11", "7", "owner", "repo", "https://github.com/owner/repo.git", "main")
                    self.gateway.token_reader = lambda _: {"token": "wrong"}
                with self.assertRaises(github.GitHubError):
                    self.gh.comment_delete(self.origin, "11", "issue", 7, 9)
                self.assertEqual(sum(call[0] == "DELETE" for call in self.transport_calls), 0)

    def test_risk_reporter_enforces_utf8_boundary_fixed_target_and_stdin(self):
        calls = []
        token_reader = lambda request: self.token(
            "99", github.ADMIN_OWNER, github.ADMIN_NAME, request["permissions"], "risk-secret")
        reporter = github.RiskReporter("99", token_reader,
            lambda argv, **kwargs: calls.append((argv, kwargs)) or self.runner(argv, **kwargs),
            self.state, provider_observer=self.admin_observer)
        event = github.TrustedRiskEvent(github.RiskSource.SLACK, "W1", "C1", "E1")
        result = reporter.create(github.RiskCategory.CIRCUMVENTION, event, "é" * 500)
        self.assertEqual(result.state, "created")
        self.assertNotIn("stdout", result.process)
        self.assertNotIn("stderr", result.process)
        self.assertNotIn("peirce-admin", repr(result))
        argv, options = calls[0]
        self.assertEqual(options["env"]["GH_REPO"], "peirce-example/peirce-admin")
        self.assertEqual(argv[-2:], ["--body-file", "-"])
        self.assertNotIn("é", argv)
        with self.assertRaises(github.GitHubError):
            reporter.create(github.RiskCategory.CIRCUMVENTION, event, "é" * 501)

    def test_risk_reporter_accepts_only_trusted_current_types(self):
        reporter = github.RiskReporter("99", lambda request: self.token(
            "99", github.ADMIN_OWNER, github.ADMIN_NAME, request["permissions"]), self.runner,
            self.state, provider_observer=self.admin_observer)
        event = github.TrustedRiskEvent(github.RiskSource.SLACK, "W1", "C1", "E1")
        with self.assertRaises(github.GitHubError):
            reporter.create(github.RiskCategory.UNAUTHORIZED_ACCESS, event, "summary",
                            {"owner": "requested", "name": "target", "repository_id": "8"})

    def test_risk_create_uses_fresh_same_id_admin_identity(self):
        fresh = project.ProviderObservation(
            "99", "8", "new-owner", "new-admin",
            "https://github.com/new-owner/new-admin.git", "trunk")
        requests = []
        executions = []

        def token_reader(request):
            requests.append(dict(request))
            return self.token("99", "new-owner", "new-admin", request["permissions"])

        def runner(argv, **kwargs):
            executions.append((argv, kwargs))
            return self.runner(argv, **kwargs)

        reporter = github.RiskReporter(
            "99", token_reader, runner, self.state, provider_observer=lambda _: fresh)
        event = github.TrustedRiskEvent(github.RiskSource.SLACK, "W1", "C1", "E1")
        self.assertEqual(reporter.create(
            github.RiskCategory.CIRCUMVENTION, event, "summary").state, "created")
        self.assertEqual([request["installation_id"] for request in requests], [8])
        self.assertTrue(all(options["env"]["GH_REPO"] == "new-owner/new-admin"
                            for _, options in executions))

    def test_risk_create_process_outcomes(self):
        event = github.TrustedRiskEvent(github.RiskSource.SLACK, "W1", "C1", "E1")
        token_reader = lambda request: self.token(
            "99", github.ADMIN_OWNER, github.ADMIN_NAME, request["permissions"])
        cases = (
            ({"state": "exited", "exit_code": 2, "stdout": "", "stderr": "",
              "uncertain": False}, ("unknown", "create")),
            ({"state": "timed_out", "exit_code": None, "uncertain": True},
             ("unknown", "create")),
            ({"state": "exited", "exit_code": 0, "stdout": "", "stderr": "",
              "stdout_truncated": True}, ("unknown", "create")),
            ({"state": "spawn_failed", "exit_code": None, "stdout": "", "stderr": "",
              "uncertain": False}, ("failed", "no_effect")),
            ({"state": "rejected", "exit_code": None, "stdout": "", "stderr": "",
              "uncertain": False}, ("failed", "no_effect")),
        )
        for raw, expected in cases:
            with self.subTest(raw=raw):
                reporter = github.RiskReporter("99", token_reader,
                    lambda argv, raw=raw, **kwargs: raw, self.state,
                    provider_observer=self.admin_observer)
                result = reporter.create(github.RiskCategory.PERSISTENT_ABUSE, event, "summary")
                self.assertEqual((result.state, result.effect), expected)

    def test_rejected_run_input_has_no_implicit_reporting_or_execution(self):
        token_calls = []
        self.gateway.token_reader = lambda request: token_calls.append(request) or self.fail("token called")
        with mock.patch.object(github.RiskReporter, "create") as report:
            with self.assertRaises(github.GitHubError):
                self.gh.run(self.origin, "11", ["issue", "list", "--repo", "other/repo"])
            report.assert_not_called()
        self.assertFalse(token_calls)
        self.assertFalse(self.process_calls)


if __name__ == "__main__":
    unittest.main()
