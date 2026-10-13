from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pentagi_codex as pc


class FakeResponse:
    def __init__(self, payload: dict):
        self.body = json.dumps(payload).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, _limit: int) -> bytes:
        return self.body


class PentAGIClientTests(unittest.TestCase):
    def test_graphql_uses_documented_endpoint_and_bearer_header(self):
        observed = {}

        def opener(request, timeout):
            observed["url"] = request.full_url
            observed["auth"] = request.get_header("Authorization")
            observed["timeout"] = timeout
            observed["body"] = json.loads(request.data)
            return FakeResponse({"data": {"createFlow": {"id": "17", "title": "test", "status": "created"}}})

        client = pc.PentAGIClient("https://pentagi.example", "test-token", opener=opener)
        flow = client.create_flow("provider-a", "authorized test")
        self.assertEqual(flow["id"], "17")
        self.assertEqual(observed["url"], "https://pentagi.example/api/v1/graphql")
        self.assertEqual(observed["auth"], "Bearer test-token")
        self.assertIn("createFlow(modelProvider: $provider, input: $input)", observed["body"]["query"])
        self.assertEqual(observed["body"]["variables"], {"provider": "provider-a", "input": "authorized test"})

    def test_graphql_errors_are_not_returned_as_unredacted_payloads(self):
        client = pc.PentAGIClient(
            "https://pentagi.example",
            "test-token",
            opener=lambda *_args, **_kwargs: FakeResponse(
                {"errors": [{"message": "password=super-secret failed"}]}
            ),
        )
        with self.assertRaises(pc.PentAGIError) as raised:
            client.providers()
        self.assertNotIn("super-secret", str(raised.exception))

    def test_remote_api_requires_https(self):
        with self.assertRaises(pc.PentAGIError):
            pc.PentAGIClient("http://pentagi.example", "token")
        self.assertEqual(pc.validate_base_url("http://127.0.0.1:8080"), "http://127.0.0.1:8080")


class ScopeTests(unittest.TestCase):
    def test_all_profiles_load_and_gaming_profiles_default_deny(self):
        profiles = pc.list_profiles()
        self.assertGreaterEqual(len(profiles), 9)
        gaming = [item for item in profiles if item["name"].startswith("gaming-")]
        self.assertEqual(len(gaming), 7)
        for item in gaming:
            profile = pc.load_profile(item["name"])
            self.assertEqual(profile["mode"], "scoped-assessment")
            self.assertTrue(profile["requires_scope_enforcer"])
            self.assertEqual(profile["allowed_targets"], [])
            self.assertEqual(profile["allowed_cidrs"], [])

    def test_lab_profile_allows_loopback_and_exact_lab_host(self):
        profile = pc.load_profile("research-lab")
        loopback = pc.make_scope(profile, "http://127.0.0.1:3000", [], enforcer=False)
        self.assertEqual(loopback.primary_host, "127.0.0.1")
        named = pc.make_scope(profile, "http://juice-shop:3000", ["juice-shop"], enforcer=False)
        self.assertEqual(named.allowed_hosts, ("juice-shop",))

    def test_empty_or_mismatched_scope_denies_by_default(self):
        profile = pc.load_profile("scoped-assessment")
        with self.assertRaisesRegex(pc.PolicyError, "default-deny"):
            pc.make_scope(profile, "https://store.example", [], enforcer=True)
        with self.assertRaisesRegex(pc.PolicyError, "not in the allowlist"):
            pc.make_scope(profile, "https://other.example", ["store.example"], enforcer=True)

    def test_scope_requires_exact_hosts_or_cidr_not_wildcards(self):
        profile = pc.load_profile("scoped-assessment")
        with self.assertRaises(pc.PolicyError):
            pc.make_scope(profile, "https://store.example", ["*.example"], enforcer=True)
        scope = pc.make_scope(profile, "https://store.example", ["store.example"], enforcer=True)
        self.assertEqual(scope.allowed_hosts, ("store.example",))

    def test_scoped_profile_rejects_loopback_and_default_routes(self):
        profile = pc.load_profile("scoped-assessment")
        with self.assertRaises(pc.PolicyError):
            pc.make_scope(profile, "http://127.0.0.1", ["127.0.0.1"], enforcer=True)
        with self.assertRaises(pc.PolicyError):
            pc.make_scope(profile, "https://store.example", ["0.0.0.0/0"], enforcer=True)

    def test_approval_is_required_before_any_api_call(self):
        args = SimpleNamespace(approve=False)
        with self.assertRaisesRegex(pc.PolicyError, "approval required"):
            pc.run_flow(args)


class BudgetAndReportTests(unittest.TestCase):
    def setUp(self):
        self.budgets = {
            "max_runtime_seconds": 60,
            "max_total_tokens": 1000,
            "max_cost_usd": 1.0,
            "max_tasks": 4,
            "poll_interval_seconds": 1,
        }
        self.snapshot = {
            "flow": {"id": "9", "title": "flow", "status": "running"},
            "tasks": [],
            "usage": {
                "totalUsageIn": 20,
                "totalUsageOut": 30,
                "totalUsageCacheIn": 2,
                "totalUsageCacheOut": 0,
                "totalUsageCostIn": 0.1,
                "totalUsageCostOut": 0.2,
            },
        }

    def test_budget_checks_runtime_tokens_cost_and_task_count(self):
        self.assertIsNone(pc.budget_exceeded(self.snapshot, 1, self.budgets))
        self.assertEqual(pc.budget_exceeded(self.snapshot, 60, self.budgets), "runtime budget reached")
        token_snapshot = json.loads(json.dumps(self.snapshot))
        token_snapshot["usage"]["totalUsageOut"] = 1000
        self.assertEqual(pc.budget_exceeded(token_snapshot, 1, self.budgets), "token budget reached")
        cost_snapshot = json.loads(json.dumps(self.snapshot))
        cost_snapshot["usage"]["totalUsageCostOut"] = 1.0
        self.assertEqual(pc.budget_exceeded(cost_snapshot, 1, self.budgets), "cost budget reached")
        task_snapshot = json.loads(json.dumps(self.snapshot))
        task_snapshot["tasks"] = [{} for _ in range(4)]
        self.assertEqual(pc.budget_exceeded(task_snapshot, 1, self.budgets), "task budget reached")

    def test_missing_usage_fails_closed(self):
        snapshot = {"flow": {}, "tasks": [], "usage": None}
        self.assertEqual(
            pc.budget_exceeded(snapshot, 1, self.budgets),
            "usage telemetry unavailable; fail-closed budget stop",
        )

    def test_monitor_returns_terminal_flow_using_mocked_snapshot(self):
        class Client:
            def snapshot(self, _flow_id):
                result = json.loads(json.dumps(self_snapshot))
                result["flow"]["status"] = "finished"
                return result

        self_snapshot = self.snapshot
        clock_values = iter([100.0, 101.0, 102.0])
        result = pc.monitor_flow(Client(), "9", self.budgets, clock=lambda: next(clock_values), sleep=lambda _: None)
        self.assertEqual(result["flow"]["status"], "finished")

    def test_lab_run_finishes_worker_containers_after_report(self):
        class Client:
            finished = False

            def providers(self):
                return [{"name": "mock-provider"}]

            def create_flow(self, _provider, _flow_input):
                return {"id": "lab-flow"}

            def snapshot(self, _flow_id):
                return {
                    "flow": {"id": "lab-flow", "title": "lab", "status": "finished"},
                    "tasks": [],
                    "usage": {
                        "totalUsageIn": 0,
                        "totalUsageOut": 0,
                        "totalUsageCacheIn": 0,
                        "totalUsageCacheOut": 0,
                        "totalUsageCostIn": 0.0,
                        "totalUsageCostOut": 0.0,
                    },
                }

            def finish_flow(self, _flow_id):
                self.finished = True

        client = Client()
        args = SimpleNamespace(
            approve=True,
            profile="research-lab",
            scope_enforcer_url=None,
            target="http://localhost:3000",
            allow_target=[],
            budget_runtime=None,
            budget_tokens=None,
            budget_cost=None,
            budget_tasks=None,
            poll_interval=None,
            api_timeout=1,
            model_provider="mock-provider",
            task="test disposable lab",
        )
        with patch.dict("os.environ", {"PENTAGI_SCOPE_ENFORCER_URL": ""}), patch.object(
            pc, "_client_from_env", return_value=client
        ):
            result = pc.run_flow(args)
        self.assertEqual(result["flow"]["status"], "finished")
        self.assertTrue(client.finished)

    def test_report_redacts_secrets_and_marks_findings_unvalidated(self):
        profile = pc.load_profile("research-lab")
        scope = pc.make_scope(profile, "http://127.0.0.1:3000", [], enforcer=False)
        snapshot = json.loads(json.dumps(self.snapshot))
        snapshot["flow"]["status"] = "finished"
        snapshot["tasks"] = [
            {
                "id": "1",
                "title": "Possible authorization issue",
                "status": "finished",
                "result": "Authorization: Bearer abc123 and api_key=super-secret",
                "subtasks": [],
            }
        ]
        report = pc.build_report(snapshot, profile, scope, self.budgets, elapsed_seconds=12)
        rendered = json.dumps(report)
        self.assertNotIn("abc123", rendered)
        self.assertNotIn("super-secret", rendered)
        self.assertEqual(report["validation_status"], "unvalidated")
        self.assertEqual(report["workflow"]["current_stage"], "source_review")

    def test_sanitizer_redacts_private_key_token_email_and_url_credentials(self):
        value = (
            "ghp_abcdefghijklmnopqrstuvwxyz0123456789 and user@example.com "
            "https://alice:secret@example.test/path\n"
            "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----"
        )
        cleaned = pc.sanitize_text(value)
        for secret in ("ghp_abcdefghijklmnopqrstuvwxyz0123456789", "user@example.com", "alice:secret", "abc"):
            self.assertNotIn(secret, cleaned)


class EnforcerClientTests(unittest.TestCase):
    def test_prepare_requires_exclusive_default_deny_attestation(self):
        seen = {}

        def opener(request, timeout):
            seen["url"] = request.full_url
            seen["auth"] = request.get_header("Authorization")
            seen["payload"] = json.loads(request.data)
            return FakeResponse({"ok": True, "lease_id": "lease-1", "default_deny": True, "exclusive": True})

        profile = pc.load_profile("scoped-assessment")
        scope = pc.make_scope(profile, "https://target.example", ["target.example"], enforcer=True)
        client = pc.ScopeEnforcerClient("https://scope.example", "scope-token", opener=opener)
        result = client.prepare(profile, scope, pc.effective_budgets(profile, {}))
        self.assertEqual(result["lease_id"], "lease-1")
        self.assertEqual(seen["url"], "https://scope.example/v1/scopes/prepare")
        self.assertEqual(seen["auth"], "Bearer scope-token")
        self.assertEqual(seen["payload"]["scope"]["primary_host"], "target.example")

    def test_prepare_rejects_nonexclusive_or_non_default_deny_response(self):
        client = pc.ScopeEnforcerClient(
            "http://localhost:8765",
            "scope-token",
            opener=lambda *_args, **_kwargs: FakeResponse(
                {"ok": True, "lease_id": "lease-1", "default_deny": False, "exclusive": True}
            ),
        )
        profile = pc.load_profile("scoped-assessment")
        scope = pc.make_scope(profile, "https://target.example", ["target.example"], enforcer=True)
        with self.assertRaisesRegex(pc.PentAGIError, "default-deny lease"):
            client.prepare(profile, scope, pc.effective_budgets(profile, {}))


if __name__ == "__main__":
    unittest.main()
