from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import nft_scope_enforcer as ne


class NftPolicyTests(unittest.TestCase):
    def test_policy_allows_target_and_drops_other_forwarded_egress(self):
        policy = ne.render_nft_policy(
            [ne.ipaddress.ip_network("172.20.0.0/24")],
            [ne.ipaddress.ip_network("198.51.100.24/32")],
            [ne.ipaddress.ip_network("203.0.113.0/24")],
            [ne.ipaddress.ip_network("172.21.0.2/32")],
            [ne.ipaddress.ip_address("172.20.0.1")],
            [443],
            [2376],
        )
        self.assertIn("ip saddr @workers4 ip daddr @targets4 accept", policy)
        self.assertIn("ip saddr @workers4 counter drop", policy)
        self.assertIn("tcp dport { 443 } accept", policy)
        self.assertIn("tcp dport { 2376 } accept", policy)
        self.assertIn("udp dport 53 accept", policy)
        self.assertIn("table inet pentagi_codex_scope", policy)
        self.assertIn("table bridge pentagi_codex_scope", policy)

    def test_mixed_ipv4_ipv6_uses_distinct_tables_and_drops_both(self):
        policy = ne.render_nft_policy(
            [ne.ipaddress.ip_network("172.20.0.0/24"), ne.ipaddress.ip_network("fd00:20::/64")],
            [ne.ipaddress.ip_network("198.51.100.24/32"), ne.ipaddress.ip_network("2001:db8::8/128")],
            [],
            [],
            [],
            [],
            [],
        )
        self.assertIn("table inet pentagi_codex_scope_v6", policy)
        self.assertIn("ip6 saddr @workers6 ip6 daddr @targets6 accept", policy)
        self.assertIn("ip6 saddr @workers6 counter drop", policy)

    def test_default_route_is_rejected(self):
        with self.assertRaises(ne.ScopePolicyError):
            ne.validate_scope_cidr("0.0.0.0/0")
        with self.assertRaises(ne.ScopePolicyError):
            ne.normalize_networks(["::/0"])


class NftScopeManagerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.config = {
            "worker_subnets": ["172.20.0.0/24"],
            "state_file": str(Path(self.tmp.name) / "lease.json"),
            "nft_binary": "nft",
        }

    def _request(self):
        return {
            "profile": "scoped-assessment",
            "mode": "scoped-assessment",
            "scope": {
                "primary_host": "198.51.100.20",
                "allowed_hosts": ["198.51.100.20"],
                "allowed_cidrs": [],
            },
        }

    def test_prepare_bind_release_state_machine_with_mocked_nft(self):
        manager = ne.NftScopeManager(self.config)
        scripts = []
        manager._run_nft = scripts.append
        prepared = manager.prepare(self._request())
        self.assertTrue(prepared["default_deny"])
        self.assertTrue(prepared["exclusive"])
        self.assertIn("198.51.100.20/32", scripts[0])
        self.assertEqual(manager.status()["status"], "active")
        bound = manager.bind(prepared["lease_id"], "flow-12")
        self.assertEqual(bound["flow_id"], "flow-12")
        with self.assertRaises(ne.ScopeConflict):
            manager.release(prepared["lease_id"], confirm_no_active_flow=False)
        manager.release(prepared["lease_id"], confirm_no_active_flow=True)
        self.assertFalse(manager.status()["active"])
        self.assertIn("delete table inet pentagi_codex_scope", scripts[-1])

    def test_concurrent_lease_is_denied(self):
        manager = ne.NftScopeManager(self.config)
        manager._run_nft = lambda _script: None
        lease = manager.prepare(self._request())
        with self.assertRaises(ne.ScopeConflict):
            manager.prepare(self._request())
        manager.release(lease["lease_id"], confirm_no_active_flow=True)

    def test_cidr_and_dns_special_use_targets_are_rejected(self):
        manager = ne.NftScopeManager(self.config)
        with self.assertRaises(ne.ScopePolicyError):
            manager.prepare(
                {
                    "mode": "scoped-assessment",
                    "scope": {
                        "primary_host": "127.0.0.1",
                        "allowed_hosts": ["127.0.0.1"],
                        "allowed_cidrs": [],
                    },
                }
            )
        with self.assertRaises(ne.ScopePolicyError):
            manager.prepare(
                {
                    "mode": "scoped-assessment",
                    "scope": {
                        "primary_host": "10.0.0.5",
                        "allowed_hosts": [],
                        "allowed_cidrs": ["10.0.0.0/8", "169.254.0.0/16"],
                    },
                }
            )

    def test_failed_nft_install_removes_unused_lease_state(self):
        manager = ne.NftScopeManager(self.config)
        manager._run_nft = lambda _script: (_ for _ in ()).throw(ne.ScopePolicyError("mock nft failure"))
        with self.assertRaises(ne.ScopePolicyError):
            manager.prepare(self._request())
        self.assertFalse(Path(self.config["state_file"]).exists())


if __name__ == "__main__":
    unittest.main()
