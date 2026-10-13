#!/usr/bin/env python3
"""Small worker-node API that installs a temporary default-deny nftables lease.

Run this only on a dedicated PentAGI worker node/network. It is deliberately a
separate process from the Codex API client; the API token grants authority to
change worker egress and must be kept on the worker node.
"""

from __future__ import annotations

import argparse
import fcntl
import hmac
import ipaddress
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


TABLE = "pentagi_codex_scope"
MAX_BODY_BYTES = 128 * 1024


class ScopePolicyError(RuntimeError):
    pass


class ScopeConflict(RuntimeError):
    pass


def normalize_networks(values: list[str], *, allow_empty: bool = True) -> list[ipaddress._BaseNetwork]:
    networks: list[ipaddress._BaseNetwork] = []
    for value in values:
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError as exc:
            raise ScopePolicyError("invalid network in scope enforcer configuration") from exc
        if network.prefixlen == 0:
            raise ScopePolicyError("scope enforcer refuses default routes")
        networks.append(network)
    if not networks and not allow_empty:
        raise ScopePolicyError("worker_subnets must contain at least one dedicated worker subnet")
    return networks


def normalize_addresses(values: list[str]) -> list[ipaddress._BaseAddress]:
    result: list[ipaddress._BaseAddress] = []
    for value in values:
        try:
            address = ipaddress.ip_address(value)
        except ValueError as exc:
            raise ScopePolicyError("invalid DNS server address in scope enforcer configuration") from exc
        result.append(address)
    return result


def _split_by_family(networks: list[ipaddress._BaseNetwork]) -> tuple[list[str], list[str]]:
    v4 = sorted({str(item) for item in networks if item.version == 4})
    v6 = sorted({str(item) for item in networks if item.version == 6})
    return v4, v6


def _set_block(name: str, family: int, values: list[str]) -> str:
    nft_type = "ipv4_addr" if family == 4 else "ipv6_addr"
    if values:
        return f"  set {name} {{ type {nft_type}; flags interval; elements = {{ {', '.join(values)} }} }}"
    return f"  set {name} {{ type {nft_type}; flags interval; }}"


def _render_family_table(
    family_name: str,
    workers: list[ipaddress._BaseNetwork],
    targets: list[ipaddress._BaseNetwork],
    support: list[ipaddress._BaseNetwork],
    controls: list[ipaddress._BaseNetwork],
    dns: list[ipaddress._BaseAddress],
    support_ports: list[int],
    control_ports: list[int],
    table_suffix: str = "",
) -> str:
    version = 4 if any(network.version == 4 for network in workers) else 6
    prefix = "ip" if version == 4 else "ip6"
    worker_key, target_key = f"workers{version}", f"targets{version}"
    support_key, control_key, dns_key = f"support{version}", f"controls{version}", f"dns{version}"
    workers_family = [n for n in workers if n.version == version]
    targets_family = [n for n in targets if n.version == version]
    support_family = [n for n in support if n.version == version]
    controls_family = [n for n in controls if n.version == version]
    dns_family = [f"{a.compressed}/{32 if version == 4 else 128}" for a in dns if a.version == version]
    worker_values, _ = _split_by_family(workers_family)
    target_values, _ = _split_by_family(targets_family)
    support_values, _ = _split_by_family(support_family)
    control_values, _ = _split_by_family(controls_family)

    lines = [f"table {family_name} {TABLE}{table_suffix} {{"]
    lines.extend(
        [
            _set_block(worker_key, version, worker_values),
            _set_block(target_key, version, target_values),
            _set_block(support_key, version, support_values),
            _set_block(control_key, version, control_values),
            _set_block(dns_key, version, sorted(set(dns_family))),
            "  chain forward {",
            "    type filter hook forward priority -150; policy accept;",
            f"    {prefix} saddr @{worker_key} {prefix} daddr @{target_key} accept",
        ]
    )
    if support_values and support_ports:
        ports = ", ".join(str(port) for port in sorted(set(support_ports)))
        lines.append(f"    {prefix} saddr @{worker_key} {prefix} daddr @{support_key} tcp dport {{ {ports} }} accept")
    if control_values and control_ports:
        ports = ", ".join(str(port) for port in sorted(set(control_ports)))
        lines.append(f"    {prefix} saddr @{worker_key} {prefix} daddr @{control_key} tcp dport {{ {ports} }} accept")
    if dns_family:
        lines.append(f"    {prefix} saddr @{worker_key} {prefix} daddr @{dns_key} udp dport 53 accept")
        lines.append(f"    {prefix} saddr @{worker_key} {prefix} daddr @{dns_key} tcp dport 53 accept")
    lines.extend(
        [
            f"    {prefix} saddr @{worker_key} counter drop",
            "  }",
            "}",
        ]
    )
    return "\n".join(lines)


def render_nft_policy(
    worker_subnets: list[ipaddress._BaseNetwork],
    target_networks: list[ipaddress._BaseNetwork],
    support_networks: list[ipaddress._BaseNetwork],
    control_networks: list[ipaddress._BaseNetwork],
    dns_servers: list[ipaddress._BaseAddress],
    support_ports: list[int],
    control_ports: list[int],
) -> str:
    """Build equivalent routed and bridged egress filters for the worker subnet."""
    tables: list[str] = []
    for family_name in ("inet", "bridge"):
        versions = sorted({network.version for network in worker_subnets})
        for version in versions:
            workers = [network for network in worker_subnets if network.version == version]
            targets = [network for network in target_networks if network.version == version]
            support = [network for network in support_networks if network.version == version]
            controls = [network for network in control_networks if network.version == version]
            dns = [address for address in dns_servers if address.version == version]
            suffix = "_v6" if len(versions) == 2 and version == 6 else ""
            tables.append(
                _render_family_table(
                    family_name,
                    workers,
                    targets,
                    support,
                    controls,
                    dns,
                    support_ports,
                    control_ports,
                    suffix,
                )
            )
    return "\n".join(tables) + "\n"


def validate_scope_cidr(value: str) -> ipaddress._BaseNetwork:
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise ScopePolicyError("invalid authorized CIDR") from exc
    if network.prefixlen == 0:
        raise ScopePolicyError("default routes are not allowed in scope")
    return network


def normalize_scope_host(value: str) -> str:
    raw = value.strip().rstrip(".").lower()
    try:
        return ipaddress.ip_address(raw).compressed
    except ValueError:
        pass
    try:
        host = raw.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ScopePolicyError("invalid hostname in scope") from exc
    if not host or len(host) > 253 or "*" in host or "/" in host or "@" in host:
        raise ScopePolicyError("scope requires exact hostnames; wildcards are not accepted")
    labels = host.split(".")
    if any(
        not label
        or len(label) > 63
        or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
        for label in labels
    ):
        raise ScopePolicyError("invalid hostname in scope")
    return host


def _reject_scoped_special_network(network: ipaddress._BaseNetwork) -> None:
    forbidden = (
        ipaddress.ip_network("127.0.0.0/8"),
        ipaddress.ip_network("169.254.0.0/16"),
        ipaddress.ip_network("224.0.0.0/4"),
        ipaddress.ip_network("0.0.0.0/8"),
        ipaddress.ip_network("::1/128"),
        ipaddress.ip_network("fe80::/10"),
        ipaddress.ip_network("ff00::/8"),
        ipaddress.ip_network("::/128"),
    )
    for denied in forbidden:
        if network.version == denied.version and network.overlaps(denied):
            raise ScopePolicyError("scoped assessments cannot include loopback or special-use ranges")


def resolve_allowed_hosts(hosts: list[str]) -> dict[str, list[str]]:
    resolved: dict[str, list[str]] = {}
    for raw_host in sorted(set(hosts)):
        host = normalize_scope_host(raw_host)
        try:
            address = ipaddress.ip_address(host)
            values = [address.compressed]
        except ValueError:
            try:
                rows = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
            except OSError as exc:
                raise ScopePolicyError(f"could not resolve authorized hostname {host}") from exc
            values = sorted({ipaddress.ip_address(row[4][0]).compressed for row in rows})
        if not values:
            raise ScopePolicyError(f"authorized hostname has no addresses: {host}")
        for value in values:
            address = ipaddress.ip_address(value)
            if address.is_loopback or address.is_link_local or address.is_unspecified or address.is_multicast:
                raise ScopePolicyError("scoped assessments cannot target loopback, link-local, or special-use addresses")
        resolved[host] = values
    return resolved


class NftScopeManager:
    def __init__(self, config: dict[str, Any]):
        self.config = config
        self.worker_subnets = normalize_networks(list(config.get("worker_subnets", [])), allow_empty=False)
        self.control_networks = normalize_networks(list(config.get("control_networks", [])))
        self.support_networks = normalize_networks(list(config.get("support_networks", [])))
        self.dns_servers = normalize_addresses(list(config.get("dns_servers", [])))
        self.support_ports = self._ports("support_tcp_ports")
        self.control_ports = self._ports("control_tcp_ports")
        self.nft_binary = str(config.get("nft_binary", "nft"))
        self.state_file = Path(str(config.get("state_file", "/run/pentagi-codex-scope/lease.json")))
        self.lock_file = self.state_file.with_suffix(self.state_file.suffix + ".lock")

    def _ports(self, key: str) -> list[int]:
        ports: list[int] = []
        for value in self.config.get(key, []):
            try:
                port = int(value)
            except (TypeError, ValueError) as exc:
                raise ScopePolicyError(f"invalid {key} entry") from exc
            if not 1 <= port <= 65535:
                raise ScopePolicyError(f"invalid {key} entry")
            ports.append(port)
        return sorted(set(ports))

    def _locked(self):
        manager = self

        class Lock:
            def __enter__(self):
                manager.lock_file.parent.mkdir(parents=True, exist_ok=True)
                self.handle = manager.lock_file.open("a+")
                os.chmod(manager.lock_file, 0o600)
                fcntl.flock(self.handle.fileno(), fcntl.LOCK_EX)
                return self

            def __exit__(self, exc_type, exc, tb):
                fcntl.flock(self.handle.fileno(), fcntl.LOCK_UN)
                self.handle.close()

        return Lock()

    def _read_state(self) -> dict[str, Any] | None:
        try:
            return json.loads(self.state_file.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return None
        except (OSError, json.JSONDecodeError) as exc:
            raise ScopeConflict("scope lease state is unreadable; inspect the worker node before continuing") from exc

    def _write_state(self, state: dict[str, Any]) -> None:
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", dir=self.state_file.parent, delete=False
        ) as stream:
            json.dump(state, stream, sort_keys=True)
            stream.write("\n")
            temp_path = Path(stream.name)
        os.chmod(temp_path, 0o600)
        os.replace(temp_path, self.state_file)

    def _run_nft(self, script: str) -> None:
        try:
            result = subprocess.run(
                [self.nft_binary, "-f", "-"],
                input=script,
                text=True,
                capture_output=True,
                timeout=15,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ScopePolicyError("nftables could not apply the worker egress policy") from exc
        if result.returncode != 0:
            raise ScopePolicyError("nftables rejected the worker egress policy")

    def status(self) -> dict[str, Any]:
        with self._locked():
            state = self._read_state()
        if state is None:
            return {"ok": True, "active": False}
        return {
            "ok": True,
            "active": True,
            "lease_id": state["lease_id"],
            "flow_id": state.get("flow_id"),
            "profile": state.get("profile"),
            "created_at": state.get("created_at"),
            "status": state.get("status"),
        }

    def prepare(self, request: dict[str, Any]) -> dict[str, Any]:
        scope = request.get("scope") or {}
        primary = normalize_scope_host(str(scope.get("primary_host", "")))
        allowed_hosts = [normalize_scope_host(str(item)) for item in scope.get("allowed_hosts", [])]
        allowed_cidrs = [str(item) for item in scope.get("allowed_cidrs", [])]
        if not primary or (primary not in allowed_hosts and not allowed_cidrs):
            raise ScopePolicyError("primary target is not explicitly in scope")
        target_networks = [validate_scope_cidr(item) for item in allowed_cidrs]
        if request.get("mode") == "scoped-assessment":
            for network in target_networks:
                _reject_scoped_special_network(network)
        if primary not in allowed_hosts:
            try:
                primary_address = ipaddress.ip_address(primary)
            except ValueError:
                primary_address = None
            if primary_address is not None:
                if not any(primary_address in network for network in target_networks):
                    raise ScopePolicyError("primary target IP is outside the authorized CIDRs")
            else:
                addresses = resolve_allowed_hosts([primary])[primary]
                if not all(any(ipaddress.ip_address(item) in net for net in target_networks) for item in addresses):
                    raise ScopePolicyError("primary target resolves outside the authorized CIDRs")
        resolved = resolve_allowed_hosts(allowed_hosts)
        target_networks.extend(self._addresses_as_networks(resolved))
        target_networks = self._dedupe_networks(target_networks)
        if not target_networks:
            raise ScopePolicyError("scope contains no enforceable target addresses")

        with self._locked():
            if self._read_state() is not None:
                raise ScopeConflict("another scope lease is active; this worker network supports one scoped flow at a time")
            lease_id = str(uuid.uuid4())
            worker_versions = {network.version for network in self.worker_subnets}
            table_suffixes = ["", "_v6"] if len(worker_versions) == 2 else [""]
            state = {
                "lease_id": lease_id,
                "flow_id": None,
                "profile": str(request.get("profile", "")),
                "created_at": int(time.time()),
                "targets": [str(item) for item in target_networks],
                "table_suffixes": table_suffixes,
                "status": "installing",
            }
            self._write_state(state)
            script = render_nft_policy(
                self.worker_subnets,
                target_networks,
                self.support_networks,
                self.control_networks,
                self.dns_servers,
                self.support_ports,
                self.control_ports,
            )
            try:
                self._run_nft(script)
            except Exception:
                self.state_file.unlink(missing_ok=True)
                raise
            state["status"] = "active"
            self._write_state(state)
        return {
            "ok": True,
            "lease_id": lease_id,
            "default_deny": True,
            "exclusive": True,
            "resolved_hosts": resolved,
        }

    @staticmethod
    def _addresses_as_networks(resolved: dict[str, list[str]]) -> list[ipaddress._BaseNetwork]:
        result: list[ipaddress._BaseNetwork] = []
        for values in resolved.values():
            for value in values:
                address = ipaddress.ip_address(value)
                result.append(ipaddress.ip_network(f"{address}/{32 if address.version == 4 else 128}", strict=False))
        return result

    @staticmethod
    def _dedupe_networks(values: list[ipaddress._BaseNetwork]) -> list[ipaddress._BaseNetwork]:
        result: dict[str, ipaddress._BaseNetwork] = {}
        for item in values:
            result[str(item)] = item
        return [result[key] for key in sorted(result)]

    def bind(self, lease_id: str, flow_id: str) -> dict[str, Any]:
        if not flow_id:
            raise ScopePolicyError("flow id is required")
        with self._locked():
            state = self._read_state()
            if state is None or not hmac.compare_digest(str(state.get("lease_id", "")), lease_id):
                raise ScopeConflict("scope lease does not exist")
            state["flow_id"] = str(flow_id)
            self._write_state(state)
        return {"ok": True, "lease_id": lease_id, "flow_id": str(flow_id)}

    def release(self, lease_id: str, confirm_no_active_flow: bool) -> dict[str, Any]:
        with self._locked():
            state = self._read_state()
            if state is None or not hmac.compare_digest(str(state.get("lease_id", "")), lease_id):
                raise ScopeConflict("scope lease does not exist")
            if state.get("flow_id") and not confirm_no_active_flow:
                raise ScopeConflict("active flow is bound to this lease; verify it is stopped before release")
            statements = []
            for suffix in state.get("table_suffixes", [""]):
                name = TABLE + str(suffix)
                statements.extend([f"delete table inet {name}", f"delete table bridge {name}"])
            self._run_nft("\n".join(statements) + "\n")
            self.state_file.unlink(missing_ok=True)
        return {"ok": True, "lease_id": lease_id, "released": True}


def _read_json_body(handler: BaseHTTPRequestHandler) -> dict[str, Any]:
    try:
        length = int(handler.headers.get("Content-Length", "0"))
    except ValueError as exc:
        raise ScopePolicyError("invalid request length") from exc
    if length < 0 or length > MAX_BODY_BYTES:
        raise ScopePolicyError("request body exceeds the size limit")
    try:
        value = json.loads(handler.rfile.read(length).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ScopePolicyError("request body must be JSON") from exc
    if not isinstance(value, dict):
        raise ScopePolicyError("request body must be a JSON object")
    return value


class ScopeHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, address: tuple[str, int], manager: NftScopeManager, token: str):
        self.manager = manager
        self.token = token
        super().__init__(address, ScopeRequestHandler)


class ScopeRequestHandler(BaseHTTPRequestHandler):
    server: ScopeHTTPServer

    def log_message(self, fmt: str, *args: Any) -> None:
        # Request targets and flow IDs do not belong in routine access logs.
        return

    def _send(self, status: int, payload: dict[str, Any]) -> None:
        data = json.dumps(payload, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _authorized(self) -> bool:
        value = self.headers.get("Authorization", "")
        expected = "Bearer " + self.server.token
        return hmac.compare_digest(value, expected)

    def do_GET(self) -> None:
        if self.path == "/healthz":
            self._send(200, {"ok": True})
            return
        if not self._authorized():
            self._send(401, {"ok": False, "error": "unauthorized"})
            return
        if self.path == "/v1/scopes/status":
            self._send(200, self.server.manager.status())
            return
        self._send(404, {"ok": False, "error": "not_found"})

    def do_POST(self) -> None:
        if not self._authorized():
            self._send(401, {"ok": False, "error": "unauthorized"})
            return
        try:
            payload = _read_json_body(self)
            if self.path == "/v1/scopes/prepare":
                result = self.server.manager.prepare(payload)
            elif self.path == "/v1/scopes/status":
                result = self.server.manager.status()
            else:
                match = re.fullmatch(r"/v1/scopes/([0-9a-fA-F-]{36})/(bind|release)", self.path)
                if not match:
                    self._send(404, {"ok": False, "error": "not_found"})
                    return
                lease_id, action = match.groups()
                if action == "bind":
                    result = self.server.manager.bind(lease_id, str(payload.get("flow_id", "")))
                else:
                    result = self.server.manager.release(
                        lease_id, bool(payload.get("confirm_no_active_flow", False))
                    )
            self._send(200, result)
        except ScopeConflict:
            self._send(409, {"ok": False, "error": "scope_conflict"})
        except ScopePolicyError:
            self._send(400, {"ok": False, "error": "scope_policy_rejected"})
        except Exception:
            self._send(500, {"ok": False, "error": "scope_enforcer_error"})


def serve(config: dict[str, Any], cert_path: str | None, key_path: str | None) -> None:
    token = os.environ.get("PENTAGI_SCOPE_ENFORCER_TOKEN", "")
    if len(token) < 32:
        raise ScopePolicyError("set a random PENTAGI_SCOPE_ENFORCER_TOKEN of at least 32 characters")
    manager = NftScopeManager(config)
    host = str(config.get("listen", "127.0.0.1"))
    port = int(config.get("port", 8765))
    try:
        is_loopback = ipaddress.ip_address(host).is_loopback
    except ValueError as exc:
        raise ScopePolicyError("listen must be a numeric IP address") from exc
    if not is_loopback and not (cert_path and key_path):
        raise ScopePolicyError("non-loopback listener requires TLS certificate and key")
    if bool(cert_path) != bool(key_path):
        raise ScopePolicyError("TLS certificate and key must be configured together")
    server = ScopeHTTPServer((host, port), manager, token)
    if cert_path and key_path:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(certfile=cert_path, keyfile=key_path)
        server.socket = context.wrap_socket(server.socket, server_side=True)
    try:
        server.serve_forever(poll_interval=0.25)
    finally:
        server.server_close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the scoped PentAGI worker egress enforcer.")
    parser.add_argument("--config", required=True, help="worker-node JSON configuration")
    parser.add_argument("--tls-cert")
    parser.add_argument("--tls-key")
    args = parser.parse_args(argv)
    try:
        config = json.loads(Path(args.config).read_text(encoding="utf-8"))
        if not isinstance(config, dict):
            raise ScopePolicyError("configuration must be a JSON object")
        serve(config, args.tls_cert, args.tls_key)
    except (OSError, json.JSONDecodeError, ScopePolicyError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
