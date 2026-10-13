#!/usr/bin/env python3
"""Codex-facing PentAGI flow runner. Python standard library only."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable


ROOT = Path(__file__).resolve().parent
PROFILE_DIR = ROOT / "profiles"
MAX_RESPONSE_BYTES = 8 * 1024 * 1024


class PentAGIError(RuntimeError):
    pass


class PolicyError(PentAGIError):
    pass


class BudgetExceeded(PentAGIError):
    def __init__(self, reason: str, snapshot: dict[str, Any] | None = None):
        super().__init__(reason)
        self.reason = reason
        self.snapshot = snapshot


_ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
_PEM_RE = re.compile(
    r"-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----",
    re.IGNORECASE | re.DOTALL,
)
_BEARER_RE = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+")
_AUTH_HEADER_RE = re.compile(r"(?im)(authorization\s*:\s*)[^\r\n]+")
_COOKIE_RE = re.compile(r"(?im)((?:set-)?cookie\s*:\s*)[^\r\n]+")
_SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(password|passwd|token|secret|api[_-]?key|access[_-]?key|client[_-]?secret)"
    r"(\s*[:=]\s*)(?:\"[^\"]*\"|'[^']*'|[^\s,;]+)"
)
_TOKEN_RE = re.compile(
    r"\b(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|"
    r"xox[baprs]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9_-]{20,})\b"
)
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b")
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_URL_AUTH_RE = re.compile(r"(?i)(https?://)[^/@\s]+:[^/@\s]+@")


def sanitize_text(value: Any, limit: int = 6000) -> str:
    """Redact common credentials/PII before findings leave the local API."""
    text = str(value or "")
    text = _ANSI_RE.sub("", text)
    text = _PEM_RE.sub("[REDACTED PRIVATE KEY]", text)
    text = _AUTH_HEADER_RE.sub(r"\1[REDACTED]", text)
    text = _COOKIE_RE.sub(r"\1[REDACTED]", text)
    text = _BEARER_RE.sub("Bearer [REDACTED]", text)
    text = _SECRET_ASSIGNMENT_RE.sub(r"\1\2[REDACTED]", text)
    text = _TOKEN_RE.sub("[REDACTED TOKEN]", text)
    text = _JWT_RE.sub("[REDACTED JWT]", text)
    text = _URL_AUTH_RE.sub(r"\1[REDACTED]@", text)
    text = _EMAIL_RE.sub("[REDACTED EMAIL]", text)
    text = "".join(ch for ch in text if ch in "\n\t" or ord(ch) >= 32)
    if len(text) > limit:
        text = text[:limit].rstrip() + "…[truncated]"
    return text


def normalize_host(value: str) -> str:
    raw = value.strip().rstrip(".").lower()
    if not raw or "*" in raw or "/" in raw or "@" in raw:
        raise PolicyError("scope entries must be exact hostnames or IP ranges; wildcards are not accepted")
    try:
        return ipaddress.ip_address(raw).compressed
    except ValueError:
        pass
    try:
        host = raw.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise PolicyError("invalid internationalized hostname in scope") from exc
    if len(host) > 253:
        raise PolicyError("hostname is too long")
    labels = host.split(".")
    if any(
        not label
        or len(label) > 63
        or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
        for label in labels
    ):
        raise PolicyError("invalid hostname in scope")
    return host


def parse_target_url(target: str) -> tuple[str, str]:
    try:
        parsed = urllib.parse.urlsplit(target.strip())
        port = parsed.port  # forces validation of malformed ports
    except ValueError as exc:
        raise PolicyError("target URL has an invalid port") from exc
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise PolicyError("target must be an absolute http:// or https:// URL")
    if parsed.username is not None or parsed.password is not None:
        raise PolicyError("credentials must not be embedded in target URLs")
    if parsed.fragment:
        raise PolicyError("URL fragments are not valid assessment targets")
    host = normalize_host(parsed.hostname)
    display_host = f"[{host}]" if ":" in host else host
    origin = f"{parsed.scheme.lower()}://{display_host}"
    if port is not None:
        origin += f":{port}"
    return host, origin


def parse_scope_entry(value: str, *, allow_local: bool) -> tuple[str | None, str | None]:
    raw = value.strip()
    if not raw:
        raise PolicyError("empty scope entry")
    if "://" in raw:
        host, _ = parse_target_url(raw)
        if not allow_local:
            _reject_local_host(host)
        return host, None
    try:
        network = ipaddress.ip_network(raw, strict=False)
        if network.prefixlen == 0:
            raise PolicyError("default routes such as 0.0.0.0/0 and ::/0 are not allowed")
        if not allow_local:
            _reject_local_network(network)
        return None, str(network)
    except ValueError:
        host = normalize_host(raw)
        if not allow_local:
            _reject_local_host(host)
        return host, None


def _reject_local_host(host: str) -> None:
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return
    if address.is_loopback or address.is_link_local or address.is_unspecified or address.is_multicast:
        raise PolicyError("loopback, link-local, unspecified, and multicast targets are lab-only")


def _reject_local_network(network: ipaddress._BaseNetwork) -> None:
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
            raise PolicyError("loopback, link-local, unspecified, and multicast ranges are lab-only")


def resolve_host(host: str) -> list[str]:
    try:
        return [ipaddress.ip_address(host).compressed]
    except ValueError:
        pass
    try:
        rows = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise PolicyError(f"could not resolve an allowlisted target hostname: {host}") from exc
    addresses = sorted({ipaddress.ip_address(row[4][0]).compressed for row in rows})
    if not addresses:
        raise PolicyError(f"allowlisted target hostname has no addresses: {host}")
    return addresses


@dataclass(frozen=True)
class Scope:
    primary_target: str
    primary_host: str
    allowed_hosts: tuple[str, ...]
    allowed_cidrs: tuple[str, ...]

    def as_json(self) -> dict[str, Any]:
        return {
            "primary_target": self.primary_target,
            "primary_host": self.primary_host,
            "allowed_hosts": list(self.allowed_hosts),
            "allowed_cidrs": list(self.allowed_cidrs),
        }


def load_profile(name: str) -> dict[str, Any]:
    path = PROFILE_DIR / f"{name}.json"
    if not path.is_file():
        raise PolicyError(f"unknown profile: {name}; run `profiles` to list available profiles")
    try:
        profile = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PolicyError(f"cannot read profile {name}") from exc
    if profile.get("name") != name or profile.get("mode") not in {"research-lab", "scoped-assessment"}:
        raise PolicyError(f"profile {name} has an invalid name or mode")
    if not isinstance(profile.get("budgets"), dict):
        raise PolicyError(f"profile {name} is missing budgets")
    return profile


def list_profiles() -> list[dict[str, str]]:
    profiles: list[dict[str, str]] = []
    for path in sorted(PROFILE_DIR.glob("*.json")):
        profile = json.loads(path.read_text(encoding="utf-8"))
        profiles.append(
            {
                "name": str(profile.get("name", path.stem)),
                "mode": str(profile.get("mode", "")),
                "description": str(profile.get("description", "")),
            }
        )
    return profiles


def make_scope(profile: dict[str, Any], target: str, extra_entries: list[str], *, enforcer: bool) -> Scope:
    primary_host, origin = parse_target_url(target)
    allow_local = profile["mode"] == "research-lab"
    hosts: set[str] = set()
    cidrs: set[str] = set()
    # Profile entries are convenient defaults for the disposable lab. Once a
    # caller supplies explicit entries, use those as the complete run scope so
    # a named target does not silently inherit localhost or a lab CIDR.
    if extra_entries:
        entries = list(extra_entries)
    else:
        entries = list(profile.get("allowed_targets", [])) + list(profile.get("allowed_cidrs", []))
    for entry in entries:
        host, network = parse_scope_entry(str(entry), allow_local=allow_local)
        if host:
            hosts.add(host)
        if network:
            cidrs.add(network)
    if not hosts and not cidrs:
        raise PolicyError("default-deny scope: add an exact --allow-target or an approved CIDR")

    in_scope = primary_host in hosts
    if not in_scope:
        try:
            primary_ip = ipaddress.ip_address(primary_host)
        except ValueError:
            primary_ip = None
        if primary_ip is not None:
            in_scope = any(primary_ip in ipaddress.ip_network(item) for item in cidrs)
        elif cidrs:
            try:
                resolved = resolve_host(primary_host)
            except PolicyError:
                resolved = []
            if resolved:
                in_scope = all(
                    any(ipaddress.ip_address(item) in ipaddress.ip_network(network) for network in cidrs)
                    for item in resolved
                )
    if not in_scope:
        raise PolicyError(f"default-deny scope: {primary_host} is not in the allowlist")

    if enforcer:
        # The worker-node enforcer resolves hostnames in the worker's DNS view and
        # pins the result to IP sets before a flow is created.
        hosts.add(primary_host)
    return Scope(origin, primary_host, tuple(sorted(hosts)), tuple(sorted(cidrs)))


def effective_budgets(profile: dict[str, Any], overrides: dict[str, Any]) -> dict[str, Any]:
    result = dict(profile["budgets"])
    for key, value in overrides.items():
        if value is not None:
            result[key] = value
    for key in ("max_runtime_seconds", "max_total_tokens", "max_cost_usd", "max_tasks", "poll_interval_seconds"):
        if key not in result:
            raise PolicyError(f"profile budget is missing {key}")
        if float(result[key]) <= 0:
            raise PolicyError(f"budget {key} must be greater than zero")
    if int(result["poll_interval_seconds"]) > 60:
        result["poll_interval_seconds"] = 60
    return result


def build_flow_input(
    profile: dict[str, Any], scope: Scope, task: str, budgets: dict[str, Any]
) -> str:
    lines = [
        "Codex-orchestrated authorized security assessment.",
        f"Profile: {profile['name']} ({profile['mode']}).",
        f"Initial target: {scope.primary_target}",
        "Authorized targets are the exact hostnames and CIDR ranges in the scope below.",
        "Do not interact with, scan, exploit, or pivot to an asset outside that scope.",
        "Within scope, use PentAGI's complete autonomous offensive-security capabilities:",
        "multi-agent planning, tool execution, exploitation, attack chaining, and adversarial testing are enabled.",
        "No attack technique is disabled by this integration; only authorization scope and run budgets apply.",
        "Collect the minimum evidence needed, redact secrets and personal data, and report unvalidated findings as candidates.",
        "Authorized hostnames: " + (", ".join(scope.allowed_hosts) or "(none)"),
        "Authorized CIDRs: " + (", ".join(scope.allowed_cidrs) or "(none)"),
        "Run budgets: "
        + json.dumps(
            {
                "runtime_seconds": budgets["max_runtime_seconds"],
                "total_tokens": budgets["max_total_tokens"],
                "cost_usd": budgets["max_cost_usd"],
                "tasks": budgets["max_tasks"],
            },
            sort_keys=True,
        ),
    ]
    objectives = profile.get("objectives", [])
    if objectives:
        lines.append("Profile objectives:")
        lines.extend(f"- {item}" for item in objectives)
    constraints = profile.get("operational_constraints", [])
    if constraints:
        lines.append("Operational constraints:")
        lines.extend(f"- {item}" for item in constraints)
    lines.extend(["", "User task:", task.strip()])
    return "\n".join(lines)


def validate_base_url(value: str) -> str:
    try:
        parsed = urllib.parse.urlsplit(value.strip())
        _ = parsed.port
    except ValueError as exc:
        raise PentAGIError("PENTAGI_BASE_URL is malformed") from exc
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise PentAGIError("PENTAGI_BASE_URL must be an absolute http(s) URL")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise PentAGIError("PENTAGI_BASE_URL must not contain credentials, query, or fragment")
    host = normalize_host(parsed.hostname)
    if parsed.scheme != "https":
        try:
            local = ipaddress.ip_address(host).is_loopback
        except ValueError:
            local = host == "localhost"
        if not local:
            raise PentAGIError("remote PentAGI API URLs must use HTTPS")
    return value.rstrip("/")


class PentAGIClient:
    def __init__(
        self,
        base_url: str,
        token: str,
        timeout: float = 30,
        opener: Callable[..., Any] = urllib.request.urlopen,
    ):
        self.base_url = validate_base_url(base_url)
        if not token.strip():
            raise PentAGIError("PENTAGI_API_TOKEN is required")
        self.token = token.strip()
        self.timeout = timeout
        self.opener = opener
        self.endpoint = self.base_url + "/api/v1/graphql"

    def _graphql(self, query: str, variables: dict[str, Any] | None = None) -> dict[str, Any]:
        body = json.dumps({"query": query, "variables": variables or {}}).encode("utf-8")
        request = urllib.request.Request(
            self.endpoint,
            data=body,
            headers={
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            method="POST",
        )
        try:
            with self.opener(request, timeout=self.timeout) as response:
                raw = response.read(MAX_RESPONSE_BYTES + 1)
        except urllib.error.HTTPError as exc:
            raise PentAGIError(f"PentAGI GraphQL returned HTTP {exc.code}") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise PentAGIError("PentAGI API request failed") from exc
        if len(raw) > MAX_RESPONSE_BYTES:
            raise PentAGIError("PentAGI API response exceeded the size limit")
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PentAGIError("PentAGI API returned invalid JSON") from exc
        errors = payload.get("errors")
        if errors:
            message = "; ".join(sanitize_text(item.get("message", "GraphQL error"), 300) for item in errors)
            raise PentAGIError("PentAGI GraphQL error: " + message)
        data = payload.get("data")
        if not isinstance(data, dict):
            raise PentAGIError("PentAGI GraphQL response did not include data")
        return data

    def providers(self) -> list[dict[str, str]]:
        data = self._graphql("query CodexProviders { providers { name type } }")
        return list(data.get("providers") or [])

    def create_flow(self, provider: str, flow_input: str) -> dict[str, Any]:
        query = """
        mutation CodexCreateFlow($provider: String!, $input: String!) {
          createFlow(modelProvider: $provider, input: $input) { id title status }
        }
        """
        data = self._graphql(query, {"provider": provider, "input": flow_input})
        flow = data.get("createFlow")
        if not isinstance(flow, dict) or not flow.get("id"):
            raise PentAGIError("PentAGI did not return the created flow id")
        return flow

    def snapshot(self, flow_id: str) -> dict[str, Any]:
        query = """
        query CodexFlowSnapshot($flowId: ID!) {
          flow(flowId: $flowId) { id title status }
          tasks(flowId: $flowId) {
            id title status result
            subtasks { id title status description result }
          }
          usageStatsByFlow(flowId: $flowId) {
            totalUsageIn totalUsageOut totalUsageCacheIn totalUsageCacheOut
            totalUsageCostIn totalUsageCostOut
          }
        }
        """
        data = self._graphql(query, {"flowId": str(flow_id)})
        if not isinstance(data.get("flow"), dict) or data.get("usageStatsByFlow") is None:
            raise PentAGIError("PentAGI did not return flow and usage budget data")
        return {
            "flow": data["flow"],
            "tasks": list(data.get("tasks") or []),
            "usage": data["usageStatsByFlow"],
        }

    def stop_flow(self, flow_id: str) -> None:
        data = self._graphql(
            "mutation CodexStopFlow($flowId: ID!) { stopFlow(flowId: $flowId) { success error } }",
            {"flowId": str(flow_id)},
        )
        result = data.get("stopFlow")
        if isinstance(result, dict) and result.get("success") is False:
            raise PentAGIError("PentAGI refused to stop the flow")

    def finish_flow(self, flow_id: str) -> None:
        data = self._graphql(
            "mutation CodexFinishFlow($flowId: ID!) { finishFlow(flowId: $flowId) { success error } }",
            {"flowId": str(flow_id)},
        )
        result = data.get("finishFlow")
        if isinstance(result, dict) and result.get("success") is False:
            raise PentAGIError("PentAGI refused to finish the flow")


class ScopeEnforcerClient:
    """Remote worker-node firewall API; policy is installed before flow creation."""

    def __init__(
        self,
        base_url: str,
        token: str,
        timeout: float = 15,
        opener: Callable[..., Any] = urllib.request.urlopen,
    ):
        self.base_url = base_url.rstrip("/")
        self.token = token.strip()
        self.timeout = timeout
        self.opener = opener
        if not self.token:
            raise PentAGIError("PENTAGI_SCOPE_ENFORCER_TOKEN is required")
        parsed = urllib.parse.urlsplit(self.base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise PentAGIError("scope enforcer URL must be an absolute http(s) URL")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise PentAGIError("scope enforcer URL must not contain credentials, query, or fragment")
        if parsed.scheme != "https":
            host = normalize_host(parsed.hostname)
            try:
                local = ipaddress.ip_address(host).is_loopback
            except ValueError:
                local = host == "localhost"
            if not local:
                raise PentAGIError("remote scope enforcers must use HTTPS")

    def _request(self, method: str, path: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        data = None if payload is None else json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            self.base_url + path,
            data=data,
            headers={
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            method=method,
        )
        try:
            with self.opener(request, timeout=self.timeout) as response:
                raw = response.read(1024 * 1024 + 1)
        except urllib.error.HTTPError as exc:
            raise PentAGIError(f"scope enforcer returned HTTP {exc.code}") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise PentAGIError("scope enforcer request failed") from exc
        if len(raw) > 1024 * 1024:
            raise PentAGIError("scope enforcer response exceeded the size limit")
        try:
            result = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PentAGIError("scope enforcer returned invalid JSON") from exc
        if not isinstance(result, dict) or result.get("ok") is False:
            raise PentAGIError("scope enforcer rejected the request")
        return result

    def prepare(self, profile: dict[str, Any], scope: Scope, budgets: dict[str, Any]) -> dict[str, Any]:
        result = self._request(
            "POST",
            "/v1/scopes/prepare",
            {
                "profile": profile["name"],
                "mode": profile["mode"],
                "scope": scope.as_json(),
                "max_runtime_seconds": int(budgets["max_runtime_seconds"]),
            },
        )
        if not result.get("lease_id") or result.get("default_deny") is not True or result.get("exclusive") is not True:
            lease_id = result.get("lease_id")
            if lease_id:
                try:
                    self.release(str(lease_id), confirm_no_active_flow=True)
                except PentAGIError:
                    raise PentAGIError(
                        "scope enforcer failed its default-deny attestation; inspect scope-status before continuing"
                    )
            raise PentAGIError("scope enforcer did not attest an exclusive default-deny lease")
        return result

    def bind(self, lease_id: str, flow_id: str) -> None:
        self._request("POST", f"/v1/scopes/{urllib.parse.quote(lease_id, safe='')}/bind", {"flow_id": str(flow_id)})

    def release(self, lease_id: str, *, confirm_no_active_flow: bool) -> None:
        self._request(
            "POST",
            f"/v1/scopes/{urllib.parse.quote(lease_id, safe='')}/release",
            {"confirm_no_active_flow": confirm_no_active_flow},
        )

    def status(self) -> dict[str, Any]:
        return self._request("GET", "/v1/scopes/status")


def token_total(usage: dict[str, Any]) -> int:
    return int(usage.get("totalUsageIn", 0)) + int(usage.get("totalUsageOut", 0))


def cost_total(usage: dict[str, Any]) -> float:
    return float(usage.get("totalUsageCostIn", 0.0)) + float(usage.get("totalUsageCostOut", 0.0))


def budget_exceeded(snapshot: dict[str, Any], elapsed_seconds: float, budgets: dict[str, Any]) -> str | None:
    if elapsed_seconds >= float(budgets["max_runtime_seconds"]):
        return "runtime budget reached"
    usage = snapshot.get("usage")
    if not isinstance(usage, dict):
        return "usage telemetry unavailable; fail-closed budget stop"
    if token_total(usage) >= int(budgets["max_total_tokens"]):
        return "token budget reached"
    if cost_total(usage) >= float(budgets["max_cost_usd"]):
        return "cost budget reached"
    if len(snapshot.get("tasks") or []) >= int(budgets["max_tasks"]):
        return "task budget reached"
    return None


def monitor_flow(
    client: PentAGIClient,
    flow_id: str,
    budgets: dict[str, Any],
    *,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    started = clock()
    while True:
        elapsed = clock() - started
        if elapsed >= float(budgets["max_runtime_seconds"]):
            raise BudgetExceeded("runtime budget reached")
        snapshot = client.snapshot(flow_id)
        elapsed = clock() - started
        if elapsed >= float(budgets["max_runtime_seconds"]):
            raise BudgetExceeded("runtime budget reached", snapshot)
        reason = budget_exceeded(snapshot, elapsed, budgets)
        if reason:
            raise BudgetExceeded(reason, snapshot)
        status = str(snapshot["flow"].get("status", "")).lower()
        if status in {"finished", "failed"}:
            return snapshot
        sleep(float(budgets["poll_interval_seconds"]))


def build_report(
    snapshot: dict[str, Any],
    profile: dict[str, Any],
    scope: Scope,
    budgets: dict[str, Any],
    *,
    elapsed_seconds: float,
    stop_reason: str | None = None,
) -> dict[str, Any]:
    flow = snapshot.get("flow", {})
    tasks = []
    for task in snapshot.get("tasks", []):
        subtasks = []
        for subtask in task.get("subtasks") or []:
            subtasks.append(
                {
                    "id": str(subtask.get("id", "")),
                    "title": sanitize_text(subtask.get("title", ""), 300),
                    "status": str(subtask.get("status", "")),
                    "summary": sanitize_text(subtask.get("result") or subtask.get("description", "")),
                }
            )
        tasks.append(
            {
                "id": str(task.get("id", "")),
                "title": sanitize_text(task.get("title", ""), 300),
                "status": str(task.get("status", "")),
                "candidate_summary": sanitize_text(task.get("result", "")),
                "subtasks": subtasks,
            }
        )
    usage = snapshot.get("usage", {})
    return {
        "schema_version": 1,
        "flow": {
            "id": str(flow.get("id", "")),
            "title": sanitize_text(flow.get("title", ""), 300),
            "status": str(flow.get("status", "")),
        },
        "profile": profile["name"],
        "target": scope.primary_target,
        "authorized_hosts": list(scope.allowed_hosts),
        "authorized_cidrs": list(scope.allowed_cidrs),
        "elapsed_seconds": round(elapsed_seconds, 2),
        "stop_reason": stop_reason,
        "budget": {
            "max_runtime_seconds": int(budgets["max_runtime_seconds"]),
            "max_total_tokens": int(budgets["max_total_tokens"]),
            "max_cost_usd": float(budgets["max_cost_usd"]),
            "max_tasks": int(budgets["max_tasks"]),
        },
        "usage": {
            "input_tokens": int(usage.get("totalUsageIn", 0)),
            "output_tokens": int(usage.get("totalUsageOut", 0)),
            "cached_input_tokens": int(usage.get("totalUsageCacheIn", 0)),
            "cached_output_tokens": int(usage.get("totalUsageCacheOut", 0)),
            "input_cost_usd": float(usage.get("totalUsageCostIn", 0.0)),
            "output_cost_usd": float(usage.get("totalUsageCostOut", 0.0)),
        },
        "candidate_findings": tasks,
        "validation_status": "unvalidated",
        "workflow": {
            "current_stage": "source_review",
            "next_stage": "vulnerability_validation",
            "required_sequence": [
                "source_review",
                "vulnerability_validation",
                "remediation",
                "regression_test",
            ],
            "note": "PentAGI output is candidate evidence; validate each finding in scope before remediation, then add and run a regression test.",
        },
    }


def write_json_output(payload: dict[str, Any], output: str | None) -> None:
    rendered = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    if output:
        path = Path(output)
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(rendered)
        print(f"Report written to {path}")
    else:
        print(rendered, end="")


def _client_from_env(timeout: float = 30) -> PentAGIClient:
    base_url = os.environ.get("PENTAGI_BASE_URL", "")
    token = os.environ.get("PENTAGI_API_TOKEN", "")
    if not base_url:
        raise PentAGIError("PENTAGI_BASE_URL is required")
    return PentAGIClient(base_url, token, timeout=timeout)


def _enforcer_from_env(url_override: str | None = None) -> ScopeEnforcerClient:
    url = url_override or os.environ.get("PENTAGI_SCOPE_ENFORCER_URL", "")
    token = os.environ.get("PENTAGI_SCOPE_ENFORCER_TOKEN", "")
    if not url:
        raise PentAGIError("scoped-assessment requires PENTAGI_SCOPE_ENFORCER_URL")
    return ScopeEnforcerClient(url, token)


def run_flow(args: argparse.Namespace) -> dict[str, Any]:
    if not args.approve:
        raise PolicyError("execution approval required: pass --approve after reviewing profile, target, and budget")
    profile = load_profile(args.profile)
    requires_enforcer = bool(profile.get("requires_scope_enforcer"))
    enforcer_url = args.scope_enforcer_url or os.environ.get("PENTAGI_SCOPE_ENFORCER_URL")
    if requires_enforcer and not enforcer_url:
        raise PolicyError("scoped-assessment requires the worker-node default-deny scope enforcer")
    scope = make_scope(profile, args.target, args.allow_target or [], enforcer=bool(enforcer_url))
    budgets = effective_budgets(
        profile,
        {
            "max_runtime_seconds": args.budget_runtime,
            "max_total_tokens": args.budget_tokens,
            "max_cost_usd": args.budget_cost,
            "max_tasks": args.budget_tasks,
            "poll_interval_seconds": args.poll_interval,
        },
    )
    client = _client_from_env(args.api_timeout)
    provider_names = {str(item.get("name")) for item in client.providers()}
    if args.model_provider not in provider_names:
        raise PolicyError("model provider is not configured in PentAGI; run `providers` and use an exact provider name")
    enforcer = _enforcer_from_env(args.scope_enforcer_url) if enforcer_url else None
    lease: dict[str, Any] | None = None
    flow_id: str | None = None
    creation_started = False
    started = time.monotonic()

    if enforcer:
        lease = enforcer.prepare(profile, scope, budgets)
    try:
        creation_started = True
        flow = client.create_flow(args.model_provider, build_flow_input(profile, scope, args.task, budgets))
        flow_id = str(flow["id"])
        if lease:
            enforcer.bind(str(lease["lease_id"]), flow_id)
        stop_reason = None
        try:
            snapshot = monitor_flow(client, flow_id, budgets)
        except BudgetExceeded as exc:
            stop_reason = exc.reason
            client.stop_flow(flow_id)
            snapshot = client.snapshot(flow_id)
        report = build_report(
            snapshot,
            profile,
            scope,
            budgets,
            elapsed_seconds=time.monotonic() - started,
            stop_reason=stop_reason,
        )
        # finishFlow removes the worker containers for both lab and scoped runs.
        # On scoped runs, do this before releasing the egress lease.
        client.finish_flow(flow_id)
        if lease:
            enforcer.release(str(lease["lease_id"]), confirm_no_active_flow=True)
            lease = None
        return report
    except KeyboardInterrupt:
        if flow_id:
            try:
                client.stop_flow(flow_id)
                client.finish_flow(flow_id)
                if lease:
                    enforcer.release(str(lease["lease_id"]), confirm_no_active_flow=True)
                    lease = None
            except Exception as exc:
                print("Cancellation cleanup failed; verify PentAGI worker state before reuse.", file=sys.stderr)
                print(sanitize_text(exc, 300), file=sys.stderr)
        elif lease and creation_started:
            print(
                f"Flow creation may have reached PentAGI; scope lease {lease['lease_id']} remains active. "
                "Check PentAGI before releasing it.",
                file=sys.stderr,
            )
        elif creation_started:
            print("Flow creation may have reached PentAGI; check its flow list before retrying.", file=sys.stderr)
        elif lease:
            try:
                enforcer.release(str(lease["lease_id"]), confirm_no_active_flow=True)
            except Exception:
                print("Could not release the unused scope lease; the worker network remains restricted.", file=sys.stderr)
        raise
    except Exception:
        if flow_id:
            try:
                client.stop_flow(flow_id)
                client.finish_flow(flow_id)
                if lease:
                    enforcer.release(str(lease["lease_id"]), confirm_no_active_flow=True)
                    lease = None
            except Exception as cleanup_error:
                print("Flow cleanup failed; verify PentAGI worker state before reuse.", file=sys.stderr)
                print(sanitize_text(cleanup_error, 300), file=sys.stderr)
        elif lease and creation_started:
            print(
                f"Flow creation outcome is uncertain; scope lease {lease['lease_id']} remains active. "
                "Use `scope-status`, verify the flow is stopped, then use `scope-release`.",
                file=sys.stderr,
            )
        elif creation_started:
            print("Flow creation outcome is uncertain; check PentAGI before retrying.", file=sys.stderr)
        elif lease:
            try:
                enforcer.release(str(lease["lease_id"]), confirm_no_active_flow=True)
            except Exception:
                print("Could not release the unused scope lease; the worker network remains restricted.", file=sys.stderr)
        raise


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run and control authorized PentAGI flows from Codex.")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("profiles", help="list built-in profiles")
    sub.add_parser("providers", help="list PentAGI model provider names")

    run = sub.add_parser("run", help="start, monitor, budget, and report a PentAGI flow")
    run.add_argument("--profile", required=True)
    run.add_argument("--target", required=True, help="initial target URL reachable from the PentAGI worker network")
    run.add_argument("--allow-target", action="append", default=[], help="additional exact host, URL, or CIDR; repeat as needed")
    run.add_argument("--task", required=True)
    run.add_argument("--model-provider", required=True, help="exact provider name shown by `providers`")
    run.add_argument("--approve", action="store_true", required=True, help="approve this profile, scope, and budget")
    run.add_argument("--scope-enforcer-url", help="worker-node scope enforcer; defaults to PENTAGI_SCOPE_ENFORCER_URL")
    run.add_argument("--poll-interval", type=int)
    run.add_argument("--budget-runtime", type=int)
    run.add_argument("--budget-tokens", type=int)
    run.add_argument("--budget-cost", type=float)
    run.add_argument("--budget-tasks", type=int)
    run.add_argument("--api-timeout", type=float, default=30)
    run.add_argument("--output", help="write sanitized report JSON with owner-only permissions")

    report = sub.add_parser("report", help="fetch and print a sanitized flow report")
    report.add_argument("--flow-id", required=True)
    report.add_argument("--profile", default="research-lab")
    report.add_argument("--target", help="optional target origin to include in the report")
    report.add_argument("--output")

    cancel = sub.add_parser("cancel", help="stop a running flow")
    cancel.add_argument("--flow-id", required=True)
    finish = sub.add_parser("finish", help="finish a flow and remove its worker containers")
    finish.add_argument("--flow-id", required=True)

    sub.add_parser("scope-status", help="inspect the worker-node firewall lease")
    release = sub.add_parser("scope-release", help="release a scope lease after confirming no flow is active")
    release.add_argument("--lease-id", required=True)
    release.add_argument("--confirm-no-active-flow", action="store_true", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "profiles":
            print(json.dumps(list_profiles(), indent=2))
            return 0
        if args.command == "providers":
            print(json.dumps(_client_from_env().providers(), indent=2, sort_keys=True))
            return 0
        if args.command == "run":
            report = run_flow(args)
            write_json_output(report, args.output)
            return 0
        if args.command == "report":
            profile = load_profile(args.profile)
            if args.target:
                target_host, origin = parse_target_url(args.target)
                scope = Scope(origin, target_host, (), ())
            else:
                scope = Scope("not recorded", "", (), ())
            budgets = effective_budgets(profile, {})
            snapshot = _client_from_env().snapshot(args.flow_id)
            write_json_output(
                build_report(snapshot, profile, scope, budgets, elapsed_seconds=0), args.output
            )
            return 0
        if args.command == "cancel":
            _client_from_env().stop_flow(args.flow_id)
            print(json.dumps({"flow_id": args.flow_id, "status": "stop_requested"}))
            return 0
        if args.command == "finish":
            _client_from_env().finish_flow(args.flow_id)
            print(json.dumps({"flow_id": args.flow_id, "status": "finished"}))
            return 0
        if args.command == "scope-status":
            print(json.dumps(_enforcer_from_env().status(), indent=2, sort_keys=True))
            return 0
        if args.command == "scope-release":
            _enforcer_from_env().release(args.lease_id, confirm_no_active_flow=args.confirm_no_active_flow)
            print(json.dumps({"lease_id": args.lease_id, "released": True}))
            return 0
    except KeyboardInterrupt:
        print("Flow cancelled by operator.", file=sys.stderr)
        return 130
    except (PentAGIError, OSError, ValueError) as exc:
        print(sanitize_text(exc, 500), file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
