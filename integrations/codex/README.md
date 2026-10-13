# PentAGI control from Codex

This integration is a small Python control-plane client over PentAGI's documented GraphQL API. It does not change PentAGI's agent prompts, tool catalogue, Docker sandbox behavior, or attack planning. PentAGI retains its autonomous multi-agent exploitation and tool execution. The client adds explicit target scope, an approval gate, monitored budgets, cancellation, sanitized candidate reports, and (for scoped assessments) a worker-node network egress lease.

## Requirements

- Python 3.11 or newer; the client and tests use only the standard library.
- PentAGI 2.2.0 or newer. Earlier releases are affected by CVE-2026-14784.
- A PentAGI API token created in **Settings → API Tokens** and a configured model provider.
- For `scoped-assessment`, the separate Linux worker-node nftables enforcer described below.
- The Research Lab profile must run inside a disposable authorized lab network.

No credentials are stored in this directory. Supply them through a secret manager or environment variables:

```sh
export PENTAGI_BASE_URL="https://pentagi.example.internal"
export PENTAGI_API_TOKEN="<load this from your secret manager>"
python3 integrations/codex/pentagi_codex.py profiles
python3 integrations/codex/pentagi_codex.py providers
```

For a local PentAGI instance, `http://localhost:8443` is accepted. Remote API URLs must use HTTPS; TLS verification remains enabled.

## Run a disposable Research Lab flow

The lab profile enables PentAGI's full attack techniques and multi-agent autonomy. Its built-in scope includes loopback. Add an exact service hostname or CIDR when the disposable target is reachable through the lab's worker network:

```sh
python3 integrations/codex/pentagi_codex.py run \
  --profile research-lab \
  --target http://juice-shop:3000 \
  --allow-target juice-shop \
  --model-provider "<provider name from providers>" \
  --task "Assess this disposable application; document exploit chains and reproducible evidence." \
  --approve
```

`--approve` is required for every flow. The initial target must match a profile target or an explicit `--allow-target`. The lab profile does not require the additional firewall service, so a basic local lab remains straightforward. Put PentAGI and the target on a disposable network with no path to production assets. The wrapper does not turn the research profile into a safe internet sandbox by itself.

## Run a scoped Gaming Arena assessment

Choose one of the structured profiles listed by `profiles`, then pass the precise approved hostnames/CIDRs. All Gaming Arena profiles default to an empty target set and therefore deny by default. Scoped runs require the network enforcer before the flow is created:

```sh
export PENTAGI_SCOPE_ENFORCER_URL="https://scope-enforcer.example.internal"
export PENTAGI_SCOPE_ENFORCER_TOKEN="<load this from your secret manager>"

python3 integrations/codex/pentagi_codex.py run \
  --profile gaming-storefront \
  --target https://storefront.example.internal \
  --allow-target storefront.example.internal \
  --model-provider "<provider name from providers>" \
  --task "Run the approved storefront assessment and report candidate findings." \
  --approve
```

Profiles are provided for the storefront, backend, admin panel, payment/order flows, game redemption, device licensing, and Windows client. No Gaming Arena hostnames are guessed or embedded. Put the real approved names and CIDRs in the command or an operator-managed profile. The exact scope and effective budgets are included in the submitted task. The egress filter permits all ports and protocols to approved targets; it does not remove or suppress PentAGI techniques.

### Worker-node egress enforcer

`nft_scope_enforcer.py` is a separate small service for the Linux PentAGI worker node. It installs an nftables default-deny rule for a **dedicated worker subnet** before a scoped flow is created. The firewall allows the approved target CIDRs/addresses, configured DNS servers, and the explicitly configured Docker/control or package-mirror endpoints. It covers routed and bridged forwarding. The lease is exclusive, so only one scoped flow may use that worker network at a time. It remains installed after an orchestration crash until an operator verifies the flow is stopped and releases the lease.

1. Create a dedicated Docker network for PentAGI workers. Do not put the PentAGI API, database, or unrelated containers on that subnet. Determine the worker subnet and required DNS/Docker daemon endpoints on the worker node.
2. Copy `scope-enforcer.example.json` to an operator-owned config file. Fill in `worker_subnets`; add the worker DNS server addresses; and add only required Docker daemon or package mirror networks/ports. Empty values intentionally fail closed for an unknown service.
3. Generate a random token of at least 32 characters and load it as `PENTAGI_SCOPE_ENFORCER_TOKEN` through the worker node's secret manager.
4. Run the enforcer on the worker node with nftables installed and `CAP_NET_ADMIN` (normally a small privileged system service):

   ```sh
   python3 integrations/codex/nft_scope_enforcer.py \
     --config /etc/pentagi-codex/scope-enforcer.json \
     --tls-cert /etc/pentagi-codex/tls/server.crt \
     --tls-key /etc/pentagi-codex/tls/server.key
   ```

   The example binds to `127.0.0.1`. For Codex to reach a remote worker, use an authenticated private route or a TLS/mTLS reverse proxy; do not expose the firewall API to the public internet. A non-loopback bind requires TLS certificate and key paths.
5. Verify `GET /healthz`, then run a disposable test flow through the scoped profile. The enforcer resolves exact hostnames from the worker's DNS view and pins the returned addresses for the lease. DNS rebinding to a different address cannot widen the worker's permitted destinations.

The firewall enforces destination IPs, not HTTP `Host` headers or TLS SNI. If an approved hostname shares an IP with other virtual hosts, those services are reachable at the network layer; keep the assessment authorization explicit for shared infrastructure, or use dedicated target addresses where that distinction matters. The agent prompt still carries the exact hostname scope, but it is not a substitute for a layer-7 egress proxy.

The enforcer deliberately supports one active lease. A separate PentAGI worker network/instance is needed for concurrent engagements. If a lease remains after an interrupted or ambiguous API request, inspect `scope-status`, verify that flow is stopped in PentAGI, then release it:

```sh
python3 integrations/codex/pentagi_codex.py scope-status
python3 integrations/codex/pentagi_codex.py scope-release \
  --lease-id "<lease id from scope-status>" --confirm-no-active-flow
```

For tool installation or Docker-in-Docker, populate only the required `support_networks` or `control_networks` and corresponding TCP ports. Prefer preloaded tools and local package mirrors. The target set itself remains unrestricted across ports/protocols, preserving authorized exploit and network-testing techniques.

## Flow operations and reports

- `cancel --flow-id ID` calls PentAGI's `stopFlow` mutation.
- `finish --flow-id ID` calls `finishFlow`, which removes worker containers.
- `report --flow-id ID` fetches the flow, task results, and usage totals, then redacts common credentials, private keys, tokens, and email addresses.
- `run --output reports/flow.json` writes the sanitized report with owner-only file permissions.

The report labels results as unvalidated candidate findings and marks the workflow stage `source_review`. Continue the existing sequence in Codex: review source and PentAGI evidence → validate each vulnerability with an in-scope reproduction → remediate → add and run a regression test. Do not treat a generated hypothesis as confirmed before validation.

The runner stops a flow when runtime, token, cost, task, or usage-telemetry limits are reached. It polls PentAGI usage stats at the profile interval and stops fail-closed if telemetry is unavailable. One model call may be in flight between polls, so set provider-side spending quotas when a hard billing ceiling is required. Ctrl-C requests `stopFlow`; scoped runs then finish the flow before releasing the network lease.

Budgets can be raised per run after reviewing them and passing `--approve`:

```text
--budget-runtime 7200 --budget-tokens 250000 --budget-cost 10 --budget-tasks 100
```

## Optional REA boundary

`rea_adapter.py` defines a dependency-free `REAAdapter` protocol for a future compiled-Windows analysis plugin. An implementation supplies `analyze_windows_binary(artifact: Path, manifest: Mapping)`. It is loaded only when explicitly requested through `load_adapter("module:factory")`; no REA package, service, or license is required for PentAGI flow orchestration. See `REA_ADAPTER.md`.

## Tests

```sh
python3 -m unittest discover -s integrations/codex/tests -v
```

These tests use in-process mock APIs and mocked nftables execution. They do not launch Docker, touch a production target, or install firewall rules.

## Runtime deployment plan

Upstream README lists **2 vCPU and 4 GiB RAM** as its minimum for PentAGI. Treat that as a minimal management-stack floor, not a capacity recommendation for full parallel testing. The worker layer and local model are additional:

- **Management node minimum:** Linux with Docker Compose v2, 2 vCPU, 4 GiB RAM, and at least 30 GiB free disk for a minimal PentAGI/PostgreSQL stack. Add capacity for optional observability or Graphiti services.
- **Worker node minimum for a useful isolated lab:** Linux Docker worker, 4 vCPU, 8 GiB RAM, and 50 GiB free disk. This is a deployment estimate, not an upstream-published minimum; PentAGI's Kali image alone is documented as 6 GiB or larger. Add disk for flow artifacts and tool images.
- **LLM:** Hosted providers need no local accelerator but incur provider costs. A local model needs separate model-specific CPU/GPU memory and storage; size that from the chosen model rather than treating it as part of PentAGI's minimum.
- **Scoped egress enforcement:** nftables-capable Linux worker, a dedicated worker subnet, and a small enforcer process with `CAP_NET_ADMIN`. Its memory/CPU needs are negligible relative to PentAGI, but it is security-critical and should be managed as privileged infrastructure.
- **Optional services:** Graphiti/Neo4j, Langfuse, and observability add their own resources; enable only when needed.

The Codex Cloud workspace is only a client/build environment. No production VPS, paid infrastructure, Docker daemon, or long-running target service was provisioned or modified for this change.
