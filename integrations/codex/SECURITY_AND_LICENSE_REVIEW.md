# PentAGI fork review for the Codex integration

Review date: 2026-10-13. Source reviewed: `rhmedseddiq/pentagi` commit `843dfeb4bfc809c09d1bc5022e567c602d8fc9dd`, the fork's current `main` at branch creation. The same commit is upstream `vxcontrol/pentagi` `main`. The latest GitHub release observed was v2.2.0, published 2026-10-05.

## Architecture and API

PentAGI is a self-hosted Go backend and React/TypeScript frontend. The backend coordinates flows, tasks, subtasks, specialized agents, tools, and persistent memory. PostgreSQL with pgvector stores flow and vector data; Graphiti/Neo4j and Langfuse/observability are optional. Tool execution runs in Docker worker sandboxes. The README documents 20+ pentest tools, multi-agent autonomous planning, external/local LLM providers, and REST plus GraphQL APIs.

The smallest compatible Codex extension is a separate API client rather than a backend fork of flow execution. PentAGI documents Bearer API tokens and `POST /api/v1/graphql`; its schema exposes `createFlow`, `flow`, `tasks`, `usageStatsByFlow`, `stopFlow`, and `finishFlow`. REST endpoints are described in `backend/pkg/server/docs/swagger.yaml`, including `GET/POST /api/v1/flows/` and flow-specific task/log routes. The new client uses the GraphQL contract and leaves upstream agent/tool behavior unchanged.

The existing worker-node guide (`examples/guides/worker_node.md`) is the natural security extension point for sandbox containment. The public API does not accept a per-flow egress ACL, so the scoped profile uses a separate worker-node nftables service to install an exclusive deny-by-default network lease before flow creation. The ordinary research-lab profile does not require that service.

## CVE-2026-14784

The CVE Project record published 2026-07-06 lists PentAGI 2.0 and 2.1.0 as affected and describes a Docker API sandbox issue. That record still says its fix pull request "awaits acceptance," which is stale: upstream PR [#355](https://github.com/vxcontrol/pentagi/pull/355), `fix(sandbox): harden sandbox containers against privilege escalation`, is closed and merged as `aaa1726691115a3086916f17a43e773d16f42f70` on 2026-07-29. The [v2.2.0 release notes](https://github.com/vxcontrol/pentagi/releases/tag/v2.2.0) state that the historical issue affected releases through 2.1.0 and was fixed in 2.2.0.

Source-level protections verified in the selected revision:

- `.env.example` and `backend/pkg/config/config.go` default `DOCKER_INSIDE=false`.
- `backend/pkg/docker/worker_spec.go` drops all Linux capabilities, adds back an explicit pentest-compatible allowlist, withholds `MKNOD`, and adds `SYS_PTRACE` for debugging; `NET_ADMIN` is opt-in.
- The worker container gets a default PID limit of 2048.
- Nested Docker requires an explicit `DOCKER_INSIDE_HOST` separate daemon. The worker-node bundle includes a fail-closed OPA Docker authorization policy, seccomp profile, cleanup timer, and policy tests.
- With `DOCKER_INSIDE_POLICY_TESTS=true`, the startup probe tests 27 denied escape operations and 7 allowed operations. The setting defaults to false, so deployment must enable it to get this startup attestation.
- The docs warn that `DOCKER_SOCKET`/legacy socket mode can expose the host daemon and is not covered by the separate-daemon identity check. Do not set `DOCKER_SOCKET` for isolated deployments; use a separate TLS-protected sandbox daemon.

This was a source review, not a live escape exercise. Docker is present as a CLI binary in the Codex workspace, but no daemon or PentAGI stack was attached; no container probes were run. The selected source has the fix, but an operator still needs to configure and verify a separate sandbox daemon and enable the startup policy tests.

## License findings

The top-level PentAGI `LICENSE` is MIT. The current README says the VXControl Cloud SDK is MIT licensed. `backend/go.mod` pins `github.com/vxcontrol/cloud v1.0.1`, and the SDK's v1.0.1 `LICENSE` is MIT. The Cloud SDK README at that tag also identifies its code as MIT and separates code licensing from access to paid/registered VXControl Cloud services.

However, PentAGI's root `NOTICE` still says the VXControl Cloud SDK is AGPL-3.0 with a special exception for the official PentAGI project. Those statements conflict. The `EULA.md` also calls the source MIT and says MIT prevails for source-code conflicts, while elsewhere describing the grant as revocable/non-transferable and restricting sublicensing, sale, leasing, and distribution. Those additional terms should be reconciled with the MIT grant.

This review cannot determine whether the NOTICE is obsolete or whether a special exception is needed for an earlier SDK revision. Keep the legal files unchanged until the SDK maintainers or counsel confirm the intended licensing and whether the exception covers this fork and redistribution. The new integration is Python standard-library code and does not import the Cloud SDK.

## Security design and limitations

- Target matching is exact-host/CIDR based, rejects wildcard scope, and denies an empty allowlist. All `gaming-*` profiles start empty.
- Scoped runs require an exclusive default-deny nftables lease on a dedicated worker subnet before calling `createFlow`. Target addresses are resolved from the worker's DNS view and pinned; all ports and protocols remain open to explicitly allowed targets so PentAGI's offensive techniques are preserved.
- nftables enforces destination IPs, not HTTP `Host` headers or TLS SNI. A hostname hosted on a shared IP may expose other virtual hosts at the network layer; ensure authorization covers that shared infrastructure or use dedicated target addresses when host-level isolation is required. A layer-7 proxy would add protocol restrictions and is not part of this integration.
- DNS, Docker daemon, and support/package mirror egress are separately configured on the worker node. They must be limited to the minimum service endpoints needed.
- The flow runner polls PentAGI token/cost usage, wall time, and task count; it calls `stopFlow` on budget exhaustion or Ctrl-C. It fails closed if usage telemetry is unavailable. A provider call in flight between polls can exceed a configured cost threshold; provider-side quotas are still needed for a hard billing ceiling.
- Reports omit raw tool logs and sanitize task/subtask result text for common credentials, private keys, tokens, and email addresses. Sanitization is best-effort; review reports before sharing.
- The research-lab profile deliberately avoids requiring the firewall service for a simple local lab. Its containment depends on the disposable isolated network selected by the operator. It is not a safe profile for an internet-connected worker.

## Deployment sizing

Upstream README states a 2 vCPU / 4 GiB RAM minimum for PentAGI. A practical minimum plan is a 2 vCPU / 4 GiB management node with at least 30 GiB free disk, plus a separate 4 vCPU / 8 GiB worker with at least 50 GiB free disk for the Kali image, tools, and flow artifacts. The worker sizing and disk figures are deployment estimates, not upstream-published minimums; the README notes the Kali image is at least 6 GiB. Local LLM compute is separate and model-specific. Optional Neo4j/Graphiti and Langfuse require additional resources.
