# Implementation brief: full CLI-to-MCP workflow parity

Implement **full workflow and argument parity for every FormalSpecGen CLI command through MCP, under enforced permissions**. Use `91c6790` as the documented baseline, but regenerate inventory from the actual checkout and every approved installed command plugin. Do not stop at tool registration or the current two-tool catalogue. Do not switch off strict enforcement to achieve availability.

## Mandatory scope

1. Enumerate every command, semantic mode, option, default and enum. Start with the accompanying 38-command / 205-declaration inventory, then reconcile actual source. Include hidden flags, root version/help metadata, REPL clarification behavior and installed plugin commands. Fail CI for drift, omissions or silently discarded arguments. Do not remove CLI functionality to satisfy parity.
2. Move workflow logic out of terminal handlers into typed shared services used by CLI and MCP. Generate or cross-check both interfaces against one definition. Keep named tools and aliases; do not implement a free-form CLI/shell execution tool.
3. Register completed adapters independently of per-invocation approval/readiness. Every requested mode/backend must have a real implementation path. Permission rejection and missing dependencies are honest runtime outcomes, not substitutes for migration completion.
4. Enforce independent read, write, provider, execution and publication authority. Preserve request-effect attenuation, resource scopes, profile hashing and policy versions. The trusted planner derives required effects. Check permissions again at every real effect. Child workflows cannot widen scope or multiply parent budgets. Deny hidden subprocesses, fallback providers, arbitrary executable paths, workspace plugin imports and unrestricted retry.
5. Migrate every reachable backend/tool probe/build/SAST/generated-code stage to the strict executor. Preserve actual observations, immutable snapshots, cgroup/tmpfs/output/process limits and publication. Add real acceptance for every supported backend. Keep readiness and infrastructure failure separate from negative program evidence.
6. Convert `domain`, generative `draft` and `design-system` into resumable structured sessions. Support up-front answers, clarification, restart, cancellation, idempotency and reconnect. Use protocol-native tasks/elicitation only when supported; retain a tested ordinary-tool continuation path. Never prompt through terminal stdin.
7. Expose promotion, signing and trust administration as complete approval workflows. Keep raw trust executors outside agent authority. Separate request/status coordinators from an independently authenticated human signer/admin service. Bind approval to exact action, artifact/evidence/policy digests, destination, identity, expiry and single-use nonce. Reject forged/replayed/stale approval and changed artifacts. List-only trust access is distinct from mutation. A Boolean, key ID or hash supplied by the model is not approval.
8. Preserve all options through explicit mappings: JSON presentation becomes structured results plus authorized export; executable selection becomes operator-controlled toolchain identity; sensitive force/replacement/signing flags become approval-bound intent; lowered-assurance modes retain lower claim ceilings; provider fallback is separately approved. Do not ignore options lacking exact current MCP arguments.
9. Return typed results separating workflow completion, verification, claim, admission, execution compliance, publication and approval. Record exact policies and source/tool/output identities in evidence. Parent results reference child manifests. Pure inspections and generated documents never become proof claims by association.
10. Add schema/discovery, shared-service parity, negative policy, approval, session/replay, and real MCP transport tests. Mandatory provisioned backend tests must not skip. Complete greenfield and brownfield AiderDesk recipes without shell or compatibility-mode escape paths. Generate updated guide/reference/admission matrices from the same inventory.

## Deliverables

Shared request/result services; full named MCP adapters; complete invocation profiles; hardened effect/provider/approval/session services; backend migration; machine-readable parity manifest; generated command/option documentation; unit/adversarial tests; real backend/transport acceptance; and a per-command completion report.

Use the companion specification and matrix for scope. Proposed names are not existing public API. Preserve existing compatible aliases where appropriate. Implement in dependency-ordered changes, but do not declare the release complete until every supported CLI workflow has a working MCP path with its required permissions or human approval.

## Definition of done

For equivalent inputs, approved permissions and a provisioned environment, every CLI workflow completes through MCP with equivalent semantics, claim limits and evidence. No missing command/mode/option, no unrestricted subprocess path, no omitted effect check, no model-controlled human approval, no registration-only placeholder counted as complete.
