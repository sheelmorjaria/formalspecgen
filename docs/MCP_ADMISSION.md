# Strict MCP admission guide

Strict MCP exposes invocation profiles, not whole commands. A profile is the combination of a
command, mode, language, backend, provider policy, workspace effects, and evidence behavior that
has completed admission testing. An unlisted combination fails before side effects with
`ISOLATION_UNSUPPORTED` and `claim=NO_PROOF`.

A profile is a permission ceiling, not a bundle of permissions silently granted to every matching
request. An invocation receives only the intersection of its explicitly requested effects and that
ceiling. Omitting execution, publication, provider access, or writes means the corresponding effect
boundary will reject the operation even when the broader profile could have allowed it.

> Strict MCP exposes only explicitly admitted invocation profiles. Executing workflows require
> approved isolation and evidence publication across all execution stages. Non-executing workflows
> require bounded processing and explicitly constrained workspace and provider access. Unsupported
> combinations fail before side effects. Human promotion, signing, and trust administration remain
> outside agent authority.

## Current admitted profiles

| Workflow | CLI | Strict MCP | Modes / language / backend | Workspace effects | Provider access | Evidence | Human approval |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `verify_code` | Yes | Admitted | `parse`, `check`, `esc` / Java or JML / OpenJML | Read immutable input; execute in bounded disposable workspace; publish new immutable evidence | None | Exact execution observation and terminal manifest | Required for any later promotion or signing |
| `inspect_code` | Yes | Admitted | `inspect` / Java / built-in inspector | Read approved workspace input; no writes | None | Structured findings, not a proof receipt | Required before applying proposed changes |

Admission is checked before input processing and again at concrete execution and evidence-publication
boundaries. The strict catalogue is generated from these registry profiles, so an unsupported tool
is not registered merely because it has a Python handler.

Published verification evidence records requested and granted effects, the complete canonical
profile definition and its SHA-256 digest, and the admission-policy version. This binds a run to the
policy contents that authorized it rather than relying on a mutable profile name.

## Available through CLI but not admitted to strict MCP

The following legacy MCP handlers remain classified `unsupported`. Their CLI availability is
unchanged, but no command/mode/backend profile below is authorized for unattended MCP use:

```text
validate_architecture  implement_code        analyze_codebase
document_code          assess_security       security_inspect
security_exploit       remediate_code         correct_behavior
apply_refactor         verify_refactor        verify_bisimulation
optimize_algorithm     discover_algorithms    validate_domain
compose                reverify_composition   unified_system
draft_canonical_contract architecture         system
prove_equivalence      generate_traceability_matrix
verify_unbounded       verify_linearizability verify_distributed
verify_heap            verify_hal             macro_translate
verify_lockfree        verify_weak_memory     verify_wcet
verify_liveness        verify_dma             extract_intrusive_list
resolve_callbacks      doctor_environment
```

This classification does not mean that every handler is unsafe. It means its complete reachable
workflow has not yet demonstrated the required constraints. For example, `doctor_environment`
launches executable version/help probes and therefore cannot be admitted as non-executing.
`document_code --no-llm` and provider-assisted documentation are distinct prospective profiles
because file writes and provider data export are independent permissions.

## Admission paths

### Non-executing profiles

A non-executing profile must have bounded input traversal, processing time, and response size. It
must not launch external commands, evaluate submitted code, run project hooks, contact a provider,
or write files unless those effects are separately declared. A deterministic transformation should
initially write only new artifacts beneath a designated output root and must never promote them.

### Executing profiles

Every reachable compiler, verifier, generated program, subprocess, and delegated backend must use
the approved executor. Inputs come from an immutable snapshot; writable locations are bounded and
disposable; networking is denied unless a distinct reviewed profile permits it; descendants share
enforced resource limits; and infrastructure failure never falls back to unrestricted execution.
The actual execution observation—not a reconstructed command—must reach immutable publication and
the MCP response.

### Provider-assisted profiles

Provider access is never implied by a non-executing or transformation label. A future admitted
profile must bind server-controlled endpoint/model selection, explicit source-export permission,
request budgets, and a no-fallback policy. Credentials remain in the trusted controller and are
excluded from generated-program environments and evidence logs. Provider output remains an
untrusted proposal until independently reviewed and checked.

## Permanent human boundary

`promote_domain`, `sign_artifact`, and `manage_trust` are human trust actions. They cannot acquire
an MCP invocation profile even if their implementation could run in a sandbox. An agent may prepare
a review package, but it cannot accept, sign, or change reviewer trust policy.

## Deployment

Leave `FORMALSPECGEN_MCP_STRICT_JAVA_ONLY` unset for the strict catalogue. Setting it to `0` restores
the full legacy catalogue for explicitly trusted local compatibility work; it is not an admission
mechanism and does not grant those workflows strict-isolation or durable-publication claims.

For a supervised agent deployment, install a pinned package outside the agent-editable checkout,
run the MCP service in a delegated cgroup-v2 leaf, and expose only the default strict catalogue.
