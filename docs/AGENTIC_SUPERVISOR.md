# Supervised agentic workflow

FormalSpecGen's first goal-level supervisor is an MCP-only application capability. It coordinates
existing admitted workflows; it is not a shell agent, a source editor, an approval authority, or a
second verifier.

The admitted profile accepts one Java/JML source snapshot and this fixed action proposal:

```text
inspect → verify → immutable review report
```

The caller proposes those typed actions. The trusted gateway rejects unknown actions, validates the
Git revision and source digest, derives the required effects, and invokes the existing admitted
`inspect_code` and `verify_code` paths. Verification therefore retains its sandbox observation and
child evidence manifest. Raw verifier output is not copied into operational state.

## MCP tools

| Tool | Purpose | Authority |
| --- | --- | --- |
| `start_agent_run` | Bind a goal and execute the approved plan | Workspace read, strict execution, evidence publication, service-state read/write |
| `get_agent_run` | Read durable state without resuming | Service-state read only |
| `resume_agent_run` | Continue only between known actions | Same bounded authority as start |
| `cancel_agent_run` | Record cancellation; never acceptance | Service-state read/write only |

The protected operational store is configured with an absolute
`FORMALSPECGEN_AGENT_STATE_ROOT` outside the agent-editable workspace. The authenticated application
principal is configured with `FORMALSPECGEN_AGENT_PRINCIPAL`. Both are server settings, not tool
arguments.

Example request:

```json
{
  "run_id": "counter-review-001",
  "objective": "Inspect and verify the approved Counter implementation",
  "base_revision": "<full 40-character Git revision>",
  "source": "src/Counter.java",
  "source_sha256": "<SHA-256 of the approved source bytes>",
  "mode": "esc",
  "proposed_actions": ["inspect", "verify"],
  "allowed_paths": ["src/Counter.java"],
  "protected_paths": ["specs/Counter.jml"],
  "resource_budget": {
    "max_actions": 2,
    "max_failures": 1,
    "max_input_bytes": 1048576
  }
}
```

The initial profile has no source-write, provider, worker-dispatch, signing, promotion, trust-policy,
or merge permission. A result can be `COMPLETED` only when verification reports that the requested
check was satisfied and its evidence publication was committed. Negative verification, denied
authority, source drift, and infrastructure failure remain visible and cannot be rewritten by the
supervisor.

## Persistence and recovery

Goals and state transitions are principal-scoped, hash-chained, append-only events. The terminal
review is published with no-replace semantics and binds the goal digest, revision, source digest,
actual inspection result, verification result, child evidence receipt, admission policy, unresolved
findings, and human-approval boundary.

An action intent is persisted before its workflow runs. If the controller dies before its outcome
is recorded, `resume_agent_run` returns a blocked review with `ACTION_OUTCOME_UNKNOWN`; it does not
blindly repeat the verifier or create replacement evidence. Runs can resume automatically only at a
known boundary between actions.

## Relationship to A2A coordination

The existing A2A coordinator remains the infrastructure service for optional independent worker
review. Worker task records, leases, reconciliation, cancellation, and acceptance stay inside that
service. This first supervisor profile does not dispatch workers, because combining an independent
proposal with goal acceptance needs a reviewed task-reference contract and transport acceptance of
its own. Until that profile lands, use the admitted A2A tools separately and treat every worker
artifact as an unaccepted proposal. Worker completion, model agreement, and this supervisor's
verification result remain distinct facts.

The next profile may attach an existing principal-owned A2A task and wait/reconcile through the
coordinator. It must preserve `dispatch_uncertain`, `cancellation_pending`, and coordination
inconsistency rather than manufacturing a successful review.
