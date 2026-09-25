# A2A worker coordination

FormalSpecGen can expose a small MCP-to-A2A bridge for implementation workers.
A2A coordinates work and returns proposal artifacts; MCP remains the admitted
tool interface. Worker completion never means that an implementation was
accepted, formally verified, signed, or authorized for merge.

The strict MCP catalogue provides four coordination tools:

| Tool | Effect |
| --- | --- |
| `submit_work_item` | Submit one revision-bound work item to an approved worker. |
| `get_work_item` | Read local state or refresh the remote A2A task. |
| `get_work_artifacts` | Return digest-bound artifact references. It does not apply a patch. |
| `cancel_work_item` | Request remote cancellation and record the outcome. |

## Install

Install the MCP and pinned official A2A transports in the trusted service
environment:

```bash
python -m pip install -r requirements-mcp.txt -r requirements-a2a.txt -e .
```

The integration is pinned to the official Python SDK 1.1.5 and uses the A2A
1.0 JSON-RPC binding. HTTP worker URLs are accepted only for loopback fixtures;
deployed workers must use HTTPS.

## Operator configuration

The service requires these environment variables:

```text
FORMALSPECGEN_A2A_POLICY=/operator/config/formalspecgen-a2a-policy.json
FORMALSPECGEN_A2A_STATE_ROOT=/operator/state/formalspecgen-a2a
FORMALSPECGEN_A2A_PRINCIPAL=aiderdesk-production
```

The policy and state root must be absolute and outside the agent-editable
workspace. Worker authentication tokens are named by policy and supplied in the
service environment; they are not MCP arguments or work-item fields. The policy
must be a regular, non-symlink file that is not group- or world-writable; an
existing state root must likewise be a protected, non-symlink directory.

A policy has this shape:

```json
{
  "schema": "formalspecgen-a2a-policy-v1",
  "authorities": [
    {
      "ref": "verify-rust-grant",
      "principal_id": "aiderdesk-production",
      "project_root": "/srv/formalspecgen/project",
      "workers": ["rust-worker"],
      "workflows": ["verify"],
      "effects": ["workspace_read", "workspace_write_new"],
      "allowed_paths": ["pipeline/**", "tests/**"],
      "max_budget": {"wall_seconds": 900},
      "expires_at": "2026-12-31T23:59:59+00:00"
    }
  ],
  "workers": [
    {
      "worker_id": "rust-worker",
      "endpoint": "https://workers.example.invalid/rust",
      "agent_card_sha256": "<64 lowercase hex characters>",
      "workflows": ["verify"],
      "effects": ["workspace_read", "workspace_write_new"],
      "allowed_paths": ["pipeline/**", "tests/**"],
      "max_budget": {"wall_seconds": 600},
      "auth_token_env": "FORMALSPECGEN_RUST_WORKER_TOKEN"
    }
  ]
}
```

The effective worker grant is the intersection of the authority, worker
profile, requested effects, path scopes, and resource ceilings. The worker ID
resolves only through this operator policy; callers cannot provide an endpoint.
The Agent Card is digest-pinned before a work item is sent.

Each worker runtime needs its own MCP client configuration and its own admitted
FormalSpecGen permissions. Connecting the coordinator does not forward MCP
credentials or make unadmitted workflows available to a worker. A typical
implementation worker can write only candidate artifacts in its assigned
workspace, while a review worker receives read and approved-check authority but
no candidate-rewrite authority.

## Work-item and result contracts

Submission uses `formalspecgen-work-item-v1`. It binds the objective and
authority reference to a full base commit, constrained paths, requested effects,
budgets, an acceptance-plan reference, and expected deliverables. Reusing an ID
with identical content is idempotent. Reusing it with different content fails.
Child work items may name `parent_work_item_id`; their effects, paths, and the
sum of active sibling budgets cannot exceed the parent. Active work under one
authority also shares its aggregate operator ceiling rather than multiplying it
once per worker.

Workers return `formalspecgen-worker-result-v1` as an A2A artifact named
`formalspecgen-work-result`. The result must bind the work-item ID and base
revision, list changed paths, and provide SHA-256 identities for patch/artifact
references. Out-of-scope changes fail closed.

Task events are append-only and hash chained. Retrieval and cancellation are
principal scoped: an unknown task and another principal's task have the same
response. The task record always retains:

```json
{
  "acceptance": {"status": "pending", "claim": "NO_PROOF"}
}
```

The trusted integration and acceptance runner must independently retrieve the
proposal, validate its bytes and path manifest, apply it in an isolated
workspace, and execute revision-bound acceptance. This bridge intentionally has
no merge, promotion, signing, or trust-management operation.

## Deployment boundary

- Give implementation and review workers distinct authority references.
- Keep provider, GitHub, signing, and reviewer credentials out of work items.
- Do not enable networking inside compiler, verifier, or generated-code sandboxes
  merely because the coordinator needs network access.
- Authenticate and authorize the worker endpoint independently. A2A task IDs are
  not bearer credentials.
- Run acceptance on the integrated revision. Evidence from separate worker
  branches does not establish the merged result.

CI runs a provisioned loopback acceptance using the official A2A server/client
and the real MCP stdio server. Missing A2A dependencies fail that job rather than
turning it into a skipped test.
