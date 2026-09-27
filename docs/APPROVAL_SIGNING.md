# Authenticated approval and protected signing

Refactor signing is a continuation of an already published verification result. It is not a new
proof and does not strengthen the result's claim.

## Trust boundary

The strict MCP server may create an artifact-bound approval request, report its state, and ask a
fixed protected signer to execute an approved action. It cannot create the human decision, select a
different signer, accept a private key as a tool argument, or modify the unsigned evidence.

The request binds the exact result artifact and evidence-manifest digests, action, destination,
reviewer and signer identities, admission-profile digest, policy version, expiry, and unique
operation identifier. The human decision repeats those bindings and is authenticated with a
detached GPG signature. Under approval policy v2, the protected signer captures bounded private
copies of the request, decision, decision signature, artifact, and evidence manifest. Parsing,
authentication, signing, and post-signature verification all use those captured bytes. It never
asks GPG to reopen the agent-workspace artifact after validating it.

Reviewer and signer configuration uses **complete primary-key fingerprints**. An eligible signing
subkey is accepted only when GPG reports that it belongs to the pinned primary key. Receipts record
both the pinned primary fingerprint and the actual signing fingerprint. Short key IDs, suffix
matching, and otherwise-valid signatures from unrelated primary keys are rejected.

## Operator configuration

Configure these values in the trusted MCP service environment. Paths must be absolute, outside the
agent workspace, and not group- or world-writable.

| Variable | Purpose |
| --- | --- |
| `FORMALSPECGEN_APPROVAL_ROOT` | Durable, operator-controlled request/decision/receipt state |
| `FORMALSPECGEN_APPROVAL_GNUPGHOME` | Public-key-only GPG home for reviewer and signer validation |
| `FORMALSPECGEN_APPROVAL_TRUST_REGISTRY` | Trusted reviewer registry |
| `FORMALSPECGEN_APPROVAL_SIGNER` | Fixed executable implementing the protected signer contract |
| `FORMALSPECGEN_SIGNING_IDENTITY` | Complete pinned signer primary-key fingerprint |
| `FORMALSPECGEN_REVIEWER_IDENTITY` | Complete pinned reviewer primary-key fingerprint for newly created requests |
| `FORMALSPECGEN_APPROVAL_TTL_SECONDS` | Optional request lifetime, default 900 seconds |

The signer must keep its private key and signer configuration outside the MCP process. In a
production deployment, run it under a separate OS identity or service boundary and authorize only
the narrow request/decision/artifact interface. The CI wrapper is a disposable acceptance fixture,
not a production key-isolation design.

Requests created under approval policy v1 are not automatically upgraded. Create a new request
after deploying policy v2 so the human decision explicitly binds the current policy semantics.

## Workflow

1. Call `verify_refactor` with a fresh `result_export` and `signing_intent: true`.
2. Review the unsigned result, immutable evidence, request digest, action, destination, identities,
   policy, and expiry.
3. Record the human decision outside MCP:

   ```bash
   python -m pipeline.approval_service \
     --root /protected/formalspecgen/approvals \
     --request-id REQUEST_ID \
     --decision approve \
     --key REVIEWER_FINGERPRINT \
     --gpg-home /protected/reviewer-gpg
   ```

4. Call `get_approval_request` to observe the decision state.
5. Call `complete_refactor_signing` with the request identifier.
6. Independently validate the returned receipt and detached signature against the exact exported
   artifact.

A denial is terminal. Expired, forged, replayed, mismatched, or artifact-stale approvals are
rejected. Concurrent retries share one operation identity and cannot replace a prior signature or
receipt. If the process stops after signature creation but before receipt publication, retry
validates the existing signature and publishes the receipt without signing again.

## Claim semantics

Keep these outcomes separate:

- unsigned verification and preservation result;
- human approval decision;
- protected signing execution;
- receipt publication.

`SIGNED` means the exact recorded artifact was signed under the approved identity. It does not mean
behavioral equivalence was proved, remove backend bounds, or turn a `NO_PROOF` result into proof.
