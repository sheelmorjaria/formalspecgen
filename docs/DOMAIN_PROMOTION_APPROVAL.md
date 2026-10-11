# Protected V2 promotion through MCP

This profile coordinates V2 promotion using the existing `ApprovalService` and
out-of-band OpenPGP decisions. It does not authorize an agent to approve a domain,
change trust policy, or select a reviewer or private key. Legacy V1 promotion
remains operator-only. Full `promote-domain` CLI/MCP parity is not claimed.

The three tools are:

- `request_domain_promotion(name, candidate, validation_evidence,
  replace_reviewed_domain=false, sign=false, ttl_seconds=900)` captures bounded,
  symlink-free workspace inputs and prepares a reviewed artifact privately. It
  returns `PENDING` with the request ID and complete promotion descriptor.
- `get_domain_promotion(request_id)` returns the request or authenticated receipt.
- `complete_domain_promotion(request_id)` asks an operator-configured helper to
  execute an existing authenticated decision. Without a decision it returns
  `APPROVAL_REQUIRED` and publishes no reviewed artifact.

The signed request binds the semantic candidate digest, exact source bytes,
validation-artifact bytes, expected applicability context, prepared reviewed
bytes, destination, existing destination digest, replacement intent, signing
behavior, requester, reviewer, current admission profile and operator policy.
`sign` selects the configured protected signing identity; it cannot name a key.
The promotion claim remains `NO_PROOF`. Bounded validation and deliberate review
remain separate properties.

## Operator configuration

Use the existing approval settings: `FORMALSPECGEN_APPROVAL_ROOT`,
`FORMALSPECGEN_APPROVAL_GNUPGHOME` (public verification keys),
`FORMALSPECGEN_APPROVAL_TRUST_REGISTRY`, `FORMALSPECGEN_APPROVAL_SIGNER`,
`FORMALSPECGEN_SIGNING_IDENTITY`, and `FORMALSPECGEN_REVIEWER_IDENTITY`.
Also configure:

| Variable | Meaning |
|---|---|
| `FORMALSPECGEN_PROMOTION_REGISTRY` | Existing protected directory for reviewed V2 JSON artifacts |
| `FORMALSPECGEN_PROMOTION_VALIDATION_POLICY` | Protected JSON file specifying expected validation options; `{}` selects defaults |
| `FORMALSPECGEN_PROMOTION_REVOCATIONS` | Protected JSON revocation list |
| `FORMALSPECGEN_PROMOTION_PRINCIPAL` | Operator-authenticated identity of this server/session; never a tool argument |
| `FORMALSPECGEN_PROMOTION_PUBLISHER` | Operator-controlled executable accepting only `--request-id` |

Configuration paths must be absolute, outside the agent workspace, free of
symlinks, and protected against group/world writes. The operator must enforce
filesystem/process permissions separating publication and private-key authority
from the agent. Merely placing a script outside the workspace does not create an
OS security boundary. The publisher must receive its authority and environment
from the operator; use a fixed installation of
`python -I -m pipeline.domain_promotion_approval --request-id ID`, not a
workspace-selected Python module or executable. The separate protected signer
holds private-key access; the MCP server receives no signing credentials.

The validation policy supports `timeout`, `max_states`, `max_transitions` and
`max_work_items`, independently of the validation envelope. A changed policy,
reviewer registry, principal, promotion implementation or request admission
profile requires a fresh request. Example revocation file:

```json
{"schema":"formalspecgen-promotion-revocations-v1","request_ids":[]}
```

An operator can add a request ID to revoke it. Revocations and current reviewer
policy are checked at completion and receipt inspection. They prevent further
execution/reporting as authorized; they do not undo an already published domain.

## Human decision and publication

Inspect the request, captured inputs, validation context, proposed reviewed
artifact, destination and replacement/signing intent before recording a decision
using the existing operator CLI:

```bash
python -m pipeline.approval_service \
  --root /protected/approvals --request-id REQUEST_ID \
  --decision approve --key FULL_REVIEWER_FINGERPRINT \
  --gpg-home /protected/reviewer-secret
```

The MCP tools never take a decision, signature, reviewer or acceptance flag as
approval authority. The publisher independently captures and verifies the
request/decision/signature, checks live inputs against their captured bytes,
reconstructs applicability from the current toolchain and operator validation
policy, and verifies that the reviewed output is exactly the approved output.

Publication serializes cooperating publishers and checks the destination against
the approved prior digest. Replacement requires explicit intent. Each artifact
contains its unique `approval_operation_id`. A durable intent record and atomic
rename let an interrupted action recover only its own published bytes. Signing
happens through the protected signer before publication; the detached signature
is retained in the protected approval bundle and returned by the receipt.
Retries return the same authenticated receipt and never sign or publish twice.
If completion times out, inspect/retry the same request ID rather than creating
another request. An uncompleted action must still satisfy expiry and current
policy/applicability; an expired request cannot authorize a fresh publication.

Inspection returns separate publication, signing and receipt phases. In particular,
an interrupted action can report `PUBLISHED`, `SIGNED`, `NOT_COMMITTED` while
remaining `DECISION_RECORDED`. Reading those phases never publishes or signs.
The publisher checks the prior destination again after signing, immediately before
rename. The protected registry must restrict writes to cooperating publishers;
the advisory lock does not serialize unrelated filesystem writers.

The receipt binds the request, reviewer signature identity, exact published
artifact and optional detached signature. Authentic approval does not establish
specification adequacy, source correspondence or an unbounded proof.

## Qualification

Unit contracts cover approval absence, denial, replay, wrong principal/reviewer,
revocation, expiry, changes to inputs/configuration/destination, tampered receipts,
protected signing and interrupted publication. Provisioned CI additionally runs
real TLC, MCP stdio, an external human GPG decision and the protected publisher,
then verifies the detached signature independently and uploads the observations.
The MCP server, publisher and signer use a wheel installed outside the hostile
workspace. Nine transport cases cover signed/unsigned creation and replacement,
denial, stale candidate, changed destination, interrupted publication and competing
approved replacements. The downloaded bundle retains exact control/publication
bytes, public keys, schemas and call results. Replay it at its clean tested revision:

```bash
python -m scripts.qualify_domain_promotion \
  --evidence /path/to/downloaded/domain-promotion-acceptance \
  --output /tmp/promotion-qualification.json
```

This checks the revision/tree, plan, observed schemas, authenticated decisions,
approval bindings, receipts and detached signatures. Qualification relies on
obtaining the bundle from trusted CI; a self-authored bundle is not a CI attestation.
Local acceptance does not qualify an uncommitted revision. The checked-in parity
baseline remains evidence-free; V1 and complete command parity remain out of
scope for this profile.
