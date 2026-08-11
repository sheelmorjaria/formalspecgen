# V2 Domain Evidence Blueprint

Status: **implemented through the explicit V2 CLI lifecycle**

This document defines the evidence lifecycle for typed V2 domain models, including multi-actor
Boolean APIs. V2 is selected explicitly with `domain --schema-version 2`, `validate-domain`, and
`promote-domain --schema-version 2`. It does not change the reviewed V1 elevator model, which uses
strict-guarded `void` actions and a scoped single-threaded atomic contract-refinement claim.

## Claims and boundaries

- `unreviewed` is a generated proposal and carries no semantic trust.
- `VALIDATED` means deterministic consistency checks and bounded TLC safety checks completed for
  the exact candidate identified by the evidence.
- `reviewed` requires a separate explicit human promotion of that exact validated candidate.
- `SOURCE_MODEL_REFINEMENT` requires a separate reviewed method/action simulation gate.
- Hashes provide artifact integrity and TOCTOU detection. They do not authenticate a reviewer and
  do not provide non-repudiation. Those claims require a separately verified GPG/Sigstore signing
  policy.
- This evidence is suitable for inclusion in a larger assurance case; it is not regulatory
  certification and does not establish liveness, fairness, unbounded correctness, or concurrent
  linearizability.

## Successful validation envelope

The outer digest covers only a canonical serialization of the inner `evidence` object. It never
covers the envelope containing itself.

```json
{
  "evidence": {
    "schema_version": 2,
    "candidate_sha256": "<canonical candidate digest>",
    "generated_tla_sha256": "<generated module digest>",
    "validation_status": "VALIDATED",
    "execution_assumption": "atomic_last_result_abstraction",
    "abstraction_mode": "atomic_operations",
    "bounds": {
      "current_floor": [0, 4],
      "door_state": [0, 1],
      "moving_state": [0, 2],
      "actors": 2
    },
    "state_space_upper_bound": 270,
    "reachable_state_count": "<measured integer >= 1>",
    "reachable_transition_count": "<measured non-negative integer>",
    "tools": {
      "tlc": {
        "version": "<captured version>",
        "command": ["java", "-jar", "<tla2tools.jar>", "-help"]
      }
    },
    "tlc_exit_status": 0
  },
  "evidence_sha256": "<digest of canonicalized evidence only>"
}
```

Counts are never placeholders in a `VALIDATED` artifact. Before validation they are absent or
`null` under a `PENDING` status. Tool-version discovery failure is explicit and prevents successful
validation according to policy.

TLC 2.19 does not implement `-version`. Provenance discovery invokes its supported `-help`
command and requires a recognized version banner. TLC currently exits 1 after rendering help;
successful provenance is therefore determined by strict banner parsing, while the observed help
exit status is retained rather than silently rewritten.

## Canonicalization

Candidate and evidence digests use UTF-8 JSON with recursively sorted keys, compact separators,
and non-finite numbers forbidden:

```python
canonical = json.dumps(
    value,
    sort_keys=True,
    separators=(",", ":"),
    ensure_ascii=False,
    allow_nan=False,
).encode("utf-8")
digest = hashlib.sha256(canonical).hexdigest()
```

The raw source-file digest may additionally be recorded, but it is distinct from the semantic
canonical digest.

## Atomic publication

Successful and failed artifacts use separate paths. Publication writes a uniquely named temporary
file in the destination directory, flushes and `fsync`s the file, applies the intended permissions,
then atomically replaces the destination. On platforms requiring crash-durable directory updates,
the destination directory is also `fsync`ed. Temporary files are cleaned up after failures.

```text
domains/candidates/<domain>.validation.json
domains/candidates/<domain>.validation_failed.json
```

A failed validation never overwrites the last successful validation certificate. Its failure
artifact records the candidate hash, failed gate, normalized diagnostics, tool provenance available
at failure, and timestamp. Diagnostics must be scrubbed of secrets and machine-specific credentials.

## Promotion

Promotion recomputes the canonical candidate digest and requires it to equal both:

1. the digest in the successful validation envelope; and
2. the digest explicitly accepted by the human invocation.

The reviewed canonical artifact records the accepted candidate digest and its own canonical digest.
Changing `review_status` therefore does not pretend that candidate and canonical files have the same
hash. Future reviewer authentication may sign a payload containing the candidate digest, validation
evidence digest, reviewer identity, timestamp, action, and signing-policy identifier.

## Boolean last-result abstraction

Future `false_and_stutter` APIs use a bounded per-actor `callResult`. Success and failure are
separate actions. Failure changes only `callResult[actor]` and leaves all domain state unchanged.
The result variable is declared in `VARIABLES`, initialized, included in `TypeOK`, and included in
the specification state tuple.

This is an `atomic_last_result_abstraction`: it does not represent pending invocations, response
histories, overlapping calls, or linearization points. A stronger concurrency claim requires an
explicit call protocol with per-actor program counters, arguments, invocation/response events, and
a separate linearizability proof.

## Validation order

1. Parse the typed discriminated schema.
2. Validate initial values, frames, effects, failure semantics, and expression types.
3. Compute a bounded state-space upper bound and fail closed above the configured cap.
4. Traverse reachable states with simultaneous pre-state effect evaluation.
5. Check bounds and invariants in `Init` and every reachable post-state.
6. Deterministically render TLA+ and its separate TLC configuration.
7. Run SANY/TLC and capture exact command, version, exit status, bounds, and abstraction.
8. Construct and atomically publish the successful evidence envelope, or separately publish a
   failure artifact.
9. Require explicit hash-bound human promotion before assigning `reviewed` status.
