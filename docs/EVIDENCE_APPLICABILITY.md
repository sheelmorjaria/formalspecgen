# Evidence applicability

Integrity, applicability, authenticity and assurance sufficiency are separate
properties. The shared `pipeline.evidence_applicability` service compares an
integrity-checked recorded context with independently supplied current
expectations. Its versioned decision contains reasons, evidence/context digests,
and `APPLICABLE` or `REVALIDATE`. It never grants human approval or authenticates
the evidence. Exact JSON types matter; larger bounds do not automatically make
different evidence reusable.

## Domain validation and promotion

New `validate-domain` results include an `applicability_context` inside the
digest-protected validation envelope, also retained in the immutable bundle.
The `formalspecgen-domain-validation-context-v1` context binds:

- Validation schema and workflow identity.
- The complete captured domain-input tree: exact candidate bytes, size and digest.
- The exact generated TLA/CFG identities and effective parsing, traversal, resource and TLC execution limits.
- Package/dependency versions and parser, translator, validation and policy
  implementation file digests.
- The TLC jar digest from the actual execution snapshot, Java launcher, runtime release, standard modules and JVM library digests, plus Python/platform identity. The envelope also
  records the observed TLC version, generated model identity and validation result.
- The strict admission profile digest and admission-policy version.

This source-tree scope is **captured domain inputs**, not every file in a Git
checkout. It works for installed wheels and projects without Git. No checkout
revision, dependency-contract applicability, source correspondence, specification
adequacy or general proof-sufficiency claim is inferred from it.

Human-only V2 promotion consumes the shared applicability decision before
publication. It requires both `--accept-candidate-sha256` and
`--accept-validation-sha256`; the latter is the exact artifact **byte digest**
returned as `validation_artifact.sha256`, not the envelope's inner evidence digest.
Promotion captures each input once using bounded regular-file reads and rejects
ambiguous evidence JSON. It records the accepted candidate, inner evidence,
artifact and current-context digests in the reviewed domain.

```bash
formalspecgen validate-domain toggle --json validation-result.json
# Inspect the candidate, result, immutable bundle and applicability context.
formalspecgen promote-domain toggle \
  --validation-evidence "$(jq -r '.validation_artifact.path' validation-result.json)" \
  --accept-candidate-sha256 "$(jq -r '.candidate_sha256' validation-result.json)" \
  --accept-validation-sha256 "$(jq -r '.validation_artifact.sha256' validation-result.json)"
```

Defaults match `validate-domain`. For nondefault limits, supply an independent
operator JSON file with `--validation-config policy.json`. Supported fields are
`timeout`, `max_states`, `max_transitions`, and `max_work_items`; omitted fields
use the defaults. Unknown fields, invalid values and ambiguous JSON are rejected.
Relative policy paths are resolved under `--project-root`.

An intact envelope from different captured bytes, implementation, tool, policy
or effective configuration yields `REVALIDATE` with specific reasons. Old
envelopes remain readable for integrity inspection but cannot be promoted
without revalidation. There is no implicit stale-context override.

The ordinary MCP agent still cannot promote domains. CLI digest acceptance
expresses deliberate operator review; it does not authenticate a reviewer or
replace the future protected approval coordinator. The CLI does not query GitHub or authenticate a CI qualification receipt; qualifying the implementation commit remains a separate operator/release gate. The JVM identity covers the named runtime components, not the entire operating system or every native dependency. `evidence applies`, project
planning and other verification workflows are future consumers, not currently
qualified by this domain-specific adapter.

## Qualification reports

Keep these figures separate: mapped interfaces, admitted invocation profiles,
and CI-qualified complete workflows at an exact revision. At `cc7ba42`, trusted
[CI qualification](https://github.com/sheelmorjaria/formalspecgen/actions/runs/37925860631)
established 18/44 complete workflows. That historical result does not qualify
subsequent applicability changes. The checked-in report remains evidence-free;
fresh revision-bound CI evidence is needed for a new completion claim. Provisioned acceptance includes eight synthetic operator CLI promotion cases, with retained candidate and validation artifact bytes, matching-context acceptance, digest checks and rejection of candidate, configuration, legacy, implementation, version and integrity mismatches. These fixture checks do not authenticate a human reviewer or admit MCP promotion.
