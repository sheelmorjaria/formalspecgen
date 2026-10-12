# Reviewed V2 domains to Java

This scoped profile connects the resumable V2 domain and authenticated promotion
handoff to deterministic Java/JML generation and isolated native ESC. Full
`draft` and `implement` CLI/MCP parity remains incomplete: V1, other languages,
interactive drafting, repair loops, dependency adapters and specialist assurance
options retain their existing operator workflows.

## Inputs and permissions

Keep the original unreviewed candidate, its validation artifact and the exact
promoted reviewed JSON together. Copy the reviewed artifact into the authorized
workspace, preserving its bytes, if the protected registry is outside it. The
reviewed JSON goes under `domains/v2/<module_name>.json` for canonical drafting.

The service captures regular files once through no-follow descriptors, rejects
symlink components and bounds total input to 4 MiB/five files. It compares the
reviewed semantics with the original candidate and checks the accepted candidate,
validation artifact, envelope and applicability-context digests. Legacy or stale
validation requires revalidation and promotion. Expected validation options come
from the current default bounded profile; custom validation configurations are
outside this initial Java profile.

Reviewed artifact integrity is not reviewer authentication. This service neither
grants promotion authority nor replaces the protected approval coordinator. A
natural-language requirement is retained by digest; generation does not establish
that the formal domain adequately expresses that requirement.

Generation requires workspace read and new-file publication only. It invokes no
provider, compiler or verifier. Implementing additionally requires external
execution and evidence publication. Omitting an explicit implementation candidate
also requires provider access. The provider uses operator configuration, receives
one request, and has a 256 KiB HTTP-response and 128 KiB source limit. There is no
automatic repair or retry loop. Model input is limited to 256 bytes.

## MCP

```text
draft_canonical_contract(
  domain="switch", requirement="A boolean switch",
  domain_candidate="candidate.json",
  validation_evidence="validation.json",
  out_file="draft/Switch.java")

implement_code(
  spec_path=".formalspecgen/mcp-output/draft/Switch.java",
  v2_reviewed_domain="domains/v2/switch.json",
  v2_validation_evidence="validation.json",
  domain_candidate="candidate.json",
  candidate="implementation/Switch.java")
```

For provider generation omit `candidate` and select an admitted `provider` and
optional `model`. Strict MCP accepts only sequential atomic V2 Java. Unsupported
languages and assurance modes are rejected before legacy dispatch. Output paths
are relative to the server-controlled `FORMALSPECGEN_MCP_OUTPUT_ROOT` and must
end in the generated public class filename. The default creates a unique bundle.
Existing files and symlinked destinations are never replaced.

## CLI

```bash
formalspecgen draft 'A boolean switch' --canonical-domain switch --lang java \
  --no-clarify --generation-only --domain-candidate candidate.json \
  --validation-evidence validation.json --out output \
  --out-file draft/Switch.java --json -

formalspecgen implement output/draft/Switch.java --canonical-java \
  --v2-reviewed-domain domains/v2/switch.json \
  --v2-validation-evidence validation.json --domain-candidate candidate.json \
  --candidate implementation/Switch.java --out output --json -
```

Both adapters use the same typed request and service. CLI JSON uses the existing
`formalspecgen-cli-result-v1` envelope. Legacy drafting and implementation remain
available without the new opt-in flags. Unsupported combinations fail explicitly.

## Results and claims

Generation returns `CANONICAL_CONTRACT`, `NO_PROOF`. Implementation first requires
the exact deterministic scaffold and checks the candidate's complete trusted
Java/JML surface, including proof-trust directives and assumptions. Only bodies
and permitted proof annotations may change. It executes captured bytes privately
through the shared strict OpenJML adapter with no unrestricted fallback.

Successful ESC retains `DEDUCTIVE_PROOF`; failed, dropped, unavailable, timed-out
or unbound execution cannot satisfy the request. The execution observation must
show enforced policy and the exact source digest. This establishes native
contract verification, not source/model refinement, specification adequacy,
critical concurrent assurance or unbounded domain validation.

Publication commits the source, exact input snapshots and a versioned JSON receipt
as one no-replace bundle. The receipt binds input, generator/policy, contract,
trusted-surface and implementation identities, declared effects, execution
observations, raw output and available launcher identity. It is an audit receipt,
not authorization for automatic evidence reuse. Failed ESC can still publish its
negative observations. Publication failure makes the overall result unsuccessful
and `NO_PROOF`. A repeated request must choose a new destination; this profile
does not have a resumable generation loop.

## Qualification and retention

Mandatory provisioned acceptance extends the real MCP session/TLC/human-promotion
chain with explicit-candidate and provider Java ESC, negative cases and equivalent
CLI requests. Its local HTTP provider is a deterministic fixture, not a Qwen
quality evaluation. Session and promotion bundles are retained for 90 days,
aligned with the parity report.

From a clean checkout of the tested revision, replay the downloaded session bundle:

```bash
python -m scripts.qualify_reviewed_java --evidence session.json \
  --output reviewed-java-qualification.json
```

The evaluator verifies actual artifact bytes, observed schemas, human approval,
input handoffs, generator identity, executed source, claims and CLI comparisons.
Only trusted CI provenance makes this a revision-qualified statement; self-authored
hashes are insufficient. A qualification index records revision/run and report
digests. Whole-command completion remains false.

A supervised Qwen/AiderDesk pilot should separately assess elicitation quality,
invalid provider output and accurate descriptions of generated, bounded-validated,
approved and promoted states. It requires the operator's real endpoint and model;
the fixture acceptance does not establish those usability properties.
