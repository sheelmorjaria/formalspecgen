# FormalKernel state-of-the-art roadmap — M86–M120

Status: **prospective roadmap**. Nothing in this document is a minted claim.
Completed implementation and evidence through M85 remain documented in
[`FORMALKERNEL_PLAN.md`](FORMALKERNEL_PLAN.md).

## Strategic objective

FormalKernel should not attempt to reproduce every Linux subsystem. Its target
is a practical general-purpose OS whose important runtime mechanisms carry
machine-checkable, compositional, deployment-specific evidence from reviewed
specification through implementation, binary, hardware configuration, and
operation.

The controlling weakness is the unfinished M76 vertical spine. Current evidence
binds artifacts and exhaustively validates a bounded VFS implementation, but it
does not establish general Rust-to-LLVM semantic refinement, verified lowering,
target-binary semantics, or an end-to-end refinement theorem. Later milestones
must not inherit those stronger conclusions.

External comparison points include the [seL4 roadmap](https://sel4.systems/roadmap.html),
[RefinedRust](https://plv.mpi-sws.org/refinedrust/),
[Verus](https://verus-lang.github.io/verus/guide/overview.html), and the
[CHERI adoption landscape](https://cheri-alliance.org/adoption/). These links
provide research context; they are not FormalKernel evidence.

## Gate 0 — unfinished foundation

Work on M86 may be prototyped, but no M86 production claim is eligible until the
applicable foundation gate is discharged or explicitly recorded as pending.

| Gate | Required work | Eligible result |
| --- | --- | --- |
| M76.3 | Foundational semantics and implementation refinement for the accepted FormalKernel Rust subset | `RUST_IMPLEMENTATION_REFINEMENT_PROVED` |
| M76.4 | Verified or replayably validated lowering toward each target ISA | `COMPILER_REFINEMENT_CHAIN_PROVED` |
| M76.5 | Decode the final binary and relate it to target ISA semantics | `END_TO_END_REFINEMENT_CHAIN_ESTABLISHED` |
| M68/M69 closure | Physical R52 SMMU and x86 VT-d fault experiments | Profile-scoped physical DMA claims become eligible |
| M71.5 closure | Authenticated cache, memory, interconnect, DMA, IRQ, and SMT measurements | `TARGET_WCET_INTERFERENCE_BOUND_VALIDATED` |

The preferred judge stack is deliberately heterogeneous:

- RefinedRust/Iris/Rocq for foundational safe and unsafe Rust reasoning.
- Verus for scalable functional correctness of larger safe-Rust modules.
- Kani and ESBMC for bounded counterexample discovery and regression gates.
- TLA+/TLAPS for temporal, distributed, and parameterized control-state proofs.
- Z3 for arithmetic, resource, admission, and policy invariants.

No tool inherits another tool's theorem without an explicit refinement edge.

### Active milestone: M76.3 foundational Rust semantic refinement

M76.3 is now the highest-priority lane. RefinedRust provides deep foundational
assurance for unsafe and ownership-sensitive primitives; Verus provides broad
functional verification for larger safe-Rust modules. Neither replaces the
bounded, temporal, arithmetic, or weak-memory judges listed above.

M76.3a checks a deliberately tiny identity theorem through the real
`cargo refinedrust` translation and Rocq build. A controlled mutation from
`value` to `value + 1`, without changing the declared postcondition, is
rejected by Rocq as an incomplete proof. This qualifies the installed judge
lane; it does not mint implementation refinement for a kernel component.

M76.3b applies the lane to the production bounded allocator. Its initial
feasibility run is fail-closed: RefinedRust 0.1.0 currently generates an
incompatible refinement type for a fixed array embedded in a struct (dropping
the per-element `place_rfn`). A diagnostic representation with 16 individual
slots reaches the concrete proofs but does not complete the 16-way allocation
proof within the bounded run. It is not a substitute for production and mints
no claim. Closure requires a justified array-type translation, decomposed
functional contracts, and the full mutation suite.

M76.3c adds deterministic RefinedRust specification scaffolding, while Rocq
remains the judge. M76.3d permanently tests wrong postconditions, missing state
updates, stale proof artifacts, source-hash drift, and unrelated modules.
Compiler and target-ISA refinement remain separate M76.4 and M76.5 gates.

## Phase 8 — foundational verification (M86–M90)

### M86 — foundational Rust kernel core

Verify actual Rust scheduler, capability, allocator, queue, and page-table
modules in a foundational program logic, including their necessary unsafe code.

- Proposed claim: `FOUNDATIONAL_KERNEL_CORE_REFINEMENT_PROVED`.
- Required inputs: M76.3 semantics, reviewed module contracts, unsafe-code
  invariants, and foundational proof objects.
- Forbidden shortcut: model proof plus source hash is not implementation
  refinement.

#### M86.1 status — Verus production-module lane

M86.1a qualifies the pinned Verus `0.2026.08.15.7d4628a` judge with
`--no-cheating`: one positive functional theorem verifies, while a valid,
memory-safe semantic mutation reaches the judge and fails its postcondition.
The evidence binds Verus, `rust_verify`, bundled Z3, `vstd.vir`, the pinned
Rust toolchain, both inputs, and both outputs. This narrowly unlocks
`VERUS_JUDGE_QUALIFIED`.

M86.1b first linked the exact production M64 allocator as ordinary Rust. Verus
reported zero verified obligations, so that feasibility result remains
`NO_PROOF`. A subsequent verifier-only overlay now erases byte-for-byte to the
production allocator and creates an explicit constructor postcondition. The
pinned judge reports a nonzero inventory and rejects a memory-safe constructor
mutation, unlocking only `VERUS_PRODUCTION_OVERLAY_QUALIFIED`.

Allocation, release, error stuttering, and accounting are excluded from that
narrow claim because the current Verus standard-library surface does not cover
the production `iter_mut().enumerate()`, `get_mut`, and iterator-filter paths.
`BOUNDED_ALLOCATOR_FUNCTIONAL_CORRECTNESS_PROVED` therefore remains locked.
Imported code plus a successful compiler exit is never treated as verification.

All Verus lanes share a generic anti-vacuity policy. Zero verification units,
zero proof obligations, zero semantic postconditions, a surviving mutation, or
overlay drift produce `NO_PROOF` with a named refusal code.

M86.1c separates the remaining allocator library semantics into three generic
`--no-cheating` probes. The pinned Verus release currently rejects mutable
slice iteration plus enumeration, slice `get_mut`, and filter/count before
proof generation. Each bridge therefore remains `NO_PROOF`, with
`ITERATOR_TRAVERSAL_SEMANTICS_PROVED`, `GET_MUT_FRAME_SEMANTICS_PROVED`, and
`OCCUPANCY_COUNT_CORRESPONDENCE_PROVED` individually locked. Suggested
`assume_specification` or external-body shims are not accepted as proof, and the
production loop is not replaced with verifier-friendly manual indexing.

M86.2a expands coverage without making the allocator a blocker. A
Verus-specific scanner reads the live bridge ledger, excludes verifier-only
sources, and ranks the four production Rust modules by supported syntax,
semantic usefulness, and mutation surface. This scan is `NO_PROOF`.

M77 is the preferred conceptual target but currently has no production Rust VM
accounting module—only the reviewed model and its Python/Z3 judge lane. It is
therefore ineligible rather than replaced by proof-only code. The highest-ranked
existing candidate is `VirtioBlkAdapter::complete`, whose scalar queue mutation
has no known Verus blocker; its generic trait and `Result` try path remain
unknown until the exact-overlay probe.

M86.2b then qualifies an exact virtio-blk overlay. Erasure is byte-identical to
the production adapter, the entire module passes `--no-cheating`, and the real
`complete` method discharges four semantic postconditions covering empty-queue
error/stuttering and nonempty success/exact decrement. A memory-safe mutation
that decrements by zero fails. This unlocks only
`VERUS_VIRTIO_BLK_OVERLAY_QUALIFIED`; submit-path accounting, the complete
functional theorem, and the abstract-model bridge remain locked.

M86.2c extends that same exact overlay across constructor, occupancy getter,
submit, refusal stuttering, capacity preservation, and completion. Verus proves
the transition contracts from arbitrary states satisfying the private queue
invariant. Five memory-safe mutations covering initialization, missing
increment/decrement, and false-success error paths all fail, unlocking the
narrow `VIRTIO_QUEUE_ACCOUNTING_IMPLEMENTATION_CORRECTNESS_PROVED` claim.

M86.3 carries a separately materialized queue model with three
bounded states and eight submit/complete transitions. A deterministic validator
checks the candidate shape, and the exact production overlay discharges the
explicit relation `model.outstanding == rust.queue_depth()` with twelve semantic
obligations. Six memory-safe negative mutations are rejected, including a
weakened model transition. A human accepted candidate SHA-256
`191566f356e440aa074c44eae49b9088e0673706ce5e9b051152fe964b569b0e`.
The human-only promotion command froze a separate reviewed artifact and replayed
the positive Verus judgment and all six negative mutations before minting the
narrow `VIRTIO_QUEUE_MODEL_BRIDGE_PROVED` claim. Device behavior, interrupt
delivery, DMA completion, and virtio protocol semantics remain outside this bridge.

The Verus lane establishes broad functional correctness only. It does not mint
the foundational RefinedRust refinement claim, compiler refinement, or the
end-to-end refinement chain.

M86.4 freezes the virtio result as the reference bridge lifecycle and begins a
second-module scan. A common validated evidence schema now requires nonzero
verification units and semantic obligations, complete negative-mutation closure,
exact production/overlay/model hashes, explicit assumptions, and a reviewed-model
hash before any bridge may report `PROVED`. The scan finds no existing production
Rust implementation for the capability-authority or boot-rollback models.
`boot_order.rs` is constant-only, `timer_tick.rs` has no persistent authorization
or refusal state, and `witness.rs` uses unsafe volatile operations and indexed
arrays outside this broad Verus target fragment. M86.4a is therefore complete
and parked at `PARKED_NO_ELIGIBLE_PRODUCTION_MODULE` with `claim: NO_PROOF`;
no verification-only subsystem is invented. It reopens only when a production
state transition exists inside the supported safe-Rust fragment with a meaningful
contract and a viable negative mutation. The promoted virtio bridge is frozen as
the golden regression fixture for the common bridge schema.

### M87 — weak-memory implementation refinement

Relate Rust atomic operations through compiler lowering to declared Arm, x86,
and RISC-V memory models.

M87.1 performs the first exact-production feasibility gate. The scanner covers
the executable FormalKernel Rust tree while excluding proof and verifier-only
sources. It finds no `Atomic*` transition, atomic operation, or explicit
`Ordering`, so the lane is complete and parked at
`PARKED_NO_PRODUCTION_ATOMIC_TRANSITION` with `claim: NO_PROOF`. The existing
M61 x86 and AArch64 litmus hashes remain bound as model-level evidence, but the
report explicitly records that no Rust-source, compiler-lowering, or physical
silicon correspondence exists. The lane reopens only when kernel engineering
introduces a genuine production atomic transition with explicit ordering, a
reviewable state relation, and a meaningful negative ordering mutation.

- Proposed claim: `WEAK_MEMORY_IMPLEMENTATION_REFINEMENT_PROVED`.
- Existing herd7 litmus evidence remains model-level until this edge exists.
- Compiler version, target features, atomic lowering, and final instruction
  sequence must be bound.

### M88 — information-flow security

Prove confidentiality, integrity, and explicit declassification across process,
IPC, capability, and shared-memory boundaries.

M88.1 defines the first reusable hyperproperty envelope and a hash-bound scope
candidate over the reviewed M49/M50/M65 syscall, IPC, and capability artifacts.
It separates private server payload/token state from the deliberately narrow low
observables: syscall result, IPC route, capability decision, public queue
occupancy, and explicitly declassified output. The property is two-run,
termination-insensitive, and timing-insensitive. No declassification rule has
yet been accepted, no self-composed judge has run, and no confidentiality mutation
has failed, so the candidate records `claim: NO_PROOF`. Timing, cache state,
interrupt delivery, device behavior, token unforgeability, and implementation
refinement remain forbidden or outside scope.

M88.2a promotes candidate SHA-256
`059fc89f109c8983f9a7b0b4036a77b7670a5958d6ac60eef67ab2a0140ee81f`
through the human-only scope command, producing a separate reviewed artifact
without minting a proof. M88.2b then uses Z3 self-composition to prove one-step
low-observable equality for arbitrary differing high bits under identical public
inputs. Five model mutations leak high state into each reviewed observable and
produce counterexamples; removing an observable and widening declassification
are rejected by separate scope gates. This mints only
`SERVER_POLICY_TWO_RUN_NONINTERFERENCE_PROVED`. Trace, termination, timing,
declassification correctness, token unforgeability, and implementation refinement
remain locked.

M88.3 unrolls the reviewed relation across three matched public-input transitions
and compares all five low-observation traces. The Z3 self-composition is unsatisfiable
for arbitrary differing high bits. Two history-dependent mutations remain silent in
the first transition but leak through a later IPC route or later queue update; both
produce counterexamples. A separate anti-vacuity gate refuses trace depth below two.
This mints the bounded, termination- and timing-insensitive
`SERVER_POLICY_TRACE_NONINTERFERENCE_PROVED` claim only. The broad information-flow
claim and declassification theorem remain locked.

M88.4 begins with a separate declassification candidate. Its single reviewed-intent
rule, `AUTH_RESULT_PUBLIC`, permits only the Boolean authorization projection from
the internal capability-token state to the public capability decision when the
operation is mediated and caller identity is public. The candidate binds the
reviewed information-flow scope and depth-three trace evidence. Promotion is a
separate human-only exact-hash action and mints `NO_PROOF`; release authorization,
precision, non-amplification, rule isolation, and all policy mutations remain
unexecuted until that policy is accepted.

The exact candidate is now human accepted. Z3 discharges release authorization,
release precision, depth-three non-amplification, and rule isolation. Five semantic
policy mutations produce counterexamples: unconditional release, an extra secret
field, a redirected sink, implicit rule enabling, and remembered-secret laundering.
Broadening the source projection and deleting the required rule are rejected by
structural policy gates. This mints `DECLASSIFICATION_POLICY_PROVED` only for the
single reviewed `AUTH_RESULT_PUBLIC` rule; broad information-flow, timing,
microarchitectural, token-unforgeability, and implementation claims remain locked.

- Proposed claim: `INFORMATION_FLOW_NONINTERFERENCE_PROVED`.
- Scope must name principals, observations, scheduler assumptions, covert
  channels, and declassification policy.
- Timing and speculative channels remain separate unless explicitly modeled.

### M89 — capability authenticity

Prove derivation, delegation, revocation, attenuation, and non-forgeability for
software capability tokens.

M89.1 began with a parameterized authority-algebra candidate over arbitrary
finite nonempty principal, object, and right sets. Capabilities explicitly carry
object, rights, owner, generation, and validity. The reviewed transition surface
is `mint_root`, `derive`, `delegate`, `revoke`, and `check`, with fail-closed
stuttering refusals. The candidate states attenuation, creation closure,
transitive revocation, stale-generation rejection, and failed-operation frame
invariants. The human-reviewed model is bound to candidate SHA-256
`66c8e3455a412cc7a2246cf5afdc911d9a6974a9d439989c2675a5f7af7efb77`.

M89.2 uses TLAPS over arbitrary finite capability, principal, object, and right
universes. All 12 inductive obligations pass. Four negative variants—unauthorized
root minting, rights amplification, object substitution, and forged creation
origin—are rejected. This mints `CAPABILITY_AUTHORITY_ALGEBRA_PROVED` and
`CAPABILITY_TOKEN_CREATION_CLOSED_PROVED`. Transitive revocation remains M89.3.

M89.3 adds a separate parameterized revocation proof without changing the
M89.2 artifact. TLAPS discharges ten theorem obligations covering descendant
blocking, persistence across later transitions, unrelated-branch framing,
fresh-generation issuance, stale derive/delegate/check/revoke rejection, and
failed-operation stuttering. Nine semantic mutations are rejected. Generations
are modeled as unbounded naturals; fixed-width wraparound remains explicitly
unproved. This mints `CAPABILITY_REVOCATION_SAFETY_PROVED`.

M89.4 performs an explicit Z3 shared-state composition over the exact M49
syscall table, M50 IPC endpoints, M65 server grants, reviewed M88 observables
and declassification rule, and both hash-bound M89 parameterized proofs. Seven
composition families establish grant confinement, legal ancestry, stale and
revoked denial, route/result/queue stuttering, scoped high-state
noninterference, unrelated-revocation framing, and failed-operation stuttering.
Seven cross-subsystem mutations produce counterexamples. This mints the narrow
model claim `SERVER_AUTHORITY_SECURITY_MODEL_PROVED` and freezes M89 at
`model-authority-security-complete`.

- Minted scoped claims: `CAPABILITY_AUTHORITY_ALGEBRA_PROVED` and
  `CAPABILITY_TOKEN_CREATION_CLOSED_PROVED`.
- Still forbidden: token bit-pattern unforgeability, hardware enforcement, and
  capability/information-flow implementation refinement.
- This closes a named M65 boundary; it does not establish hardware enforcement
  or side-channel confidentiality.

### M90 — proof-carrying build

Attach a machine-readable evidence manifest to every kernel binary, binding
source, specifications, compiler, linker, judges, target configuration, proof
objects, assumptions, and pending claims.

M90.1 now emits a deterministic canonical candidate at
`examples/formalkernel/kernel/m90_evidence_root.candidate.json`. The checked-in
candidate binds 19 exact production source files, the deployment and hardware
profiles, a freshly generated 66-entry kernel evidence bundle, 80 scoped claim
entries and their dependencies, judge and compiler provenance, reviewed human
promotions, local verifier-patch provenance, assumptions, pending judgments, and
forbidden claims. Claim-graph, promotion-inventory, judge-manifest, and source-tree
digests make those collections independently replayable.

The M90.1 validator fails closed on stale source or evidence hashes, changed judge
executables, missing promotion records, forbidden claims, inconsistent dependency
graphs, and attempts to attach an unvalidated binary. It can distinguish a stale
judge requiring replay from an invalid evidence dependency. Adversarial mutation
tests exercise each boundary.

M90.1 deliberately records `claim: NO_PROOF`, `binary_sha256: null`, and
`binary_status: BINARY_BUILD_PENDING`. It canonicalizes the evidence graph but
does not bind a final ELF.

M90.2 builds the existing production `no_std` QEMU AArch64 image with a fully
declared target, compiler/linker identity, linker script, flags, empty codegen
environment, and three-file compiled-source closure. A deterministic in-tree ELF
parser binds the ELF64 class, little-endian AArch64 machine identity, entry point,
program headers, sections, size, and structural digest in addition to the complete
ELF SHA-256. The evidence DAG binds that identity back to the exact M90.1 candidate
and build record.

Applicability is deliberately smaller than the repository bundle. Only
`SYSTEM_COMPOSITION_PROVED` and `RUST_WITNESS_REFINEMENT_PROVED` directly bind to
the compiled `main.rs`, generated `boot_order.rs`, and exact `witness.rs`; the
N150/R52, VFS, process, desktop, and other uncompiled claims are excluded. The
validator recomputes that closure rather than accepting a supplied claim list.
ELF-byte substitution, wrong-profile reuse, codegen/linker drift, source omission,
claim omission or inflation, pending-claim promotion, stale dependencies, target
identity drift, and DAG substitution all fail closed.

This mints the narrow `PROOF_CARRYING_BINARY_VALIDATED` claim for artifact identity
and applicable evidence dependency binding. Compiler semantic refinement, target
functional correctness, and end-to-end refinement remain locked. The resulting
deployment root remains `HUMAN_SEAL_PENDING`; sealing is outside MCP and
agent-controlled interfaces.

M90.3 expands the M90.2 DAG into explicit build, binary, claim, artifact, judge,
profile, and pre-build-inventory nodes. Its evaluator computes transitive causes
and typed downgrades: `STALE_SOURCE`, `REPLAY_REQUIRED`, `REBUILD_REQUIRED`,
`PROFILE_INAPPLICABLE`, `HUMAN_REVIEW_REQUIRED`, `DEPENDENCY_UNPROVED`,
`BINARY_IDENTITY_REJECTED`, `CANONICAL_ROOT_REGENERATION_REQUIRED`, and
`FORBIDDEN`. Results contain the changed dependency plus old and observed digests.

Invalidation is claim-minimal. Changing the exact queue witness invalidates the
Kani claim but leaves deterministic composition valid; Kani drift does not affect
composition; unused VFS source, N150 profile, Z3, and TLAPS changes do not affect
this Kani/deterministic-gate closure. Linker or compiler inputs require a rebuild,
while ELF substitution rejects the binary binding. Changing the bound M90.1
inventory requires root regeneration but leaves both local claim closures valid
when their own dependencies are unchanged. Removing a transitive edge or injecting
a forbidden claim fails hard.

Twelve positive/negative qualification cases validate the engine. This mints the
operationally worded `EVIDENCE_DEPENDENCY_CLOSURE_VALIDATED` and
`EVIDENCE_INVALIDATION_SEMANTICS_VALIDATED`, not a semantic proof claim. Evidence
coverage for this image is reported as 2/2 declared compiled mechanisms, explicitly
not 2/66 repository claims or source-line proof coverage.

M90.4 performs two independent clean builds from separately staged checkout paths
and deliberately different file timestamps. Both builds reproduce the exact
156,664-byte ELF, its parsed structural digest, its two-claim applicable closure,
and a canonical evidence root. The canonical root excludes only ephemeral output
directory spelling; it retains the raw ELF digest, parsed structural digest, source
closure, compiler/linker hashes, flags, linker script, applicable closure, and
M90.1 identity.

The mutation suite changes checkout directories, timestamps, locale, timezone,
`SOURCE_DATE_EPOCH`, source-manifest enumeration, compiler identity, and linker
build-ID policy. Injected environment and compiler drift are diagnosed as
`REBUILD_REQUIRED` through M90.3 even when artifact bytes happen to match. A
deliberate build ID changes the raw ELF and is not normalized away. External linker
input ordering is recorded as not applicable because this image is a single Rust
crate without a caller-controlled external input list.

This mints the empirical claims `REPRODUCIBLE_BINARY_BUILD_OBSERVED` and
`REPRODUCIBLE_EVIDENCE_ROOT_OBSERVED`. It explicitly forbids
`REPRODUCIBLE_BUILD_PROVED`; two clean rebuilds are observations, not a theorem
about every future compiler execution.

M90.5 implements the CLI-only `seal-deployment-evidence` trust action. It requires
the human to supply the exact ELF SHA-256, canonical evidence-root SHA-256, and
release identity; neither accepted hash is inferred. Before writing anything it
revalidates the ELF binding, reruns M90.3 qualification, repeats the M90.4 clean
build observations, and requires every applicable lattice node to be `VALID`.
Pending evidence uses an exact whitelist policy; this image has no applicable
pending claims.

The sealed envelope binds positive claims and empirical observations together
with assumptions, forbidden claims, not-applicable bundle entries, the complete
repository pending inventory, build/judge provenance, reviewed promotions, and
local verifier patches. Omissions, stale evidence, wrong profiles or hashes,
changed release metadata, non-valid lattice states, pending-policy widening, and
attempted overwrite all refuse. The action is registered as human-only and cannot
appear in MCP.

The human-authorized release `formalkernel-m90-qemu-aarch64-2026.08.21` accepts
ELF SHA-256 `1a8d4e1113d9fdd2a948e0f9c739303d4690eb39588a3505475564165d88d3c9`
and canonical evidence root
`36f4e6cd9ce8a26cebea3c9913935d143856b6593d29e57fa6c99cd6493ecd8e`.
Its content seal is
`2b16df0fc7bb48863e33aabce79da5b2f3f4263e51128d4248dfafa3f8a21003`.
M90.5 is now `human-authorized-release`; the artifact status is
`SEALED_DEPLOYMENT_EVIDENCE` with `claim: NO_PROOF`. It remains an unkeyed
canonical content seal, not signer identity or PKI; hardware-backed attestation
remains M108.

- Minted claim: `PROOF_CARRYING_BINARY_VALIDATED` (M90.2 scope only).
- Validated evidence operations: `EVIDENCE_DEPENDENCY_CLOSURE_VALIDATED` and
  `EVIDENCE_INVALIDATION_SEMANTICS_VALIDATED` (M90.3 deterministic engine only).
- Observed reproducibility: `REPRODUCIBLE_BINARY_BUILD_OBSERVED` and
  `REPRODUCIBLE_EVIDENCE_ROOT_OBSERVED` (M90.4 two-build experiment only).
- Validation means artifact identity and evidence dependencies check; it does not
  mean machine-code behavior or every binary property is proved.

## Phase 9 — hardware-enforced security (M91–M95)

### M91 — first-class RISC-V server profile

Add RV64GC, H-extension virtualization, AIA/IMSIC, the RISC-V IOMMU, PMP/ePMP,
supervisor timer/IPI, and an optional NUMA declaration.

- Proposed claims: `RISCV_PRIVILEGE_TRANSITION_PROVED`,
  `RISCV_IOMMU_CONFIGURATION_PROVED`, and `RISCV_AIA_ROUTING_PROVED`.
- ISA/configuration theorems remain distinct from physical board behavior.
- Primary specifications must be pinned from
  [RISC-V International](https://docs.riscv.org/).

M91.1 begins with a concrete `FK-Lab-RISCV64-QEMU` candidate: RV64GC, M/S/U
privilege modes, Sv39, four declared harts, QEMU `virt`, PLIC+ACLINT baseline,
and human-owned non-overlapping UART/interrupt/DRAM regions. AIA/IMSIC,
H-extension, Smepmp, and RISC-V IOMMU 1.0.1 are desired but explicitly unprobed.

The normative identities are pinned to the official Privileged Architecture
20260120 release (Machine-Level ISA 1.13), AIA 1.0 clarification release
20250312, and IOMMU 1.0.1 release 20260222. Their URLs are official, but content
hashes remain `JUDGE_PENDING_UNTIL_VENDORED`; a mutable URL is not treated as a
content trust root.

The RV64 Rust target standard library, QEMU 8.2.2 RISC-V system emulator, GNU
RISC-V objdump 2.42, rustc, and rust-lld are installed and hash-bound. QEMU `virt`
is available; its machine options expose ACLINT and configurable
APLIC/IMSIC-backed AIA, while its `rv64` device-tree ISA string includes the H
extension. This QEMU build does not expose a RISC-V IOMMU architecture device.
M91.1's exact candidate hash was human accepted through the CLI-only
`promote-riscv-platform` trust action, which remains excluded from MCP. Promotion
minted no theorem. M91.2 then bound the reviewed profile to a generated TLA+
control-state model. TLC 2.19 verified eight reachable states covering S-mode
preparation, `sret` to U-mode, trap entry, validated dispatch, rejection of a
user-selected supervisor resume, and return. The narrowly scoped result is
`RISCV_PRIVILEGE_TRANSITION_MODEL_PROVED` over
`reviewed_qemu_virt_smode_umode_trap_return`.

This remains a model theorem: QEMU semantics, compiler/assembly trap-vector
refinement, physical privilege transitions, and physical execution are locked.
The missing QEMU RISC-V IOMMU device parks only the IOMMU lane as
`PARKED_NO_QEMU_IOMMU_DEVICE`; Sv39, AIA/APLIC/IMSIC, and H-extension work may
advance independently.

M91.3 binds the reviewed profile and M91.2 evidence to a human-promoted exact-hash
Sv39 mapping plan and exact PTE encodings,
a reviewed root `satp`, kernel/user text and data pages, and an unmapped guard.
The deterministic three-level walker checks descriptor encoding, leaf permissions,
supervisor/user separation, user W^X, protected-frame exclusion, canonical virtual
addresses, and agreement with the declared mapping plan. Exact SHA-256 acceptance
through the human-only `promote-riscv-sv39-plan` command and its post-promotion
replay mint `RISCV_SPATIAL_ISOLATION_PROVED`, scoped to
`reviewed_qemu_virt_sv39_descriptor_and_walk_model`. Hardware page-walk semantics,
TLB coherence, compiled MMU code, and physical isolation remain explicitly locked.

M91.4 introduces an S-mode-only AIA/APLIC/IMSIC routing policy with two harts,
explicit source ownership, exact interrupt identities and IMSIC addresses, a
disabled source, and initial/reconfigured route epochs. Its exact policy hash was
accepted through the human-only `promote-riscv-aia-policy` command. The
post-promotion TLC replay verified 37 states and minted the narrowly scoped
`RISCV_INTERRUPT_ROUTING_MODEL_PROVED`; five bound behavioral mutations remain
rejected. VS-mode,
QEMU/hardware delivery semantics, implementation refinement, physical routing,
and interrupt latency remain outside this step.

M91.5a is separately staged as a two-guest HS/VS privilege-transition candidate.
It binds distinct VMIDs and reviewed context identities and covers preparation,
VS entry, guest trap, validated HS dispatch, hostile cross-guest selection, and
VS resume. TLC verified 15 states and rejected four semantic mutations. The
exact candidate was human-promoted and its post-promotion TLC replay minted
`RISCV_GUEST_PRIVILEGE_TRANSITION_MODEL_PROVED`. G-stage translation, guest IMSIC
routing, QEMU semantics, and physical execution remain separate milestones.

M91.5b stages a reviewed-candidate Sv39x4 ownership plan. It models two disjoint
guest SPA domains, HS-protected 16-KiB-aligned roots, guest-owned VS page-walk
memory, distinct active VMIDs under an explicit seven-bit QEMU-model assumption,
and epoch-based HFENCE.GVMA requirements after translation-context changes. TLC
verified the 28-state lifecycle and rejected missing-fence, wrong-root, and Bare
mode mutations. Exact-hash human promotion and post-promotion replay minted
`RISCV_G_STAGE_ISOLATION_PROVED` while leaving hardware walk, TLB coherence,
compiled `hgatp`, QEMU semantics, and physical isolation outside the claim.

### M92 — CHERI capability-hardware profile

Introduce experimental `FK-CHERI` support for pure-capability code, sealed
kernel objects, capability-aware IPC and DMA, and temporal revocation.

- Proposed claims: `HARDWARE_CAPABILITY_BOUNDS_PROVED`,
  `CAPABILITY_PROVENANCE_PRESERVED`, and `KERNEL_POINTER_FORGERY_BLOCKED`.
- CHERI configuration alone never mints software memory safety.
- Software-to-hardware capability correspondence requires its own judge.

### M93 — confidential-computing kernel

Provide separate TDX, SEV-SNP, and later Arm CCA profiles for measurement,
attestation, launch, page acceptance, and runtime private-page accounting.

- Proposed claims: `CONFIDENTIAL_GUEST_POLICY_PROVED`,
  `ATTESTATION_STATE_MACHINE_PROVED`, and
  `PRIVATE_PAGE_ACCOUNTING_PROVED`.
- Hardware threat models, firmware, attestation roots, and vendor semantics are
  explicit assumptions, not software theorems.

### M94 — CXL coherent and disaggregated memory

Model hot-add/remove, tiered and shared memory, device ownership, poison,
migration, and remote-memory failure under a pinned CXL specification.

- Proposed claims: `CXL_MEMORY_OWNERSHIP_PROVED`,
  `CXL_HOTREMOVE_SAFETY_PROVED`, `MEMORY_TIER_ACCOUNTING_PROVED`, and
  `POISON_PROPAGATION_CONTAINED`.
- Fabric/device conformance and physical failure delivery remain validation
  obligations.

### M95 — accelerator isolation

Generalize M79 to GPU, NPU, FPGA, SmartNIC, and DPU devices using PASID,
IOMMU domains, queue grants, shared virtual memory, and reset epochs.

- Proposed claims: `ACCELERATOR_DMA_ISOLATION_PROVED`,
  `DEVICE_RESET_EPOCH_SAFETY_PROVED`, and
  `SHARED_VIRTUAL_MEMORY_POLICY_PROVED`.
- Accelerator firmware and physical IOMMU enforcement remain separate.

## Phase 10 — verified scale and performance (M96–M100)

### M96 — scalable VM, cache, and reclaim

Extend M77 with buddy/per-node allocation, huge pages, COW, mmap, page cache,
dirty/writeback state, reclaim, migration, pressure, and NUMA balancing. Use
compositional ownership/accounting invariants rather than whole-server model
checking.

- Proposed claims: `DYNAMIC_VM_REFINEMENT_PROVED`,
  `PAGE_CACHE_ACCOUNTING_PROVED`, and `NUMA_MIGRATION_SAFETY_PROVED`.
- The current three-process/two-node theorem is not evidence for arbitrary
  populations or native implementation refinement.

### M97 — full RCU and scalable synchronization

Close M71 for preemptible RCU, IRQ/NMI readers, per-CPU epochs, hotplug,
callback pressure, expedited grace periods, weak memory, and exact source/model
correspondence. Add sequence locks, per-CPU counters, scalable reference counts,
and a lock-free hash table.

- Proposed claims: `RCU_IMPLEMENTATION_REFINEMENT_PROVED`,
  `RCU_FORWARD_PROGRESS_PROVED`, and `RCU_WEAK_MEMORY_SAFETY_PROVED`.
- A relational concurrency logic such as
  [ReLoC](https://iris-project.org/reloc/) is a candidate judge.

### M98 — topology-aware SMP scheduler

Extend M78 with SMT/cache/NUMA topology, load balancing, affinity, hotplug,
isolated CPUs, latency classes, mixed-criticality reservations, and energy-aware
placement.

- Proposed claims: `SMP_SCHEDULER_IMPLEMENTATION_REFINEMENT_PROVED`,
  `CPU_HOTPLUG_CONSERVATION_PROVED`, and
  `SCHEDULER_TEMPORAL_SERVICE_PROVED`.
- `FK-Safety` retains a restricted scheduler; `FK-Scale` receives a distinct,
  weaker timing envelope.

### M99 — asynchronous zero-copy I/O

Specify submission, admission, execution, cancellation, and exactly-once
completion before designing the API. Prove descriptor uniqueness, pinned-memory
bounds, buffer lifetime, capability scope, and absence of stale DMA after
cancellation.

- Proposed claims: `ASYNC_IO_LEDGER_PROVED`,
  `ZERO_COPY_BUFFER_LIFETIME_PROVED`, and
  `IO_CANCELLATION_ATOMICITY_PROVED`.
- Linux io_uring is a performance comparison point, not imported evidence.

### M100 — proof-carrying programmable datapath

Build a restricted eBPF-like VM whose programs carry termination, memory,
pointer/capability, packet-bound, helper-authority, and resource-budget
obligations.

- Proposed claims: `DATAPATH_PROGRAM_SAFETY_PROVED`,
  `DATAPATH_RESOURCE_BOUND_PROVED`, and
  `DATAPATH_CAPABILITY_CONFINEMENT_PROVED`.
- Admission must check a certificate or run the trusted verifier; extension
  authors and AI systems are never judges.

## Phase 11 — general-purpose OS closure (M101–M105)

### M101 — x86-64 ring-3 refinement

Close `DESKTOP_X86_PROCESS_ENTRY_REFINEMENT_PENDING` with an ELF64 loader,
canonical-address checks, syscall/sysret or interrupt entry, FS/GS handling,
per-process page tables, XSAVE/XRSTOR policy, and signal-frame setup.

- Proposed claims: `X86_PROCESS_ENTRY_REFINEMENT_PROVED` and
  `X86_SYSCALL_TRANSITION_PROVED`.
- This must use x86 semantics; the AArch64 M57/M62 evidence is inapplicable.

### M102 — serious POSIX compatibility

Expand M85 in waves: core file/memory calls; fork/exec/wait, futex, signals and
polling; then sockets, pipes, PTYs, credentials, and clocks.

- Empirical claims: `POSIX_CORE_CONFORMANCE_TESTED` and
  `LINUX_ABI_SUBSET_TESTED`.
- A semantic claim is eligible only for a separately specified and proved
  subset. Test counts never become deductive proof.

### M103 — containers and resource domains

Add process, mount, network, and user namespaces plus CPU, memory, and I/O
resource groups built on existing quota accounting.

- Proposed claims: `CONTAINER_RESOURCE_ISOLATION_PROVED` and
  `NAMESPACE_AUTHORITY_NONINTERFERENCE_PROVED`.
- Host-kernel implementation and hardware enforcement require explicit edges.

### M104 — advanced storage semantics

Extend M72 to rename, unlink, fsync, directory persistence, mmap/writeback,
snapshots, COW trees, checksums, and metadata replication.

- Proposed claims: `FSYNC_PERSISTENCE_CONTRACT_PROVED`,
  `ATOMIC_RENAME_CRASH_SAFETY_PROVED`, and
  `SNAPSHOT_CONSISTENCY_PROVED`.
- Every claim must name its persistence contract and device assumptions.

### M105 — fault-isolated driver framework

Run drivers as disposable processes with a bounded capability set, IOMMU
domain, queue grant, reset epoch, and supervisor. Support representative NVMe,
virtio, Ethernet, USB, PCIe enumeration, and display-control paths without
pretending to verify every device firmware implementation.

- Proposed claims: `USER_DRIVER_FAULT_CONTAINMENT_PROVED`,
  `DRIVER_CAPABILITY_CONFINEMENT_PROVED`, and
  `DEVICE_RESET_RECOVERY_MODEL_PROVED`.

## Phase 12 — resilience and operations (M106–M110)

### M106 — verified live update

Specify old state, a state transformer, new state, rollback, and the invariants
that must survive service, driver, or selected kernel-component updates.

- Proposed claims: `LIVE_UPDATE_STATE_REFINEMENT_PROVED` and
  `ROLLBACK_STATE_SAFETY_PROVED`.
- Code replacement without state refinement is not a verified update.

### M107 — reproducible and hermetic builds

Bind source, dependency locks, compiler, judges, linker, environment, and output
hashes. Compare outputs from independent clean builders where deterministic
tooling permits it.

- Evidence claims: `REPRODUCIBLE_BUILD_OBSERVED` and
  `BUILD_PROVENANCE_COMPLETE`.
- Permanently forbid `BUILD_CORRECTNESS_PROVED` from reproducibility alone.

### M108 — proof-carrying remote attestation

Attest the binary, deployment/hardware profile, proof-bundle root, judge
versions, assumptions, and pending set—not only a PCR measurement.

- Proposed claim: `ATTESTED_EVIDENCE_BUNDLE_BOUND`.
- This composes M81, M90, and M93 but does not prove vendor attestation
  hardware or verifier policy correct.

### M109 — systematic fault campaigns

Extend M83 to repeated and simultaneous faults, DMA timeout, CPU loss, poison,
journal crash, network partition, storage reset, and restart loops. Keep formal
models and physical injection results distinct.

- Proposed theorem: `MULTIFAULT_RECOVERY_MODEL_PROVED`.
- Empirical result: `FAULT_INJECTION_CAMPAIGN_PASSED`.

### M110 — trustworthy observability

Verify bounded tracing, loss accounting, capability-controlled access,
kernel-pointer redaction, and crash-dump confidentiality.

- Proposed claims: `TRACE_RESOURCE_BOUND_PROVED`,
  `CRASH_DUMP_POLICY_PROVED`, and `OBSERVABILITY_NONINTERFERENCE_PROVED`.
- Production completeness and operator tooling remain conformance evidence.

## Phase 13 — high-assurance multicore (M111–M115)

### M111 — mixed-criticality scheduling

Add temporal budgets, replenishment, criticality classes, mode switching, and
temporal isolation.

- Proposed claims: `TEMPORAL_PARTITIONING_PROVED` and
  `MIXED_CRITICALITY_MODE_SWITCH_PROVED`.
- Timer delivery and hardware timing assumptions must remain visible.

### M112 — physical multicore-interference closure

Close M71.5 using authenticated cache, DRAM, interconnect, DMA, IRQ, and SMT
measurements and conservative target-specific inflation factors.

- Validation claim: `TARGET_WCET_INTERFERENCE_BOUND_VALIDATED`.
- Forbidden overclaim: `MULTICORE_INTERFERENCE_ELIMINATED`.

### M113 — hardware-error timing and recovery

Integrate ECC, machine checks, cache/bus errors, thermal throttling, frequency
transitions, and watchdog policy. Safety configurations must prohibit
uncontrolled timing features.

- Proposed claims: `SAFETY_HARDWARE_MODE_CONFIGURATION_PROVED` and
  `HARDWARE_ERROR_RECOVERY_MODEL_PROVED`.
- Physical delivery and timing measurements remain hardware evidence.

### M114 — integrated safety/security assurance

Check policy consistency across WCET, speculative mitigations, isolation,
cryptography, availability, and watchdog response.

- Proposed claim: `SAFETY_SECURITY_POLICY_COMPATIBILITY_PROVED`.
- It proves compatibility of declared policies, not universal security or
  physical timing.

### M115 — certification evidence packages

Generate distinct DO-178C/DO-330, IEC 61508, ISO 26262, and security-evaluation
packages from profile-applicable evidence.

- Evidence names: `<STANDARD>_EVIDENCE_PACKAGE_COMPLETE`.
- `AUTHORITY_ACCEPTANCE_PENDING` remains until the relevant authority accepts
  the system-specific package. Never mint `CERTIFIED_OS` internally.

## Phase 14 — research frontier (M116–M120)

### M116 — proof-carrying kernel extensions

Require privileged extensions to carry code, contract, resource bounds, and a
certificate checked before admission.

- Proposed claim: `EXTENSION_CERTIFICATE_VALIDATED`.
- Certificate validation is scoped to the supported logic and checker.

### M117 — temporal memory safety

Combine Rust ownership, generational handles, epoch reclamation, DMA lifetime,
and optional CHERI revocation against use-after-free, ABA, stale authority, and
reuse after destruction.

- Proposed claims: `TEMPORAL_MEMORY_SAFETY_PROVED` and
  `STALE_CAPABILITY_REUSE_BLOCKED`.
- Unsafe and device boundaries must participate; safe Rust alone is
  insufficient.

### M118 — verified confidential service domains

Build small key-management, secrets, attestation, and update-authority services
inside TDX/SNP/CCA-style domains.

- Proposed claims: `CONFIDENTIAL_SERVICE_REFINEMENT_PROVED` and
  `HOST_COMPROMISE_AUTHORITY_BOUND_PROVED`.
- Claims are conditional on a pinned hardware threat model.

### M119 — proof-directed synthesis

Permit AI to propose code, invariants, lemmas, configurations, and repairs in a
counterexample-guided loop. Deterministic translators and formal tools remain
the judges; humans retain control of assumptions and trust promotion.

- Evidence claim: `AI_ASSISTED_ARTIFACT_JUDGED`.
- Permanently forbidden: `AI_PROVED_CORRECT`.

### M120 — evidence-carrying operating system

Compose a signed deployment root over the kernel binary, source identities,
reviewed specifications, refinement/concurrency proofs, hardware profile,
MMU/IOMMU configuration, timing and mitigation evidence, tool provenance,
assumptions, and pending claims. Updates must preserve the root or explicitly
declare its changed assurance envelope.

- Final scoped claim: `DEPLOYMENT_EVIDENCE_ROOT_VALIDATED`.
- Permanently forbidden: `FORMALKERNEL_COMPLETELY_PROVED`.

## Profile ambitions at M120

| Profile | Final ambition |
| --- | --- |
| `FK-Safety` | Single/few-core deterministic, bounded, certification-oriented kernel |
| `FK-Secure` | Capability-first microkernel with foundational and information-flow refinement |
| `FK-Scale` | 64–256+ core NUMA/CXL system with RCU, dynamic VM, and async zero-copy I/O |
| `FK-Desktop` | x86-64 process environment, POSIX/Linux subset, and user-mode drivers |
| `FK-Lab` | CHERI, confidential computing, proof-carrying extensions, and experimental judges |

Features and claims do not transfer automatically between profiles. A mechanism
permitted in `FK-Scale` may remain a contradiction in `FK-Safety`.

## First-priority sequence

1. M76.3–M76.5 — finish the end-to-end refinement spine.
2. M86 — foundationally verify selected actual Rust kernel modules.
3. M101 — close x86-64 ring-3 and process-entry refinement.
4. M87/M97 — connect concurrency proofs to actual weak-memory implementations.
5. M92 — introduce CHERI as an experimental profile.
6. M96 — build scalable VM, page-cache, and reclaim refinement.
7. M99 — specify and verify asynchronous zero-copy I/O.
8. M105 — isolate and supervise drivers rather than claiming them verified.
9. M108 — bind evidence into remote attestation.
10. M112 — obtain real multicore-interference evidence.

## Governing claim discipline

| Dimension | Target discipline |
| --- | --- |
| Functional assurance | Compete with machine-checked refinement, not claim count |
| Systems language | Foundationally cover the accepted safe and unsafe Rust subset |
| Concurrency | Parameterized algorithms plus implementation-level weak-memory edges |
| Memory security | Compose Rust, software capabilities, DMA lifetimes, and optional CHERI |
| Scale | Use NUMA/CXL/RCU/local invariants rather than whole-server state spaces |
| Isolation | Compose MMU, IOMMU, capabilities, virtualization, and confidential computing |
| Extensibility | Admit privileged code only with checked contracts and resource certificates |
| Operations | Preserve evidence through builds, updates, and remote attestation |
| Safety | Bind deterministic profiles to measured multicore-interference evidence |
| AI | Use synthesis and repair; never include AI in the trusted judge set |

The destination is an evidence-carrying operating system: each deployment can
state which properties survive from specification to implementation, binary,
hardware configuration, and running machine—and which remain pending.

## Research and specification references

- [seL4 development roadmap](https://sel4.systems/roadmap.html)
- [seL4 news](https://sel4.systems/news/2026.html)
- [RefinedRust](https://plv.mpi-sws.org/refinedrust/)
- [Verus overview](https://verus-lang.github.io/verus/guide/overview.html)
- [CHERI technology](https://cheri-alliance.org/discover-cheri/)
- [CHERI adoption study](https://cheri-alliance.org/adoption/)
- [RISC-V specifications](https://docs.riscv.org/)
- [Intel TDX overview](https://cdrdv2-public.intel.com/856790/Intel%20Trust%20Domain%20Extensions%20Overview%20-%20June%202025.pdf)
- [AMD SEV-SNP overview](https://www.amd.com/content/dam/amd/en/documents/epyc-business-docs/white-papers/SEV-SNP-strengthening-vm-isolation-with-integrity-protection-and-more.pdf)
- [CXL specifications](https://computeexpresslink.org/cxl-specification/)
- [ReLoC](https://iris-project.org/reloc/)
- [Linux io_uring zero-copy receive](https://docs.kernel.org/networking/iou-zcrx.html)
- [Linux eBPF verifier](https://docs.kernel.org/6.14/bpf/verifier.html)
- [Microsoft Practical System Verification publications](https://www.microsoft.com/en-us/research/project/practical-system-verification/publications/)
