# FormalKernel — the Formally Governed Kernel (M41–M85, including M71.5 and active M76.3)

TDD plan for building a hybrid-kernel development flow on top of the
M36–M40 OS verification framework. Governing rule, unchanged: *The LLM
proposes; deterministic compilers transform; formal tools judge; humans
control trusted assumptions.*

This document records implemented work through M85. The prospective Gate 0 and
M86–M120 program is maintained separately in
[`FORMALKERNEL_M86_M120_ROADMAP.md`](FORMALKERNEL_M86_M120_ROADMAP.md); its
claims are proposals and are not part of the current evidence ledger.

The kernel is not one artifact — it is an **evidence lattice** over
subsystems (scheduler, VFS, network), each extracted from legacy C,
bounded, lowered to Rust, and judged layer by layer, then composed.

## Judge-availability matrix (host-probed 2026-08-19)

| Judge | Status | Consequence |
|---|---|---|
| Z3, TLC, Prusti, ESBMC, Frama-C, rustc, objdump, gcc | installed | real proofs / real toolchain gates |
| RC11/herd7, aiT, SPIN, CN, Kani, Iris, Aeneas | absent | `judge_pending` ceilings; never minted |
| TLC scheduler fairness | no fairness constraints in the wrapper | `human_accepted_assumption` |

## Blueprint corrections (probe findings, honored throughout)

The source blueprint over-claims four points; this plan implements the
honest versions:

1. **"objdump + CFG analyzer (WCET)"** — did not exist at M38; M38's
   bound is source-level (loop-trip analysis under the cost model).
   M44 adds the real binary-level path: `rustc --emit=obj` →
   `objdump -d` → CFG longest path. Binary path is the upgrade and the
   default when the toolchain is present; the source bound remains the
   fallback, with `wcet_method` recording which judge produced it.
2. **"exactly one `_Atomic` read-modify-write step"** — the probed ESBMC
   dialect is PLAIN shared ints (no C11 atomics bodies); the
   linearization gate demands exactly ONE single-word store per
   operation. Rust `core::sync::atomic` code is judged through a C
   witness harness; the correspondence is structural and recorded as
   such. `LOCK_FREE_LINEARIZABILITY_PROVED` scopes to
   `concurrent_interleaving_bmc` over that witness — never to the Rust
   binary directly.
3. **"gcc -O2, compile the Rust"** — Rust compiles with `rustc`, not
   gcc; the plan's toolchain is `rustc --emit=obj` + binutils.
4. **Hardening strategies** — `checked-math` (CWE-190), `lock-timeout`
   (CWE-667), `fail-safe` (CWE-617) already exist in
   `behavior_correction`/`correction_router` (probed). M42 pins them
   for kernel-shaped candidates rather than re-implementing.

Also inherited honestly: `LIVENESS_PROVED` is bounded-structural with
scheduler fairness as the human assumption (no TLC fairness constraints
are emitted today); SPIN LTL stays `judge_pending`.

## Phase → milestone map

| Blueprint phase | Milestone | Artifact / gate / claim |
|---|---|---|
| 1. Trust roots | **M41** `pipeline/hardware_profile.py` | human-owned `hardware_profile.json` → deterministic `safe_capacity = usable_sram × 0.9 ÷ struct_size` per subsystem; kernel pool SRAM ranges pairwise disjoint (M39 arithmetic) → `HARDWARE_PROFILE_DERIVED` |
| 3. Bounding + hardening | **M42** | the three hardening strategies pinned on kernel-shaped V2 candidates via `correct-behavior --strategy … --cwe CWE-19x` |
| 4. Five-layer lattice, multi-arch | **M43** `pipeline/kernel_lattice.py` + CLI `verify-kernel` | per-profile runs of the M36–M39 gates → scope-tagged evidence bundle (`BARRIER_CORRESPONDENCE_PROVED scope x86_tso / armv8_sc`; WCET per cost model; DMA per memory map) |
| 4 layer 4 upgrade | **M44** `pipeline/wcet_binary.py` | real `rustc --emit=obj` + `objdump -d` CFG longest path under the human cost model → `WCET_BOUND_PROVEN scope binary_cfg`; `DEADLINE_MISSED` fail-closed |
| 6. Driver boundary | **M45** | `implement <driver>.rs --dependencies` on a kernel adapter → `UNVERIFIED_EXTERNAL_ADAPTER`, `external_io_safety_proved: false`, DmaContract re-checked at adapter call sites |

Phases 2 (Rosetta extraction + M40 dialects) and 5 (composition via
`compose --lang rust`) already exist — the plan uses them as-is and M43
chains their claims into the bundle.

## Milestones

### M41 — hardware trust roots

Artifact: `hardware_profile.json` — `{target, memory_model,
total_sram_bytes, reserved_system_bytes, word_size_bytes, cost_model?,
subsystems: {name: {struct_size_bytes, sram_base?}}}` — **human-owned**.
Deterministic derivation: `usable = total - reserved`;
`safe_capacity = floor(usable × 0.9 / struct_size)`; pool SRAM windows
`[sram_base, sram_base + capacity×struct_size)` must be pairwise
disjoint and inside usable SRAM. Fail-closed: `profile_missing`,
`profile_field_missing` (never guessed), `sram_overlap` naming the two
subsystems, `pool_outside_sram`. Claim `HARDWARE_PROFILE_DERIVED`,
ownership `human_declared_hardware_profile`. The capacity feeds the
existing M30 bounded-pool clamp.

Tests: derivation math (0.9 factor, floor, disjoint windows); every
residual named; a two-pool overlap refused; the capacity integrates
with `correct-behavior --hardware`.

### M42 — hardening strategies on kernel candidates

`checked-math` / `lock-timeout` / `fail-safe` exist (probed); pin them
end-to-end on a kernel-shaped V2 candidate: strategy residuals
eliminated, Z3 inductiveness preserved, claims recorded per strategy
CWE. No new module — tests + any router glue that the probe shows
missing.

Tests: each strategy rewrites its idiom (checked ops / timeout
transition / SAFE_STATE) and the bounded invariant still proves;
router maps CWE-190/667/617 to the strategy only when the idiom is
present (a CWE-190 request on unbounded-loop code must NOT silently
pick checked-math).

### M43 — the multi-architecture evidence lattice

`pipeline/kernel_lattice.py` + CLI `verify-kernel KERNEL_DIR
--profiles PROFILES_DIR [--json]`. Inputs: kernel sources
(`*.rs`/witness `*.c`), M41 profiles. For each profile: weak-memory gate
under `profile.memory_model`; WCET under `profile.cost_model` +
`timing.max_cycles`; DMA against `profile.memory_map`; lock-free over
witness harnesses. Output bundle:

```
{status: KERNEL_EVIDENCE_BUNDLE, claims: [
   {claim: BARRIER_CORRESPONDENCE_PROVED, scope: x86_tso, profile: n150},
   {claim: BARRIER_CORRESPONDENCE_PROVED, scope: armv8_sc, profile: r52},
   {claim: WCET_BOUND_PROVEN, scope: static_cfg_cost_model_aarch64, ...},
   ...]}
```

Rules: a failing lane marks the bundle `KERNEL_VERIFICATION_FAILED`
with the named refusal (never a silent scope drop); absent judges stay
`judge_pending` inside each entry; the architecture-agnostic claims
(refinement, lock-free over the witness) are listed once, not per
profile.

Tests: two-profile bundle carries both scopes; a racy source fails the
whole bundle by name; missing profile field fails closed; scope
deduplication.

### M44 — binary-level WCET

Probe-first: `rustc --emit=obj` a no_std-shaped function, `objdump -d`,
parse `jmp/je/jne/…` targets into a CFG, longest path weighted by the
human cost model per mnemonic class. Unresolved indirect branches →
`WCET_UNBOUNDED_INDIRECT` (never guessed); loops in the binary → trip
counts come only from declared `loop_bounds`. Toolchain absent → the
M38 source bound, `wcet_method` recording the fallback. Claim
`WCET_BOUND_PROVEN scope binary_cfg_<target>`.

Tests: real rustc+objdump round-trip (skipif not installed) proving a
bounded loop's path cost; an indirect call refused; declared
`loop_bounds` respected; the fallback path pinned.

### M45 — the driver boundary

`implement <driver>.rs --dependencies` gains a kernel-adapter path
beyond the fixed SDK list: the adapter stub carries the existing
`UNVERIFIED EXTERNAL BOUNDARY` marker; the result is compiled
(static check only) and stamped `UNVERIFIED_EXTERNAL_ADAPTER`,
`external_io_safety_proved: false`, `port_interface: immutable`. Every
`dma_map`/`ioremap` in the adapter is re-checked against the declared
DmaContract — glue code may not widen a device's contract. The
`implement` lane never mints a proof claim for adapter code.

Tests: adapter verdict shape; contract violation refused by name; Port
signature mutation detected (`TRUST_BOUNDARY_VIOLATION`); the fixed
SDK choices still work.

## Shipped beyond the original plan (M46–M54)

### M46 — kernel composition (v9.1)

`pipeline/kernel_composition.py`: a boot-orchestration artifact
(`steps: [{name, requires, establishes}]`) is checked by deterministic
precondition flow — a step whose `requires` facts no earlier step (or
itself) establishes refuses `COMPOSITION_PRECONDITION_UNMET` naming
both; re-establishing an established fact refuses
`COMPOSITION_FACT_REESTABLISHED`; duplicate step names refuse. Claim
`SYSTEM_COMPOSITION_PROVED`, scope `deterministic_precondition_flow` —
an orchestration-order claim, not a concurrency claim. Wired as the
lattice `composition` lane.

### M47 — live QEMU boot with proven order (v9.2)

The composed boot order stops being a JSON artifact: an aarch64
bare-metal image (`examples/formalkernel/boot/`) boots on
`qemu-system-aarch64` following exactly the M46-proven step order,
printing a boot transcript. The transcript-observed order must match
the proved order or the run fails.

### M48 — MMU spatial isolation (v9.3)

`pipeline/mmu_isolation.py`: page-table artifacts (per-frame base,
descriptor bits) are judged for kernel/user separation — bit 54 UXN on
user frames, AP bits permitting EL0 access only where declared — and
`walker paper-decode`: the kernel's page-table walker runs against the
same descriptors and must land where the artifact says. Claim
`SPATIAL_ISOLATION_PROVED` (deterministic gate over the descriptor
math). Live: a user wild store traps into the kernel with a named
fault (`USER_TRAP far=...`), contained.

### M49 — syscalls: the EL0 boundary (v9.4)

`pipeline/syscall_dispatch.py` + the `syscalls` lattice lane: an
aarch64 svc dispatch-table artifact (immediate → handler → capability)
is judged for total dispatch (every declared immediate answers, no
undeclared one fires) — claim `SYSCALL_BOUNDARY_PROVED`, judge_pending
`hardware_exception_level_transition` (the EL1↔EL0 trap itself is
hardware, honestly not machine-proved). Live: `svc #0x64` answered at
EL0; a user abort contains as `USER_TRAP`.

### M50 — the IPC name server (v9.5)

`pipeline/mpsc.py` (`verify_mpsc`) + `pipeline/ipc_nameserver.py`: a
partitioned-lane MPSC witness (one bounded slot-array per producer
lane, plain-int SC dialect) proves per-lane capacity and the TOTAL
posted+dropped ledger under ESBMC interleaving; the endpoint-table
gate routes cross-artifact messages through the M49 dispatch table.
Claims `MPSC_BOUNDED_PARTITION_PROVED`, `IPC_ENDPOINT_TABLE_PROVED`.
ESBMC budget: 2 producers ≈ seconds, 3 threads ≈ minutes.

### M51–M52 — user-space net stack, then respawn (v9.6/v9.7)

The network server moves to EL0 (svc #0x66 poll loop over the shared
bounded pool). Live: a wild store in the server kills it
(`NET_SERVER_KILLED`) while the kernel closes the packet ledger
exactly (`posted == served + reclaimed + kernel-held`) and survives;
M52 re-initializes the server's frames (zeroed, image re-copied,
SP_EL0 reset) and a second generation serves with its own closed
ledger. Vacuity refusals (`net_server_poll_vacuous`,
`NETSRV_LEDGER_OPEN`) keep the ledger claim honest.

### M53 — the Kani refinement lane (v9.8)

`pipeline/kani_refinement.py`: the image's own `witness.rs`
(Ring/Mpsc) is `#[path]`-included by `boot/proofs/` — not copied — and
Kani proves capacity invariants, backpressure accounting, and the
exact ledger identities over bounded nondeterministic sequences.
`WITNESS_LINK_MISSING` refuses a proof over a copy. Claim
`RUST_WITNESS_REFINEMENT_PROVED`, judge `kani`; concurrent
interleaving stays with ESBMC.

### M54 — deployment profiles (v9.9)

`pipeline/deployment_profile.py`: one tree, explicit scoped bundles, no
code fork. The root manifest declares its deployment; a monolith
carrying any boundary lane (mmu/syscalls/ipc) refuses
`MONOLITH_BOUNDARY_CONTRADICTION`. `verify-kernel --manifest
monolith.json` originally minted the 19-claim M54 monolithic bundle (boundary claims
omitted; the note says the driver is the kernel — containment does not
exist) from the same sources as the original 24-claim microkernel bundle. The
anti-drift guarantee is a test: every shared claim is the byte-identical
tuple. M60 introduces one deliberate, registry-declared divergence:
microkernels mint the EL0 preemption scope while monoliths mint only the
cooperative EL1 chunk bound.

After M85 the same anti-drift test covers five executable manifests. Current
fully judged counts are microkernel 66, monolith 54, unikernel 53, Safety 31,
and Desktop 41. Counts describe scoped evidence entries, not comparative
assurance scores.

### M55 — VFS portability lane (deliverables 1–2 of 4)

`domains/candidates/vfs.v2.yaml` is the unreviewed bounded inode-cache
candidate. Its four operations (`open`, `close`, `read`, `write`) preserve a
four-inode pool through the explicit `inode_count + free_list_head = 4`
conservation invariant; `close` is the recycle path. Deterministic traversal
currently reaches 123 states and 492 transitions within a 6,375-state ceiling.

This deliverable mints **no claim** and publishes no validation envelope. The
capability registry fixes `M55_vfs` at step 1 and maturity `scaffold`; doctor
shows `BOUNDED_ARCHITECTURE_EVIDENCE`, `SOURCE_MODEL_REFINEMENT`, and
`HARDWARE_MEMORY_BOUND_PROVED` as locked. Real TLC plus human promotion belong
to deliverable 3. Rust/Prusti refinement and the hardware-bound proof belong to
deliverable 4; only that final hash-bound gate may transition the lane to
`production`.

Deliverable 2 adds a repository-local synthetic legacy-C fixture under
`tests/fixtures/legacy_vfs`. `analyze-codebase` joins the header declaration
and C operations, derives the declared capacity of four, and translates
`list_add`/`list_del` into bounded `size` effects. It separately refuses the
RB-tree, hash-bucket, and pointer-to-pointer alias shapes with
`UNBOUNDED_STATE_REQUIRES_MANUAL_REVIEW`. The human mapping record at
`domains/candidates/vfs.legacy-mapping.yaml` explains which scalar state
represents occupancy and which semantics remain outside the candidate. It is
itself `unreviewed`, carries `NO_PROOF`, and keeps all three M55 claims locked.

Deliverable 3 ran real TLC 2.19 against candidate SHA-256
`4e6af210144c55aa71df996c02a16ec58e6639e615fb17a6fcc9310637215132`.
The hash-bound envelope records 123 reachable states, 492 transitions, a
6,375-state ceiling, and TLC exit status zero. Explicit human promotion wrote
the separate reviewed artifact `domains/v2/vfs.json`; the lane is now Step 3
and `bounded-evidence`. Only `BOUNDED_ARCHITECTURE_EVIDENCE` is available.
`SOURCE_MODEL_REFINEMENT`, `HARDWARE_MEMORY_BOUND_PROVED`, and `production`
remain locked behind Deliverable 4.

Deliverable 4 is complete. The corrected hardware lane distinguishes the
four-element logical inode pool from the profile-derived safe ceiling of
6,912 elements. Real Z3 4.8.12 proved that the 64-byte pool cannot exceed the
110,592-byte SRAM safety budget; the encoding hash is
`b3854651fb9b023f0991c0f044a88c9f41bd8ed01437a5a479a3f1e2b9e23a19`.
Real TLC then revalidated candidate
`0f5ca07b2412edc5056744ea69563aae161484602c1d595f8c353ac0481687f4`
at 123 states / 492 transitions before explicit replacement promotion.
Deterministic Rust lowering materializes `slots: [bool; 4]`; Prusti 0.2.2
verified all 9 items and all four action refinements under certificate
`140a92d89c0b45714088ec7febb1aafeabc8e2572d422d119b34769d19e50687`.
The lane is `production` with all three claims available. Both deployment
manifests include the fail-closed VFS formal-domain bundle; full verification
produces 27 microkernel and 22 monolithic entries, including the TLC, Prusti,
and Z3 VFS claims.

### M56 — confined virtio-blk driver boundary

`examples/formalkernel/kernel/vfs/virtio_blk.rs` is a rustfmt-clean,
statically checked EL0 adapter with a two-request admission bound. It is
permanently marked `UNVERIFIED EXTERNAL BOUNDARY`: virtio device semantics,
interrupt delivery, and external I/O correctness are not proved. The adapter
receives only a `BlockSyscall` capability and buffer identifiers, never a
physical address.

The mechanical claims live around it. Syscall 103 names only the kernel-owned
`blk_ring`; the storage IPC endpoint receives two statically partitioned MPSC
slots; and `virtio_blk_dma.c` maps one literal 512-byte request within each
profile's `blk_dev` contract, disjoint from every kernel pool. `verify-kernel`
hashes and statically checks the adapter before emitting the boundary marker.
The microkernel bundle reports `UNVERIFIED_EXTERNAL_ADAPTER` plus its DMA,
syscall, and IPC confinement claims. The monolith honestly reports
`UNVERIFIED_IN_KERNEL_DRIVER`, no syscall/IPC containment, and that an
in-kernel driver fault may crash the kernel.

### M57 — bounded ELF process loader

The microkernel manifest binds `elf_loader.json` to the production VFS read
capability and to a panic-free Rust ELF64/AArch64 parser. The parser accepts at
most four `PT_LOAD` entries, checks all offset arithmetic, rejects overlapping
segments and writable-executable mappings, and requires the entry point to lie
inside executable memory. The deterministic gate maps ELF `PF_X`/`PF_W` flags
exactly to M48 `UXN`/`AP` declarations and reuses spatial-isolation range
arithmetic for every hardware profile.

The resulting `ELF_SEGMENT_LAYOUT_PROVED` and
`ELF_PERMISSION_CORRESPONDENCE_PROVED` claims cover bounded parsing and the
declared mapping plan only. Hardware page-table walking and the `ERET`
EL1-to-EL0 transition remain named `judge_pending` boundaries for M62. The
monolithic manifest cannot carry this lane and records
`EL0_PROCESS_LOADER_OMITTED` instead of minting user-process claims.

### M58 — bounded post-quantum TLS pool

The shared network subsystem declares the byte footprint of its ML-KEM-768,
ML-DSA-65, and TLS workspace inputs in `net/pq_tls.json`. Each hardware target
owns a 49,152-byte TLS budget. A real Z3 query proves that two aligned 22,208-byte
sessions fit (44,416 bytes) and that a third cannot fit (66,624 bytes), making
two the exact concurrent-handshake ceiling rather than a heuristic bound.

The hash-bound Rust admission ledger contains exactly two static slots and
returns `ERR_MEM` after they are occupied. Both deployment bundles mint a
profile-scoped `HARDWARE_MEMORY_BOUND_PROVED` entry. The `liboqs` adapter remains
outside the proof boundary with `cryptographic_strength_proved: false` and
`liboqs_implementation_proved: false`; this lane proves resource containment,
not ML-KEM/ML-DSA security or third-party implementation correctness.

### M59 — bounded cryptographic handshake state machine

The Rosetta lane binds a five-state mbedTLS-style C control-flow fixture to a
deterministically rendered TLA+ model. Real TLC 2.19 explores five distinct
states (nine generated states) and checks deadlock freedom, initialized-state
safety, and weak-fair terminal reachability. Both successful establishment and
explicit failure are terminal outcomes; the model never assumes an opaque
cryptographic operation succeeds.

The published TLC envelope binds the source SHA-256 and generated-TLA SHA-256.
Both deployment bundles receive `BOUNDED_ARCHITECTURE_EVIDENCE` for the shared
control graph. `TLS_TRANSCRIPT_AUTHENTICITY_PROVED`, cryptographic strength,
and native mbedTLS/liboqs implementation refinement remain forbidden; those
properties cannot be inferred from finite control-state exploration.

### M60 — PQ workload WCET and deployment-split preemption

The NTT timing witness binds eight layers of 128 butterflies to each profile's
human-owned instruction-cost model. In the microkernel, PQ work remains at EL0:
the claim bounds the hash-bound EL1 scheduler handler (68 cycles on N150 and
133 on R52), independently of total user workload time. Physical interrupt
delivery remains unproved.

The monolith receives no preemptive-isolation claim. Its shared source has one
hash-bound cooperative yield per layer, so the multiplicative cost gate bounds
the largest non-yielding chunk at 3,456 cycles on N150 and 5,760 on R52. These
are `PQ_COOPERATIVE_WCET_BOUND_PROVED` scopes, not microkernel preemption
evidence. The registry forbids both hardware interrupt-delivery proof and any
monolithic preemptive-isolation claim.

### M61 — herd7 weak-memory simulation

The structural M37 gate still checks that every shared-access function carries
an ordering primitive. M61 adds SHA-256-bound message-passing litmus tests for
the declared `x86_tso` and `armv8_sc` profiles and invokes the real `herd7`
judge. A claim is minted only when herd7 exits successfully and reports the
forbidden observation as `Never`; `Sometimes`, `Always`, malformed output,
execution failure, and artifact drift all fail closed.

On a host without herd7 the deployment bundle remains `judge_pending`. The
declared development environment now carries herdtools7 7.58; both reviewed
litmus tests report the forbidden observation as `Never`. This is model-level
evidence only: source-to-litmus/compiled-code refinement and physical-silicon
conformance remain explicitly forbidden claims.

### M62 — exception-level transition model

A deterministic TLA+ model covers preparation of an EL0 return context,
modeled `ERET`, syscall trap entry, dispatch validation, and return to user
mode. TLC 2.19 explores six distinct states and proves that EL0 is reachable
only with the MMU enabled and user-class SPSR/ELR state, and that every return
after a trap has passed dispatch validation. The evidence binds the generated
model to the exact MMU map, syscall table, and ELF load plan hashes.

The AArch64/R52 microkernel profile mints
`EXCEPTION_LEVEL_TRANSITION_MODEL_PROVED`; the monolith
records an explicit omission because it has no EL0 process boundary. This is
not `HARDWARE_EXCEPTION_LEVEL_TRANSITION_PROVED`: ARM's physical `ERET`
behavior and refinement of compiled vector assembly remain named assumptions.

### M63 — per-task scheduler starvation freedom

The scheduler model contains three reviewed task identities and a bounded
round-robin cursor. TLC 2.19 explores 36 distinct states and checks, for every
task, that readiness leads to either that task being scheduled or the task
being explicitly blocked. This is stronger and more precise than a global
`[]<>(ready)` predicate, which does not identify which task made progress.

The temporal result depends on the declared `WF_vars(Schedule)` assumption:
when scheduling remains enabled, the scheduler action eventually executes.
Both deployment profiles mint
`SCHEDULER_STARVATION_FREEDOM_MODEL_PROVED`, bound to the exact runqueue C
witness and generated TLA+ bytes. Unbounded task creation, physical timer/IRQ
fairness, and C-to-model refinement remain forbidden claims.

### M64 — bounded EL0 user heap

The microkernel grants each process a fixed 4,096-byte heap represented by 16
allocation-free 256-byte slots. The Rust ledger returns deterministic
`HeapError::Exhausted` backpressure and rejects invalid or duplicate releases.
Kani verifies the exact path-included Rust implementation over bounded
nondeterministic allocate/release sequences, and the bundle binds both source
and proof-harness hashes. The monolith explicitly omits the separate EL0 heap.

`USER_HEAP_CAPACITY_PROVED` establishes allocator occupancy never exceeds its
grant. It does not prove physical frame assignment or general-purpose libc
allocator semantics; those remain forbidden claims.

### M65 — multi-server capability confinement

The microkernel's reviewed finite capability table separates VFS, network,
and shell authority. Z3 proves the forbidden cross-server combinations are
unsatisfiable: VFS cannot exercise raw-packet authority, and Net cannot
exercise file-descriptor authority. The evidence binds both the exact JSON
table and generated SMT encoding. Any server grant or route drift fails
closed before a claim is emitted.

`SERVER_CAPABILITY_NONINTERFERENCE_PROVED` is a bounded policy theorem. It
depends on M48 spatial isolation and M49 syscall mediation; it does not prove
capability-token unforgeability or physical enforcement. The monolith records
`SERVER_CAPABILITY_BOUNDARY_OMITTED` because no separate EL0 authority
boundary exists there.

### M66 — feature-gated unikernel profile

`unikernel.json` selects scheduler, network, and VFS from the same source tree
while the deployment gate rejects MMU, syscall, IPC, ELF-loader, exception,
EL0-heap, and server-capability artifacts. A dedicated no-std Rust crate must
build with `cargo build --features unikernel`; its manifest and source hashes
are retained in the evidence. The resulting bundle currently contains 53
entries and records `UNIKERNEL_BOUNDARIES_STRIPPED` as a named boundary.

`UNIKERNEL_BUILD_PROVED` establishes feature-gated compilation and the
declared single-EL1 structure. It does not prove a bootable VM image, runtime
behavior, or fault containment. Those claims are forbidden rather than
inferred from compilation.

### M67 — Cortex-R52 TCM placement

The R52 hardware profile is bound to a dedicated linker script with 16 KiB
ITCM for executable/read-only sections and 16 KiB DTCM for writable state. The
declared `tcm_kernel` pool must exactly equal the DTCM range, and the evidence
hash-binds both the port artifact and linker bytes. The microkernel, monolith,
unikernel, and Safety manifests carry `R52_TCM_PLACEMENT_PROVED`; the N150-only
Desktop manifest does not.

This is placement evidence over human-declared addresses, not physical-board
evidence. `R52_PHYSICAL_EXECUTION_PENDING` records that boot, SoC address-map
conformance, and measured WCET still require an attached Cortex-R52 target.

### M68 — R52 SMMU configuration and physical-test protocol

The reviewed SMMUv3 table assigns distinct stream IDs to NIC and block
devices, requires each allowed window to equal its M39 DMA contract, and
proves every window is disjoint from protected DTCM. The artifact also fixes
the physical experiment: attempt a device DMA write into `tcm_kernel` and
require a translation fault with no memory change.

Only `SMMU_CONFIGURATION_CORRESPONDENCE_PROVED` is currently minted. The
experiment's `observed` field must remain null until real board evidence is
captured; otherwise validation fails closed. Consequently
`EXTERNAL_IO_SAFETY_PROVED` and `PHYSICAL_SMMU_DMA_BLOCK_PROVED` remain
forbidden, and the registry records M68 step 1 of 2 as partial.

### M69 — Intel N150 x86_64 and VT-d configuration

The N150 artifact binds a page-aligned 1 MiB kernel linker window and distinct
PCI requester IDs to the profile's NIC and block DMA contracts. VT-d protected
ranges must equal the declared kernel pool and remain disjoint from every DMA
window. The existing herd7 `x86_tso` result remains a separate model-level
claim rather than being promoted to silicon evidence.

`N150_PLATFORM_CONFIGURATION_PROVED` covers only this static correspondence.
Physical boot, firmware placement, VT-d fault behavior, and silicon TSO
conformance remain null observations guarded by
`N150_PHYSICAL_EXECUTION_PENDING`. M69 is therefore step 1 of 2 until evidence
is captured from an actual Intel N150 system.

### M70 — hard-real-time pre-certification traceability

The deployment-specific matrix maps reviewed FormalKernel requirements to
actual, non-pending evidence entries. Each row records its claim, judges, and
sources, while a SHA-256 fingerprint binds the complete evidence tuple set.
Microkernel-only isolation requirements are excluded from monolith and
unikernel applicability rather than silently reported as satisfied.

`CERTIFICATION_TRACEABILITY_COMPLETE` means every applicable requirement has
evidence in the current bundle. It deliberately carries
`certification_ready: false` and `regulatory_certification_proved: false`.
The three physical M67–M69 closures remain listed, and DO-178C Level A,
ISO 26262 certification, and physical hard-real-time claims are forbidden.
M70 therefore provides a pre-certification work product, not authority
approval or a certification result.

### M71.5 — shared-hardware interference inventory

Both hardware profiles must disposition the complete reviewed channel set:
cache, memory bandwidth, interconnect, DMA, interrupts, and SMT. Each channel
names a control and a bounded, pending, or not-applicable status. The gate
rejects missing channels and refuses hand-entered measurement results; future
WCET inflation data must arrive through an authenticated evidence-ingestion
lane carrying target identity, workload and raw-sample hashes, an inflation
bound, and a reviewer signature.

`MULTICORE_INTERFERENCE_CHANNELS_ENUMERATED` covers the twelve inventory rows.
It does not validate a target WCET bound. The latter remains
`TARGET_WCET_INTERFERENCE_BOUND_PENDING`, while
`MULTICORE_TIMING_INTERFERENCE_PROVED` is forbidden.

### M71 — parameterized RCU reclamation safety

`RCURefinement.tla` defines the epoch, active-reader, callback, and reclaimed
state for an arbitrary `Readers` set. TLAPS discharges all ten initialization
and inductiveness obligations. A separate two-reader pthread witness uses
explicit ESBMC atomic sections for reader publication and the updater's
reclamation snapshot; ESBMC checks it with unwind 5 and context bound 3. The
initial unprotected witness produced real publication/snapshot counterexamples
and was corrected before evidence was minted.

`RCU_RECLAMATION_SAFETY_PROVED` is scoped to the parameterized grace-period
invariant plus that bounded SC witness. It is not implementation refinement:
IRQ/NMI interaction, callback-pressure bounds, weak-memory lowering, and exact
C/model correspondence remain named pending obligations.

### M72 — crash-consistent VFS journal

The bounded write-ahead-log model separates volatile pending writes from
durable filesystem and journal state. Intent and data writes may reorder;
intent, data, and commit records may tear; crashes discard the volatile cache;
and recovery itself may crash after restoring data but before clearing the
journal. TLC 2.19 explores 39 distinct states and checks type safety, commit
ordering, stable recovery writes, and old-or-new crash atomicity. TLC initially
found a repeat-data issuance path that allowed a torn rewrite before commit;
an explicit single-issuance ledger corrected the protocol before publication.

`FILESYSTEM_CRASH_ATOMICITY_PROVED` is scoped to this declared persistence
contract. Physical FUA semantics, device-firmware behavior, and
CrashMonkey-style injected-crash validation remain pending and forbidden as
stronger claims.

### M73 — adversarial TCP resource containment

The bounded TCP model tracks half-open, established, and TIME_WAIT occupancy
for attacker and legitimate principals under a four-slot pool with two-slot
per-principal quotas. It includes eight-value modular sequence arithmetic,
receive-window ACK validation, duplicate SYNs, dropped/reordered ACKs,
retransmission expiry, TIME_WAIT pressure, and challenge ACKs for blind RSTs.
TLC 2.19 explores 49 distinct states and proves pool capacity, each principal's
quota, the legitimate two-slot reserve, and bounded challenge-ACK state.

`TCP_RESOURCE_CONTAINMENT_PROVED` is scoped to this two-principal adversarial
envelope and quota policy. It is not comprehensive RFC 9293 or RFC 5961
conformance, sequence-space refinement, congestion-control verification, or
native lwIP/mbedTLS implementation refinement; those remain locked claims.

### M74 — microarchitectural mitigation policy

The N150 policy declares CPUID capabilities, a minimum reviewed microcode
revision, SMT state, and the active MDS, TAA, L1TF, SRSO, and BHI hazards. Z3
checks for a counterexample in which any active hazard lacks its corresponding
mitigation; `unsat` mints `MICROARCH_MITIGATION_POLICY_PROVED`. Selected
mitigations also require their declared CPUID capabilities.

The separate `MITIGATION_WCET_BUDGET_PROVED` claim is arithmetic over declared
costs: the selected mitigations total 105 cycles against a 160-cycle budget.
Neither claim authenticates runtime CPUID or microcode, measures physical
latency, or proves speculative information-flow noninterference. Those three
boundaries remain named `judge_pending` entries in every deployment bundle.

### M75 — tool qualification-support evidence

A standalone Python standard-library oracle script checks a reviewed golden corpus
without importing FormalSpecGen or its pipeline. Two vectors compare canonical
semantic digests of reviewed and emitted V2 ASTs; a third independently parses
the supported Boolean SMT assertion form and compares it with reviewed variable
assignments. The evidence binds SHA-256 hashes of both the corpus and oracle.

`TOOL_QUALIFICATION_EVIDENCE_READY` means only that this finite corpus passed an
independent implementation. It does not prove the serializers generally correct,
qualify FormalSpecGen under DO-330, or replace context-specific external authority
review. `DO330_EXTERNAL_QUALIFICATION_PENDING` records that remaining boundary.

### M76 steps 1–3b-r1 — vertical refinement and foundational judge qualification

The first vertical deliverable binds the promoted VFS model, its Prusti
certificate, and exact `Vfs.rs` bytes. A deterministic pass removes only
Prusti ghost attributes; rustc emits host LLVM IR and an ELF object whose
hashes and compiler provenance enter the evidence envelope. The five modeled
operation symbols must remain observable in IR.

`REFINEMENT_CHAIN_ARTIFACTS_BOUND` is identity evidence, not semantics.
Rust-to-LLVM refinement, verified compilation, target binary semantics, and
`END_TO_END_REFINEMENT_CHAIN_ESTABLISHED` remain locked for later M76 steps.

Step 2 generates a Rust relational harness directly from the reviewed V2 guard
and effect AST. It executes the exact ghost-erased implementation over all 255
states satisfying the VFS invariants and all four operations, checking 1,020
state/operation transitions plus the constructor. Explicit process exit codes
replace panic paths. `BOUNDED_COMPILED_REFINEMENT_VALIDATED` records this finite
exhaustive result; it is not a theorem about arbitrary Rust or LLVM programs.

Step 3a activates the installed RefinedRust 0.1.0, Rocq 9.2, Iris/stdpp, and
lifetime-logic stack through the isolated `refinedrust` opam switch. A minimal
Rust identity function is translated into Radium/Rocq and its generated proof
build completes. An unchanged identity postcondition rejects a deliberately
mutated `value + 1` implementation as an incomplete proof. This establishes a
non-vacuous judge smoke test only: `RUST_IMPLEMENTATION_REFINEMENT_PROVED`
remains locked until step 3b proves an actual allocator or capability primitive.

Step 3b-r1 isolates and corrects a RefinedRust 0.1.0 semantic translation defect
without changing the production allocator. Standalone `[T; N]` translated to
`array_t N T`, but the same array embedded in a struct was assigned `list T` rather
than the required `list (place_rfn T)`. The generic correction is retained as a
hash-bound local tool patch and validated for `N = 0, 1, 2, 4, 16`; all standalone
and embedded cases translate and complete their Rocq builds. Reverting the rule to
the malformed representation is rejected by Rocq with the captured type mismatch.
This mints only `REFINEDRUST_ARRAY_TRANSLATION_VALIDATED`. The patch is explicitly
not upstream-accepted, the allocator functional proof remains step 3b-r2, and all
Rust-wide/compiler/end-to-end refinement claims remain locked.

Step 3b-r2 then applies a ghost-only annotation overlay to the exact production
allocator; deterministic erasure reproduces `user/heap.rs` byte-for-byte. The
judge stops before functional obligations on three independent unsupported
constructs: named-constant normalization for the `HEAP_BLOCKS` array length,
iterator/enumerate pattern lowering in `allocate`, and the slice-index trait used
by `get_mut` in `release`. A generic constant-normalization prototype reached the
latter two boundaries but was not added to the qualified local patch. Replacing
the constant with `16`, rewriting the iterator, or proving a surrogate allocator
is forbidden. Consequently the mutation suite has not run and
`BOUNDED_ALLOCATOR_IMPLEMENTATION_REFINEMENT_PROVED` remains locked.

Step 3c does not introduce a verifier-shaped capability primitive because none
exists in the production Rust tree. A non-evidentiary feasibility scanner records
only qualified syntax observations and ranks all existing production components.
The scalar `BlockDevice::complete` transition in `virtio_blk.rs` ranks first and
is probed through a byte-identical ghost overlay. An initial ICE is reduced to an
incomplete overlay: with specifications on both trait methods and the impl, a
minimal generic `Adapter<P>` translates and its Rocq proofs complete. The exact
adapter remains blocked because its sibling `submit` method uses `?`, whose
`core::result::branch` procedure is not modeled. ELF loading and both fixed
pool ledgers contain already-recorded array, iterator, slice, or closure blockers.
The report is therefore `NO_PROOF`: no existing production primitive is currently
inside the qualified fragment, and no M76.3c refinement claim is minted.

Step 3c-u1 records this correction as qualification evidence, not a theorem and
not an upstream bug report. The inherent control completes 2,220 Rocq steps; the
generic local-trait reproducer completes 492 and 2,293 steps. A machine-readable
boundary ledger now distinguishes the qualified generic trait-registration shape
from the open Result/Try shim, and is consumed by both `doctor --judges --json`
and feasibility ranking. No additional local RefinedRust patch is introduced.

### M77 — dynamic VM and bounded NUMA accounting

`dynamic_vm.json` replaces a single fixed global pool with ownership accounting
for three admitted processes across two static NUMA nodes. Z3 checks inductive
preservation for allocation, release, mapping, fork/COW reservation, and exec
reclamation. It proves each process remains below its page quota, each node
remains below capacity, and the sum of charged pages remains below admitted
memory. Deterministic quota exhaustion stutters instead of invoking an OOM
killer.

The two minted claims, `VM_RESOURCE_ISOLATION_PROVED` and
`NUMA_ACCOUNTING_PROVED`, have scope
`three_process_two_node_symbolic_accounting`. They do not establish arbitrary
process cardinality, NUMA hotplug, hardware TLB coherence, page-walker behavior,
or native allocator refinement.

### M78 — parameterized SMP scheduler invariants

`SmpSchedulerRefinement.tla` and its reviewed scheduler policy cover per-CPU
run queues, affinity, and migration. TLAPS discharges nine obligations over
arbitrary finite CPU and task sets: unique run-queue ownership, affinity
compliance, ownership preservation, and migration conservation.

`SMP_SCHEDULER_INVARIANTS_PROVED` is the only arbitrary-finite-set theorem in
this Phase 7 group. Native load-balancer refinement, IRQ/IPI delivery, CPU
hotplug, temporal liveness, composition with M77, and measured interference
bounds remain pending.

### M79 — IOMMU, PCIe, and multiqueue device domains

`device_fabric.json` assigns unique PCIe requester IDs and IOMMU domains to the
NVMe and network devices, gives them disjoint DMA windows outside kernel and
page-table memory, and binds six MSI-X/multiqueue capacities to reserved buffer
pages. Z3 proves queue occupancy cannot exceed those reservations; the reset
contract increments an epoch and clears outstanding accounting.

`DEVICE_DMA_DOMAIN_ISOLATION_PROVED` covers the declared requester table,
ranges, and queue budgets. Physical IOMMU enforcement, PCIe/NVMe firmware,
device behavior, MSI-X delivery, and native driver refinement remain pending.

### M80 — bounded process concurrency model

The TLC process model covers `fork`, `exec`, `exit`, futex wait, and futex wake
for two processes and two threads under a two-page quota. TLC checks 15 states
for cleanup, futex consistency, and deadlock freedom. A separate Z3 query proves
that exec resets the old page charge and inherited capability state.

`PROCESS_CONCURRENCY_MODEL_PROVED` is therefore a bounded lifecycle theorem,
not full POSIX conformance. Native syscall/futex refinement, hardware futex
atomicity, signals, credentials, and unbounded process populations remain
outside the claim.

### M81 — measured boot and rollback policy

`boot_integrity.json` binds a reviewed source measurement, PCR index, root-key
identity, current version, minimum accepted version, and recovery response. TLC
checks 10 reachable control states and excludes a rollback path to Running. Z3
proves an admitted boot cannot have a mismatched measurement, missing
authorization, or stale version.

`BOOT_TO_RUNTIME_INTEGRITY_CHAIN_PROVED` is scoped to the declared policy and
hash bindings. It does not prove physical TPM semantics, firmware measurements,
key custody, SHA-256 collision resistance, final-image measurement, or physical
boot-chain enforcement.

### M82 — bounded network-scale partitioning

The network model covers IPv6 TCP/UDP classification, default-drop firewalling,
public/internal routing, four statically partitioned queues, and deterministic
backpressure. TLC checks 49 states for type safety, terminal routing decisions,
and firewall preservation. Z3 proves tenant queue occupancy cannot consume the
system reservation or exceed the total descriptor budget.

`NETWORK_RESOURCE_PARTITION_PROVED` is limited to two principals and four
queues. Full IPv6/RFC conformance, native network-stack refinement, RSS/MSI-X
behavior, cryptographic packet authenticity, and physical delivery remain
pending.

### M83 — fault containment and recovery

`fault_recovery.json` models one correctable ECC fault, uncorrectable MCE,
watchdog expiry, or device failure across a workload, supervisor, and three
pages. TLC checks eight distinct states: every pending fault has a recovery
action, poisoned page zero is no longer owned, accounting remains exact, and
the supervisor stays schedulable. Z3 proves poisoning removes one page from
both charged and allocatable totals.

`FAULT_CONTAINMENT_RECOVERY_PROVED` is scoped to this single-fault recovery
model. Physical ECC/MCE/watchdog delivery, firmware reset behavior, native
handler refinement, and repeated or simultaneous faults remain pending.

### M84 — guest isolation domains

The guest model gives two guests static CPU-slot, memory-page,
network-descriptor, and distinct IOMMU-domain reservations. TLC checks nine
states and 31 generated transitions over create, pause, resume, and destroy,
including exact reservation/reclamation and lifecycle progress. Z3 proves all
per-guest and aggregate ceilings and the domain-ID separation.

`GUEST_RESOURCE_NONINTERFERENCE_PROVED` is policy evidence for those two static
guests. Hardware VM-exit semantics, nested-page enforcement, interrupt
remapping, native hypervisor refinement, speculative side channels, and
arbitrary guest populations remain pending.

### M85 — compatibility and operations evidence

The reviewed ABI-v1 baseline freezes numbers, names, symbols, and signatures
for `open`, `read`, `write`, `close`, and `exit`. The gate compares the active
ABI byte-for-byte with that baseline, checks implementation symbols, compiles
the exact C compatibility shim with warnings as errors, and runs nine host
behavior vectors. It also structurally checks trace fields, profiling counters,
the crash-dump header, and the minimum-version/recovery upgrade policy.

The resulting names deliberately describe empirical evidence:
`ABI_STABILITY_CHECKED` and `POSIX_CONFORMANCE_TESTED`, both scoped to
`five_call_host_compiled_compatibility_shim`. They do not prove full POSIX,
kernel-dispatch refinement, target runtime behavior, production observability,
complete crash dumps, or atomic field upgrades.

## Evidence lattice shipped per subsystem

```
SOURCE_MODEL_REFINEMENT            (Prusti/TLC — proved once, arch-agnostic)
HARDWARE_MEMORY_BOUND_PROVEN       (Z3 + M41 profile — per subsystem)
LOCK_FREE_LINEARIZABILITY_PROVED   (ESBMC over the C witness — once)
BARRIER_CORRESPONDENCE_PROVED      (per profile: x86_tso | armv8_sc)
WEAK_MEMORY_SAFETY_PROVED          (herd7 forbidden-outcome check; judge_pending when absent)
WCET_BOUND_PROVEN                  (per profile cost model; binary_cfg when toolchain present)
DMA_ISOLATION_PROVED               (per profile memory map)
SYSTEM_COMPOSITION_PROVED          (deterministic precondition flow — M46)
SPATIAL_ISOLATION_PROVED           (descriptor math + walker decode — M48)
SYSCALL_BOUNDARY_PROVED            (dispatch table — judge_pending hardware trap — M49)
EXCEPTION_LEVEL_TRANSITION_MODEL_PROVED (TLC EL1/EL0 control-state model — M62)
SCHEDULER_STARVATION_FREEDOM_MODEL_PROVED (per-task TLC leads-to under WF — M63)
USER_HEAP_CAPACITY_PROVED          (Kani fixed EL0 allocator — M64)
SERVER_CAPABILITY_NONINTERFERENCE_PROVED (Z3 finite routing policy — M65)
UNIKERNEL_BUILD_PROVED              (Cargo no-std feature build — M66)
R52_TCM_PLACEMENT_PROVED            (deterministic linker/profile binding — M67)
SMMU_CONFIGURATION_CORRESPONDENCE_PROVED (R52 stream/DMA arithmetic — M68 step 1)
N150_PLATFORM_CONFIGURATION_PROVED (x86_64 linker/VT-d binding — M69 step 1)
CERTIFICATION_TRACEABILITY_COMPLETE (requirements/evidence fingerprint — M70)
MULTICORE_INTERFERENCE_CHANNELS_ENUMERATED (profile inventory — M71.5)
RCU_RECLAMATION_SAFETY_PROVED     (TLAPS invariant + ESBMC witness — M71)
FILESYSTEM_CRASH_ATOMICITY_PROVED (TLC declared persistence contract — M72)
TCP_RESOURCE_CONTAINMENT_PROVED   (TLC partitioned adversarial quotas — M73)
MICROARCH_MITIGATION_POLICY_PROVED (Z3 declared hazard-policy completeness — M74)
MITIGATION_WCET_BUDGET_PROVED    (declared mitigation-cost equation — M74)
TOOL_QUALIFICATION_EVIDENCE_READY (independent reviewed golden corpus — M75)
REFINEMENT_CHAIN_ARTIFACTS_BOUND (V2/Prusti/Rust/LLVM/object identity — M76 step 1)
BOUNDED_COMPILED_REFINEMENT_VALIDATED (255 states/1,020 transitions — M76 step 2)
VM_RESOURCE_ISOLATION_PROVED       (Z3 symbolic dynamic quotas — M77)
NUMA_ACCOUNTING_PROVED             (Z3 two-node ownership accounting — M77)
SMP_SCHEDULER_INVARIANTS_PROVED   (TLAPS arbitrary finite CPU/task sets — M78)
DEVICE_DMA_DOMAIN_ISOLATION_PROVED (IOMMU/range + Z3 multiqueue budgets — M79)
PROCESS_CONCURRENCY_MODEL_PROVED   (TLC lifecycle + Z3 exec cleanup — M80)
BOOT_TO_RUNTIME_INTEGRITY_CHAIN_PROVED (declared TLC/Z3 boot policy — M81)
NETWORK_RESOURCE_PARTITION_PROVED (TLC routing + Z3 queue partitions — M82)
FAULT_CONTAINMENT_RECOVERY_PROVED (TLC recovery + Z3 poison accounting — M83)
GUEST_RESOURCE_NONINTERFERENCE_PROVED (TLC lifecycle + Z3 partitions — M84)
ABI_STABILITY_CHECKED                (reviewed ABI baseline equality — M85)
POSIX_CONFORMANCE_TESTED             (host-compiled five-call vectors — M85)
MPSC_BOUNDED_PARTITION_PROVED      (ESBMC per-lane + total — M50)
IPC_ENDPOINT_TABLE_PROVED          (cross-artifact routing — M50)
RUST_WITNESS_REFINEMENT_PROVED     (Kani over the image's own witness.rs — M53)
UNVERIFIED_EXTERNAL_ADAPTER        (M45 — driver glue, explicitly not proved)
```

### Phase 7 assurance-profile matrix

These roadmap profiles classify intended assurance and resource policies.
`safety.json` and `desktop.json` are now executable and registry-mapped to
`FK-Safety` and `FK-Desktop`. The existing `microkernel`, `monolith`, and
`unikernel` names still describe deployment mechanics; they are not silently
relabeled as the other three assurance profiles.

| FormalKernel profile | Optimizes for | Resource philosophy |
| --- | --- | --- |
| `FK-Safety` | DO-178C-style assurance, restricted silicon | Fixed pools, bounded task population, deterministic backpressure |
| `FK-Secure` | seL4-like isolation, minimal TCB | Strong isolation with controlled dynamic user resources |
| `FK-Scale` | 64–256 core NUMA servers, high throughput | Dynamic pages, quotas, reclamation, RCU, bounded local invariants |
| `FK-Desktop` | Richer POSIX/device compatibility | Dynamic pages, broad driver support, relaxed timing |
| `FK-Lab` | New mechanisms, experimental proofs | Explicit `judge_pending` claims, unverified boundaries |

### Executable manifest matrix after M85

| Manifest | Registry assurance mapping | Hardware input | Required/forbidden policy |
| --- | --- | --- | --- |
| `kernel.json` | None; mechanical microkernel scope | N150 + R52 | EL0 boundary lanes enabled |
| `monolith.json` | None; mechanical monolithic scope | N150 + R52 | EL0 boundary lanes forbidden |
| `unikernel.json` | None; mechanical unikernel scope | N150 + R52 | Boundary lanes stripped; feature build required |
| `safety.json` | `FK-Safety` | R52 | Fixed resources, one core, hard WCET; dynamic/SMP/user-space claims forbidden |
| `desktop.json` | `FK-Desktop` | N150 | Dynamic/POSIX/guest lanes enabled; hard-WCET/interference claims forbidden |

`SAFETY_DYNAMIC_RESOURCE_CONTRADICTION` rejects a Safety manifest that carries
M77/M78, RCU, process, guest, or POSIX/user-boundary lanes or relaxes its fixed
resource flags. `DESKTOP_HARD_REALTIME_CONTRADICTION` rejects a Desktop
manifest that requests hard real-time or multicore-interference assurance. A
final registry-based minted-claim audit repeats both checks after all lanes run.

The Desktop bundle does not reuse the AArch64-only M57 ELF loader or M62 ERET
model. `DESKTOP_X86_PROCESS_ENTRY_REFINEMENT_PENDING` names the missing x86_64
ELF/ring-3/native-exec refinement explicitly.

Fail-closed is the default posture at every seam; no LLM output ever
becomes evidence.
