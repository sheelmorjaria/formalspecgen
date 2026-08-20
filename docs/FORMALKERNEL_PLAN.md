# FormalKernel — the Bounded-Pool Hybrid Kernel (M41–M60)

TDD plan for building a hybrid-kernel development flow on top of the
M36–M40 OS verification framework. Governing rule, unchanged: *The LLM
proposes; deterministic compilers transform; formal tools judge; humans
control trusted assumptions.*

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

`pipeline/deployment_profile.py`: one tree, two honest bundles, no
code fork. The root manifest declares its deployment; a monolith
carrying any boundary lane (mmu/syscalls/ipc) refuses
`MONOLITH_BOUNDARY_CONTRADICTION`. `verify-kernel --manifest
monolith.json` mints the 19-claim monolithic bundle (boundary claims
omitted; the note says the driver is the kernel — containment does not
exist) from the SAME sources as the 24-claim microkernel bundle. The
anti-drift guarantee is a test: every shared claim is the byte-identical
tuple. M60 introduces one deliberate, registry-declared divergence:
microkernels mint the EL0 preemption scope while monoliths mint only the
cooperative EL1 chunk bound.

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

## Evidence lattice shipped per subsystem

```
SOURCE_MODEL_REFINEMENT            (Prusti/TLC — proved once, arch-agnostic)
HARDWARE_MEMORY_BOUND_PROVEN       (Z3 + M41 profile — per subsystem)
LOCK_FREE_LINEARIZABILITY_PROVED   (ESBMC over the C witness — once)
BARRIER_CORRESPONDENCE_PROVED      (per profile: x86_tso | armv8_sc)
WCET_BOUND_PROVEN                  (per profile cost model; binary_cfg when toolchain present)
DMA_ISOLATION_PROVED               (per profile memory map)
SYSTEM_COMPOSITION_PROVED          (deterministic precondition flow — M46)
SPATIAL_ISOLATION_PROVED           (descriptor math + walker decode — M48)
SYSCALL_BOUNDARY_PROVED            (dispatch table — judge_pending hardware trap — M49)
MPSC_BOUNDED_PARTITION_PROVED      (ESBMC per-lane + total — M50)
IPC_ENDPOINT_TABLE_PROVED          (cross-artifact routing — M50)
RUST_WITNESS_REFINEMENT_PROVED     (Kani over the image's own witness.rs — M53)
UNVERIFIED_EXTERNAL_ADAPTER        (M45 — driver glue, explicitly not proved)
```

Fail-closed is the default posture at every seam; no LLM output ever
becomes evidence.
