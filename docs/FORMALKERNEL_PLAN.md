# FormalKernel — the Bounded-Pool Hybrid Kernel (M41–M54)

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
anti-drift guarantee is a test: the monolith's claims are a strict
subset and every shared claim is the byte-identical tuple.

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
