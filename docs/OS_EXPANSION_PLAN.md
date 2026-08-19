# OS Verification Framework — the encoding-artifact expansion (M36–M40)

Governing rule, unchanged: *the LLM proposes; deterministic compilers
transform; formal tools judge; humans control trusted assumptions.* The
pipeline is not replaced — each domain below adds **artifact kinds**,
**deterministic gates**, and **mechanical judges**, exactly as the
blueprint prescribes.

## The judge-availability discipline

A claim is minted only by a mechanical judge that actually ran. The
blueprint names several judges that are **not installed on this host**;
where a judge is absent, its domain's claim is capped at what a
deterministic structural gate can honestly establish (the M32
`ir_cfg_correspondence` precedent: a decidable structural check is a
legitimate claim with an explicit scope), and the full claim is recorded
as unmintable until the judge is provisioned.

| Judge | Blueprint role | On this host | Consequence |
|---|---|---|---|
| ESBMC | bounded interleaving (M36) | installed | real BMC judge |
| Iris / Aeneas | concurrent separation logic | absent | M36 claims bounded-interleaving BMC + structural linearization coverage, not Iris-scale logic |
| herd7 / RC11 | weak-memory simulation (M37) | absent | M37 mints `BARRIER_CORRESPONDENCE_PROVED` (deterministic structural); `WEAK_MEMORY_SAFETY_PROVED` stays unmintable |
| aiT | binary WCET (M38) | absent (commercial) | M38 computes a deterministic static CFG upper bound from the real binary (`objdump`); the cost model is the human-owned artifact |
| SPIN | LTL liveness (M38) | absent | TLC natively checks temporal properties under declared fairness — the real liveness judge |
| CN / Kani | DMA separation (M39) | absent | M39's disjointness is decidable arithmetic over declared ranges — machine-checked deterministically |
| Z3, Frama-C, Prusti, TLC, objdump, ollama | existing lanes | installed | unchanged |

## M36 — Concurrency & lock-free structures

- **Artifact:** `concurrency_model: lock_free_spsc | lock_free_mpmc` on
  the lane input (the V2 extension point; the lane records it in the
  verdict rather than the candidate payload, keeping trusted artifacts
  human-owned).
- **Judge:** real ESBMC over a two-thread SPSC ring (`kfifo` shape):
  producer/consumer `pthread`s, `_Atomic` head/tail, the capacity
  invariant asserted; ESBMC explores interleavings (bounded).
- **Gate:** linearization-point coverage — every concurrent operation
  must carry exactly one designated atomic step (an `_Atomic`
  read-modify-write or the guarded store) where it takes effect;
  operations without one fail closed.
- **Claim:** `LOCK_FREE_LINEARIZABILITY_PROVED`,
  `scope: concurrent_interleaving_bmc`; scheduler fairness
  ("if a thread steps, it does not corrupt state") is the human-accepted
  assumption; progress/starvation-freedom is explicitly NOT claimed.

## M37 — Weak memory (x86-TSO / ARMv8)

- **Artifact:** `MemoryModel` profile (`x86_tso` | `armv8_sc`).
- **Gate:** barrier correspondence — every access the profile marks
  cross-thread must go through an explicit ordering primitive
  (`atomic::Ordering::{Acquire,Release,AcqRel,SeqCst}`, `smp_mb/rmb/wmb`,
  `_Atomic`), else `WEAK_MEMORY_VIOLATION` fail-closed.
- **Claim:** `BARRIER_CORRESPONDENCE_PROVED` (deterministic structural
  scope). `WEAK_MEMORY_SAFETY_PROVED` requires herd7/RC11 and is recorded
  as `judge_pending: herd7_or_rc11` — never minted here.

## M38 — Real-time (WCET & liveness)

- **Artifacts:** `timing_constraints {max_cycles}`; hardware cost-model
  profile (cycles per instruction class — human-owned, like the M30
  hardware bound).
- **Judge (WCET):** compile the real source (`gcc -O2`), disassemble
  (`objdump -d`), rebuild the CFG, compute the longest path's instruction
  count with loop trip-count bounds from the artifact — a deterministic,
  sound-over-approximation upper bound under the declared cost model.
  Bound > `max_cycles` → `DEADLINE_MISSED`.
- **Judge (liveness):** real TLC over a TLA+ rendering with declared
  scheduler fairness (`WF_\A` on the operation actions) and a temporal
  property (e.g. `[]<>(ready)`); TLC checks liveness natively.
- **Claims:** `WCET_BOUND_PROVEN` (scope `static_cfg_cost_model`),
  `LIVENESS_PROVED` (scope `tlc_temporal_under_declared_fairness`).

## M39 — Hardware I/O & DMA safety

- **Artifacts:** `PhysicalMemoryMap` (MMIO registers, DMA windows,
  kernel bounded pools as declared ranges) and `DmaContract` (device →
  allowed ranges) — both human-reviewed inputs.
- **Gate:** IOMMU correspondence — every `dma_map`/`ioremap` call site's
  range must be contained in the device's contract AND disjoint from
  every kernel pool range; violations fail closed
  (`DMA_OVERLAPS_KERNEL_POOL` / `OUT_OF_CONTRACT`).
- **Claim:** `DMA_ISOLATION_PROVED`,
  `scope: deterministic_range_disjointness`.

## M40 — OS-pattern extraction

- **Dialect 1 (intrusive lists):** `list_add`/`list_del`/
  `list_for_each_*` on a `struct list_head` recognized as transitions on
  an abstract `size` counter bounded by the pool capacity — pointers
  abstracted away, the M30 discipline.
- **Dialect 2 (callbacks):** function-pointer registration
  (`file_operations->read = dev_read`, `.read = dev_read` initializers)
  resolved to the registered function; the function is extracted as its
  own machine and the verdict carries the composition link; unresolved
  registrations fail closed by name.

## Evidence lattice after the expansion

1. `SOURCE_MODEL_REFINEMENT` — state safety (existing lanes).
2. `LOCK_FREE_LINEARIZABILITY_PROVED` — bounded interleaving (M36).
3. `BARRIER_CORRESPONDENCE_PROVED` — ordering discipline (M37; full
   weak-memory safety pending herd7/RC11).
4. `WCET_BOUND_PROVEN` / `LIVENESS_PROVED` — timing (M38).
5. `DMA_ISOLATION_PROVED` — hardware isolation (M39).

The human burden: hardware profiles (cost models, SRAM/pool layouts),
scheduler fairness, temporal formulas, and the DmaContract. The LLM
proposes invariants and predicates; the deterministic gates and judges
reject every shortcut.
