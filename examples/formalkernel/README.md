# FormalKernel example — the lwIP packet path through the M41–M45 lattice

One real subsystem — lwIP's `tcpip` packet path, taken from the Rosetta
corpus at `runs/lwip-probe/lwip` — run through every FormalKernel lane.
Provenance of each artifact is recorded in its header comment.

## The subsystem (from real lwIP sources)

| Artifact | lwIP provenance | Kernel lane |
|---|---|---|
| `kernel/scheduler/` | the scheduler ready runqueue (irq-wake → pick, the SPSC contract) + `sched_tick.c` deadline | M36/M37 witness + M38 tick |
| `kernel/composition.json` | the orchestrator's boot flow: every callee's `requires` established by an earlier step's `establishes` | M46 precondition flow → `SYSTEM_COMPOSITION_PROVED` |
| `kernel/rx_ring.c` | `src/api/tcpip.c:61` `tcpip_mbox` — the netif→tcpip-thread packet handoff, an SPSC mailbox | M36 lock-free witness + M37 barrier correspondence |
| `kernel/timer_tick.c` | `src/core/timeouts.c` `sys_timeouts` walk over `struct sys_timeo` (include/lwip/timeouts.h:93) | M38 source WCET + the deadline the tick must meet |
| `kernel/nic.c` | the `netif` driver seam lwIP leaves to the port (`ethernetif` shape) | M39 DMA isolation + M45 driver boundary |
| `hardware_profile.json` | lwIP's pool ids (`MEMP_SYS_TIMEOUT`, `PBUF_POOL`, …) sized by silicon instead of `opt.h` heuristics | M41 trust root |

The `rx_ring.c` witness is the ESBMC plain-int dialect encoding of the
mbox contract (per `docs/FORMALKERNEL_PLAN.md` correction 2: this ESBMC
build has no C11 atomics bodies; the witness is plain shared ints with
one single-word store per operation — the linearization point).

## Run it

```bash
cd examples/formalkernel

# M41 — the silicon derives every pool (capacity = min(silicon ceiling,
#        reviewer share); SRAM windows pairwise disjoint)
python3 -c 'from pipeline.hardware_profile import *; import json; \
  print(json.dumps(derive_kernel_pools(load_profile("hardware_profile.json"), \
  json.load(open("subsystems.json"))["subsystems"]), indent=2))'

# M40 — honest boundary: lwIP's sys_timeo is intrusive but NOT the Linux
#        list_head dialect; the extractor refuses by name (fail-closed),
#        and the list is bounded instead by the M41 sys_timeouts pool
#        (lwIP itself allocates sys_timeo from MEMP_SYS_TIMEOUT)
python3 -c 'from pipeline.os_patterns import extract_intrusive_list; \
  print(extract_intrusive_list(open(\
  "../../../runs/lwip-probe/lwip/src/core/timeouts.c").read(), 8)["status"])'

# M43/M46 — the multi-subsystem, multi-architecture lattice (real
#        ESBMC per witness; WCET + DMA per profile; the composition
#        gate mints SYSTEM_COMPOSITION_PROVED once, arch-agnostic)
formalspecgen verify-kernel kernel \
  --profile profiles/n150.json --profile profiles/r52.json \
  --json ../../runs/formalkernel/bundle.json

# M44 — binary-level WCET on the Rust lowering of the timer tick
python3 -c 'from pipeline.wcet_binary import wcet_bound_binary; import json; \
  print(json.dumps(wcet_bound_binary("lowered/timer_tick.rs", json.load(\
  open("profiles/r52-wcet-binary.json"))), indent=2))'

# M45 — the NIC driver glue: LLM proposes, the DmaContract judges
formalspecgen implement driver/nic_driver.rs \
  --dependencies kernel-driver --dma-profile profiles/n150-dma.json \
  --provider ollama --json ../../runs/formalkernel/adapter.json
```

Every claim in the bundle carries its scope; absent judges stay
`judge_pending`; the adapter is stamped `UNVERIFIED_EXTERNAL_ADAPTER`
with `external_io_safety_proved: false`.

## M47 — boot it on QEMU (AArch64 virt)

The boot image is a `no_std` Rust kernel whose boot order is COMPILED
IN from the proven composition artifact (`scripts/gen_boot_order.py`
generates `boot/src/boot_order.rs` from `kernel/composition.json` —
the same artifact M46 proved). It runs the order, then floods the net
ring (16 arrivals against CAP=4 with a draining consumer) and prints
the counters over the PL011 UART.

```bash
# one-time: the cross target (no sudo needed)
rustup target add aarch64-unknown-none-softfloat

# build the image (rustc + rust-lld — no cross C toolchain)
python3 -c 'from pipeline.boot_check import build_boot_image; \
  from pathlib import Path; print(build_boot_image(\
  Path("examples/formalkernel/boot")))'

# boot it (needs qemu-system-aarch64; sudo apt-get install qemu-system-arm)
timeout 10 qemu-system-aarch64 -M virt -cpu cortex-a72 -nographic \
  -monitor none -no-reboot \
  -kernel examples/formalkernel/boot/formalkernel.elf

# judge the transcript (RUNTIME_SAMPLE ceiling — evidence, NOT proof)
python3 -c '
import json
from pipeline.boot_check import parse_transcript, run_qemu_boot
boot = run_qemu_boot("examples/formalkernel/boot/formalkernel.elf")
comp = json.load(open("kernel/composition.json"))
print(json.dumps(parse_transcript(boot["transcript"], comp), indent=2))'
```

Verified transcript (2026-08-19, this host): the four BOOT lines in
the proven order, then `NET posted=7 dropped=9 consumed=7 high_water=4
cap=4` — 16 arrivals, 7 accepted, 9 DROPPED at the bound (the ERR_MEM
backpressure path actually executed); high_water == 4 == cap is the
ESBMC-proved capacity invariant observed on emulated silicon. Then
`MMU_ON` and `FAULT far=0x41000000 ISOLATION_TRAP`: the real AArch64
stage-1 MMU is enabled (identity map + the deliberate hole at
0x41000000) and the isolation probe's store TRAPS into the kernel's
own vector handler — the runtime sample for SPATIAL_ISOLATION_PROVED.
The kernel parks in wfe (the run ends on the timeout, transcript
complete). The
verdict's `claim_ceiling` is `RUNTIME_SAMPLE`: a QEMU transcript is
evidence about the math, never more math.
