// Kani proof harnesses over the boot image's verified core.
//
// The module below is the ACTUAL witness.rs compiled into the aarch64
// image (included by path — not a copy). Kani proves the SAME capacity
// invariants ESBMC proved for the C witnesses (M36: head - tail <= CAP;
// M50: per-lane <= LANE_CAP and total <= CAP) over the Rust code the
// image runs, closing the translation gap between the C witnesses and
// the image: claim RUST_WITNESS_REFINEMENT_PROVED.
//
// Honest scope: these are bounded proofs (nondeterministic operation
// sequences within the unwind bound), the same epistemic class as the
// ESBMC lanes; read_volatile/write_volatile are modeled as plain
// memory ops under Kani (single-threaded harness, sequential
// consistency — the interleaving claims remain ESBMC's).
#[path = "../../src/witness.rs"]
pub mod witness;

#[path = "../../../kernel/user/heap.rs"]
pub mod user_heap;

/// M36 refinement: the SPSC ring's capacity invariant over any
/// bounded sequence of posts and fetches — a full ring DROPS, it
/// never overflows, and the consumer never passes the producer.
#[kani::proof]
#[kani::unwind(12)]
fn ring_capacity_invariant() {
    let mut r = witness::Ring::new();
    for _ in 0..8 {
        if kani::any() {
            r.post(kani::any());
        } else {
            r.fetch();
        }
        assert!(r.head - r.tail <= witness::CAP_U);
        assert!(r.tail <= r.head);
    }
}

/// Backpressure accounting: every post either lands or is counted as
/// dropped — posted + dropped == attempts, never a silent loss.
#[kani::proof]
#[kani::unwind(12)]
fn ring_backpressure_accounting() {
    let mut r = witness::Ring::new();
    let mut attempts = 0u32;
    for _ in 0..8 {
        if kani::any() {
            attempts += 1;
            r.post(kani::any());
        } else {
            r.fetch();
        }
        assert!(r.posted + r.dropped == attempts);
    }
}

/// M50 refinement: the partitioned MPSC queue — each lane holds at
/// most LANE_CAP messages and the TOTAL occupancy never exceeds CAP,
/// over any bounded interleaving of the two producers and the
/// consumer.
#[kani::proof]
#[kani::unwind(10)]
fn mpsc_partition_total_invariant() {
    let mut q = witness::Mpsc::new();
    let mut attempts = 0u32;
    for _ in 0..6 {
        let op: u8 = kani::any();
        match op % 3 {
            0 => {
                attempts += 1;
                q.post(0, kani::any());
            }
            1 => {
                attempts += 1;
                q.post(1, kani::any());
            }
            _ => {
                q.fetch_any();
            }
        }
        assert!(q.head[0] - q.tail[0] <= witness::IPC_LANE_CAP as u32);
        assert!(q.head[1] - q.tail[1] <= witness::IPC_LANE_CAP as u32);
        assert!(q.head[0] + q.head[1] - q.tail[0] - q.tail[1]
                <= witness::IPC_CAP as u32);
        // backpressure accounting: every attempt accepted or dropped,
        // and the accepted count IS the lane-head sum (no silent loss)
        assert!(q.posted + q.dropped == attempts);
        assert!(q.posted == q.head[0] + q.head[1]);
        assert!(q.consumed == q.tail[0] + q.tail[1]);
    }
}

/// M64: any bounded sequence of allocations and releases stays within the
/// kernel-granted fixed pool; exhaustion returns an error without overflow.
#[kani::proof]
#[kani::unwind(24)]
fn user_heap_capacity_invariant() {
    let mut heap = user_heap::UserHeap::new();
    let mut handles = [None; user_heap::HEAP_BLOCKS];
    for _ in 0..20 {
        let index: usize = kani::any();
        if index < user_heap::HEAP_BLOCKS {
            if kani::any() {
                if let Ok(block) = heap.allocate() {
                    handles[index] = Some(block);
                }
            } else if let Some(block) = handles[index] {
                let _result = heap.release(block);
                handles[index] = None;
            }
        }
        assert!(heap.allocated() <= user_heap::HEAP_BLOCKS);
        assert!(user_heap::HEAP_BYTES == 4096);
    }
}
