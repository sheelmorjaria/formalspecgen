// The verified-core shapes, shared by the boot image and the Kani
// proof harnesses (proofs/src/lib.rs includes this file BY PATH): the
// identical code compiles into the aarch64 image AND is the code Kani
// proves the capacity invariants over — that sharing IS the
// refinement link between the image and the ESBMC-proved witnesses.
pub use core::ptr::{read_volatile, write_volatile};

// ---- the verified core: the SPSC ring (witness shape, Rust) --------
pub struct Ring {
    pub buf: [u32; CAP],
    pub head: u32,   // producer index — ONE single-word store publishes
    pub tail: u32,   // consumer index
    pub posted: u32,
    pub dropped: u32,
    pub consumed: u32,
    pub high_water: u32,
}

pub const CAP: usize = 4;   // TCPIP_MBOX_SIZE / ready-slot count
pub const CAP_U: u32 = CAP as u32;

impl Ring {
    pub const fn new() -> Self {
        Ring { buf: [0; CAP], head: 0, tail: 0, posted: 0, dropped: 0,
               consumed: 0, high_water: 0 }
    }

    /// Producer side (driver context / irq wake). Returns false when
    /// the ring is full — lwIP returns ERR_MEM here; the kernel core
    /// DROPS, it never overflows.
    pub fn post(&mut self, value: u32) -> bool {
        let h = unsafe { read_volatile(&self.head) };
        if h - unsafe { read_volatile(&self.tail) } >= CAP_U {
            self.dropped += 1;          // backpressure, not corruption
            return false;
        }
        self.buf[(h % CAP_U) as usize] = value;
        // publish: ONE single-word store = the linearization point
        unsafe { write_volatile(&mut self.head, h + 1) };
        self.posted += 1;
        let used = h + 1 - unsafe { read_volatile(&self.tail) };
        if used > self.high_water { self.high_water = used; }
        true
    }

    /// Consumer side (tcpip thread / scheduler pick).
    pub fn fetch(&mut self) -> Option<u32> {
        let t = unsafe { read_volatile(&self.tail) };
        if t == unsafe { read_volatile(&self.head) } { return None; }
        let v = self.buf[(t % CAP_U) as usize];
        unsafe { write_volatile(&mut self.tail, t + 1) };  // lin. point
        self.consumed += 1;
        Some(v)
    }
}

// ---- M50: the MPSC endpoint (the name-server queue) -------------------
// The ESBMC-proved shape, exactly as the witness parameters it:
// LANES=2 (the syscall path + the kernel driver), LANE_CAP=1, CAP=2.
// Capacity is statically partitioned per producer — a shared-head
// enqueue has a real lost-update interleaving; a full lane DROPS
// (ERR_MEM backpressure), never overflows.
pub const IPC_LANES: usize = 2;
pub const IPC_LANE_CAP: usize = 1;
pub const IPC_CAP: usize = 2;

pub struct Mpsc {
    pub head: [u32; IPC_LANES],
    pub tail: [u32; IPC_LANES],
    pub buf: [[u32; IPC_LANE_CAP]; IPC_LANES],
    pub posted: u32,
    pub dropped: u32,
    pub consumed: u32,
    pub high_water: u32,
}

impl Mpsc {
    pub const fn new() -> Self {
        Mpsc { head: [0; IPC_LANES], tail: [0; IPC_LANES],
               buf: [[0; IPC_LANE_CAP]; IPC_LANES],
               posted: 0, dropped: 0, consumed: 0, high_water: 0 }
    }

    /// Producer side — lane i is written by exactly ONE producer (the
    /// linearization point is the single head store).
    pub fn post(&mut self, lane: usize, value: u32) -> bool {
        let h = unsafe { read_volatile(&self.head[lane]) };
        if h - unsafe { read_volatile(&self.tail[lane]) }
            >= IPC_LANE_CAP as u32 {
            self.dropped += 1;      // full lane: ERR_MEM, drop
            return false;
        }
        self.buf[lane][(h % IPC_LANE_CAP as u32) as usize] = value;
        unsafe { write_volatile(&mut self.head[lane], h + 1) };
        self.posted += 1;
        let mut used: u32 = 0;
        for l in 0..IPC_LANES {
            let h = unsafe { read_volatile(&self.head[l]) };
            let t = unsafe { read_volatile(&self.tail[l]) };
            used += h - t;
        }
        if used > self.high_water { self.high_water = used; }
        true
    }

    /// The ONE consumer (the name server), multiplexing lanes — the
    /// M36 SPSC shape per lane.
    pub fn fetch_any(&mut self) -> Option<u32> {
        for lane in 0..IPC_LANES {
            let t = unsafe { read_volatile(&self.tail[lane]) };
            if t < unsafe { read_volatile(&self.head[lane]) } {
                let v = self.buf[lane][(t % IPC_LANE_CAP as u32) as usize];
                unsafe { write_volatile(&mut self.tail[lane], t + 1) };
                self.consumed += 1;
                return Some(v);
            }
        }
        None
    }
}
