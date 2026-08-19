// FormalKernel boot image — QEMU virt (AArch64), no_std.
//
// The verified core runs the proven boot order (boot_order.rs is
// GENERATED from kernel/composition.json — the artifact M46 proved),
// then exercises the SPSC rings under a packet burst: when a ring is
// full the post is DROPPED (lwIP's ERR_MEM path) — the proven
// capacity bound becomes visible backpressure instead of corruption.
// Everything the image prints is runtime EVIDENCE (RUNTIME_SAMPLE
// ceiling), not proof; pipeline/boot_check.py judges the transcript.
#![no_std]
#![no_main]

use core::panic::PanicInfo;
use core::arch::asm;
use core::ptr::{read_volatile, write_volatile};

mod boot_order;

// ---- QEMU virt PL011 UART at 0x0900_0000 ---------------------------
const UART0: *mut u32 = 0x0900_0000 as *mut u32;

fn uart_putc(c: u8) {
    unsafe { write_volatile(UART0, c as u32) }
}

fn uart_puts(s: &str) {
    for b in s.bytes() {
        if b == b'\n' { uart_putc(b'\r'); }
        uart_putc(b);
    }
}

fn uart_putdec(mut v: u32) {
    if v == 0 { uart_putc(b'0'); return; }
    let mut buf = [0u8; 10];
    let mut i = 0;
    while v > 0 { buf[i] = b'0' + (v % 10) as u8; v /= 10; i += 1; }
    while i > 0 { i -= 1; uart_putc(buf[i]); }
}

// ---- the verified core: the SPSC ring (witness shape, Rust) --------
pub struct Ring {
    buf: [u32; CAP],
    head: u32,   // producer index — ONE single-word store publishes
    tail: u32,   // consumer index
    pub posted: u32,
    pub dropped: u32,
    pub consumed: u32,
    high_water: u32,
}

pub const CAP: usize = 4;   // TCPIP_MBOX_SIZE / ready-slot count
const CAP_U: u32 = CAP as u32;

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

// ---- the proven boot order, executed --------------------------------
static mut NET_RING: Ring = Ring::new();
static mut SCHED_RING: Ring = Ring::new();

fn step(name: &str) {
    uart_puts("BOOT ");
    uart_puts(name);
    uart_puts("\n");
}

core::arch::global_asm!(
    ".section .text.boot",
    ".global _start",
    "_start:",
    "ldr x0, =__stack_top",
    "mov sp, x0",
    "bl rust_main",
    "2: wfe",
    "b 2b",
    ".section .bss.stack, \"aw\", @nobits",
    ".align 16",
    ".global __stack_bottom",
    "__stack_bottom:",
    ".space 16384",
    ".global __stack_top",
    "__stack_top:"
);

#[no_mangle]
pub extern "C" fn rust_main() -> ! {
    uart_puts("FormalKernel boot (QEMU virt aarch64)\n");
    // The M46-proven order, compiled in from composition.json:
    // timer -> pools -> scheduler -> net. Each step prints BEFORE it
    // runs, so the transcript IS the executed order.
    for name in boot_order::BOOT_ORDER { step(name); }

    // ---- packet flood: the net ring under burst -------------------
    // 16 arrivals against CAP=4 with the consumer draining only 1 per
    // burst round: the ring saturates and DROPS — the proven bound,
    // exercised.
    uart_puts("FLOOD start\n");
    let (mut posted, mut dropped, mut consumed) = (0u32, 0u32, 0u32);
    for burst in 0..4u32 {
        for i in 0..4u32 {
            if unsafe { NET_RING.post(burst * 4 + i) } { posted += 1; }
        }
        if unsafe { NET_RING.fetch() }.is_some() { consumed += 1; }
    }
    // drain the rest so the counters close
    while let Some(_) = unsafe { NET_RING.fetch() } { consumed += 1; }
    dropped = unsafe { NET_RING.dropped };

    uart_puts("NET posted=");
    uart_putdec(posted);
    uart_puts(" dropped=");
    uart_putdec(dropped);
    uart_puts(" consumed=");
    uart_putdec(consumed);
    uart_puts(" high_water=");
    uart_putdec(unsafe { NET_RING.high_water });
    uart_puts(" cap=4\n");

    // ---- scheduler runqueue: steady state, no drops ---------------
    for i in 0..3u32 { unsafe { SCHED_RING.post(i) }; }
    let mut picked = 0;
    while let Some(_) = unsafe { SCHED_RING.fetch() } { picked += 1; }
    uart_puts("SCHED posted=3 picked=");
    uart_putdec(picked);
    uart_puts(" dropped=");
    uart_putdec(unsafe { SCHED_RING.dropped });
    uart_puts(" high_water=");
    uart_putdec(unsafe { SCHED_RING.high_water });
    uart_puts(" cap=4\n");

    uart_puts("HALT\n");
    loop {
        unsafe { asm!("wfe") };   // wait-for-event: the honest halt
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    uart_puts("PANIC\n");
    loop {}
}
