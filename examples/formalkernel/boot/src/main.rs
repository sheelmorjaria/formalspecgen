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

    // ---- M48: enable the real MMU, then probe the hole -------------
    uart_puts("MMU_ON\n");
    mmu_init();
    isolation_probe();        // must trap into fault_handler

    uart_puts("HALT\n");
    loop {
        unsafe { asm!("wfe") };   // wait-for-event: the honest halt
    }
}


// ---- M48: the real MMU — identity map + one deliberate hole --------
// Stage-1, 4KB granule, 2MB block mappings:
//   VA 0x00000000-0x40000000 : device (covers the PL011 UART)
//   VA 0x40000000-0x41000000 : normal (kernel + dtb region)
//   VA 0x41000000            : INVALID — the isolation hole
//   VA 0x41200000-0x48000000 : normal (the rest of virt RAM)
// A store into the hole must take a synchronous exception to OUR
// vector handler — the runtime sample for SPATIAL_ISOLATION_PROVED.

#[repr(align(0x1000))]
struct Table([u64; 512]);
static mut L0: Table = Table([0; 512]);
static mut L1_LOW: Table = Table([0; 512]);   // VA 0..1GB
static mut L2_HIGH: Table = Table([0; 512]);  // VA 0x40000000.. pairs

const ATTR_NORMAL: u64 = 0;   // MAIR attr0
const ATTR_DEVICE: u64 = 1;   // MAIR attr1
pub const ISOLATION_HOLE: usize = 0x41000000;   // unmapped on purpose

fn block_desc(pa: usize, attr: u64) -> u64 {
    // valid 2MB block: AF | SH=inner | MAIR | NX | addr[51:21]
    ((pa as u64) & 0x0000_FFFF_FFFE_0000) | (1 << 10) | (3 << 8)
        | (attr << 2) | (1 << 54) | 1
}

fn table_desc(table: *const Table) -> u64 {
    ((table as u64) & 0x0000_FFFF_FFFF_F000) | (3 << 8) | 3  // table
}

pub fn mmu_init() {
    unsafe {
        // low 1GB as device (UART lives there); one L2 walk is not
        // needed — L1_LOW[0] is a 1GB block descriptor
        L1_LOW.0[0] = block_desc(0, ATTR_DEVICE);
        L0.0[0] = table_desc(&L1_LOW);
        // the kernel's first 1GB: L1_HIGH[0] walks L2_HIGH 2MB blocks
        for j in 0..64u64 {                    // 0x40000000..0x48000000
            let pa = 0x4000_0000 + (j as usize) * 0x20_0000;
            L2_HIGH.0[j as usize] = block_desc(pa, ATTR_NORMAL);
        }
        L2_HIGH.0[8] = 0;                      // 0x41000000: the HOLE
        // THE WALK FIX: L0[0] spans VA 0..512GB — the kernel's 1GB
        // bank (0x40000000..0x80000000) is L1_LOW[1], NOT L0[1].
        L1_LOW.0[1] = table_desc(&L2_HIGH);
        core::arch::asm!(
            "dsb sy",
            "msr ttbr0_el1, {ttbr}",
            "msr tcr_el1, {tcr}",
            "msr mair_el1, {mair}",
            "msr vbar_el1, {vbar}",
            "isb",
            ttbr = in(reg) &raw const L0,
            tcr = in(reg) 0x3510u64,   // T0SZ=16 4KB SH0=3 WBWA
            mair = in(reg) 0x00FFu64,  // attr0=0xFF normal, attr1=0x00 device
            vbar = in(reg) &raw const vectors as u64,
        );
        // invalidate the TLB, then turn the MMU on
        core::arch::asm!(
            "tlbi vmalle1", "dsb sy", "isb",
            "mrs {sctlr}, sctlr_el1",
            "orr {sctlr}, {sctlr}, 1",
            "msr sctlr_el1, {sctlr}",
            "isb",
            sctlr = out(reg) _,
        );
    }
}

/// The proof point: store into the unmapped hole. With the map from
/// the SPATIAL_ISOLATION_PROVED family this MUST trap (the address is
/// deliberately in no region); the vector handler answers.
pub fn isolation_probe() {
    unsafe {
        let hole = ISOLATION_HOLE as *mut u64;
        core::arch::asm!(
            "str {val}, [{addr}]",
            val = in(reg) 0xdead_beefu64,
            addr = in(reg) hole,
        );
    }
    // unreachable when the trap fires; printed only if isolation FAILED
    uart_puts("ISOLATION_FAILED store landed\n");
}

// 16 vector slots x 0x80 bytes (0x800 total); every slot funnels to
// the handler — only the synchronous slots are expected to fire.
core::arch::global_asm!(
    ".section .text.boot",
    ".balign 0x800",
    ".global vectors",
    "vectors:",
    ".rept 16",
    "  b fault_handler",
    "  .space 0x7c",
    ".endr",
);

unsafe extern "C" {
    static vectors: u8;   // the assembly vector table's address
}

#[no_mangle]
pub extern "C" fn fault_handler() -> ! {
    let far: u64;
    unsafe { core::arch::asm!("mrs {far}, far_el1", far = out(reg) far); }
    uart_puts("FAULT far=0x");
    uart_puthex(far);
    uart_puts(" ISOLATION_TRAP\n");
    uart_puts("HALT\n");
    loop { unsafe { asm!("wfe") }; }
}

fn uart_puthex(mut v: u64) {
    let mut started = false;
    for shift in (0..=60).rev().step_by(4) {
        let nibble = ((v >> shift) & 0xF) as u8;
        if nibble != 0 || started || shift == 0 {
            uart_putc(if nibble < 10 { b'0' + nibble }
                     else { b'a' + nibble - 10 });
            started = true;
        }
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    uart_puts("PANIC\n");
    loop {}
}
