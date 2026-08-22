// FormalKernel production RV64 boot image — QEMU virt, no_std.
// This first deployment executes only the reviewed boot-order mechanism.
// It intentionally contains no S/U transition, Sv39, AIA, or H-extension path.
#![no_std]
#![no_main]

use core::arch::global_asm;
use core::panic::PanicInfo;
use core::ptr::{read_volatile, write_volatile};

mod boot_order;

const UART_THR: *mut u8 = 0x1000_0000 as *mut u8;
const UART_LSR: *const u8 = 0x1000_0005 as *const u8;

fn putc(byte: u8) {
    while unsafe { read_volatile(UART_LSR) } & (1 << 5) == 0 {}
    unsafe { write_volatile(UART_THR, byte) }
}

fn puts(text: &str) {
    for byte in text.bytes() {
        if byte == b'\n' { putc(b'\r'); }
        putc(byte);
    }
}

global_asm!(
    ".section .text.boot",
    ".global _start",
    "_start:",
    "la sp, __stack_top",
    "call rust_main",
    "1: wfi",
    "j 1b",
    ".section .bss.stack, \"aw\", @nobits",
    ".balign 16",
    "__stack_bottom:",
    ".space 16384",
    "__stack_top:"
);

#[no_mangle]
pub extern "C" fn rust_main() -> ! {
    puts("FORMALKERNEL_RV64_BEGIN\n");
    puts("COMPILED rv64_smode_boot\n");
    for step in boot_order::BOOT_ORDER {
        puts("BOOT ");
        puts(step);
        puts("\n");
    }
    puts("NOT_COMPILED su_transition sv39 aia hs_vs gstage vs_imsic guest_composition\n");
    puts("FORMALKERNEL_RV64_READY\n");
    loop { unsafe { core::arch::asm!("wfi") } }
}

#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    puts("FORMALKERNEL_RV64_PANIC\n");
    loop { unsafe { core::arch::asm!("wfi") } }
}
