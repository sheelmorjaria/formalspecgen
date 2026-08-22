/* QEMU virt/OpenSBI loads the RV64 kernel at 0x80200000. */
OUTPUT_ARCH(riscv)
ENTRY(_start)
SECTIONS {
    . = 0x80200000;
    .text : { KEEP(*(.text.boot)) *(.text*) }
    .rodata : { *(.rodata*) }
    .data : { *(.data*) }
    .bss : { *(.bss*) *(COMMON) }
    /DISCARD/ : { *(.comment*) *(.eh_frame*) }
}
