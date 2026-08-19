/* QEMU virt AArch64: -kernel loads the ELF at its link address. */
ENTRY(_start)
SECTIONS {
    . = 0x40000000;
    .text : { KEEP(*(.text.boot)) *(.text*) }
    .rodata : { *(.rodata*) }
    .data : { *(.data*) }
    .bss : { *(.bss*) *(COMMON) }
    /DISCARD/ : { *(.comment*) *(.eh_frame*) }
}
