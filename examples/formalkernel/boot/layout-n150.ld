/* Human-reviewed x86_64 N150 image layout; firmware loading remains a platform assumption. */
ENTRY(_start)
SECTIONS {
    . = 0x00100000;
    .text : ALIGN(4096) { KEEP(*(.text.boot)) *(.text*) }
    .rodata : ALIGN(4096) { *(.rodata*) }
    .data : ALIGN(4096) { *(.data*) }
    .bss : ALIGN(4096) { *(.bss*) *(COMMON) }
    __kernel_image_end = .;
    ASSERT(__kernel_image_end <= 0x00200000, "N150 kernel image exceeds declared 1 MiB window")
    /DISCARD/ : { *(.comment*) *(.eh_frame*) }
}
