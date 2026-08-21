/* Human-reviewed Cortex-R52 TCM placement model; SoC addresses remain a board assumption. */
ENTRY(_start)
MEMORY {
    ITCM (rx)  : ORIGIN = 0x00000000, LENGTH = 16K
    DTCM (rw)  : ORIGIN = 0x00004000, LENGTH = 16K
}
SECTIONS {
    .text : { KEEP(*(.text.boot)) *(.text*) } > ITCM
    .rodata : { *(.rodata*) } > ITCM
    .data : { *(.data*) } > DTCM
    .bss : { *(.bss*) *(COMMON) } > DTCM
    /DISCARD/ : { *(.comment*) *(.eh_frame*) }
}
