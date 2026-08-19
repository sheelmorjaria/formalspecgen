// GENERATED from examples/formalkernel/kernel/composition.json by
// scripts/gen_boot_order.py — do not edit by hand.
// The proven (M46) boot order, compiled into the image:
pub const BOOT_ORDER: [&str; 4] = [
    "timer_init",
    "pool_init",
    "scheduler_start",
    "net_start",
];
pub const FACTS: [&str; 4] = [
    "packet_path_up",
    "pools_mapped",
    "runqueue_ready",
    "timer_running",
];
