// FormalKernel lowering — the lwIP sys_timeouts tick (kernel/timer_tick.c)
// as the verified Rust core: bounded walk over the MEMP_SYS_TIMEOUT pool
// whose capacity derive_kernel_pools sizes from silicon.
#[no_mangle]
pub fn timer_tick(mut entries: i32) -> i32 {
    let mut fired = 0;
    while entries > 0 {
        fired = fired + 1;
        entries = entries - 1;
    }
    fired
}
