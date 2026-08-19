/* FormalKernel deadline source — lwIP sys_timeouts tick
 * (src/core/timeouts.c: sys_timeouts_mbox_fetch walks next_timeout,
 * a singly-linked intrusive list of struct sys_timeo allocated from
 * the bounded MEMP_SYS_TIMEOUT pool).
 *
 * Bounded shape: the pool capacity (derived from silicon in
 * hardware_profile.json as the sys_timeouts subsystem) bounds the
 * walk; the tick must finish inside the profile's max_cycles.
 */
#define SYS_TIMEOUT_POOL_CAP 8     /* from derive_kernel_pools */

int timer_tick(int now, int timeouts_time[SYS_TIMEOUT_POOL_CAP]) {
    int fired = 0;
    for (int i = 0; i < SYS_TIMEOUT_POOL_CAP; i++) {
        if (timeouts_time[i] <= now) {
            fired = fired + 1;     /* sys_timeout handler dispatch */
        }
    }
    return fired;
}
