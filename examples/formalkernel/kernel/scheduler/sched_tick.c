/* FormalKernel deadline source — the scheduler tick.
 *
 * The ready list walk is bounded by the same silicon-derived capacity
 * as the timeout pool (M41 scheduler share); the tick must finish
 * inside the profile's max_cycles or the schedule slips.
 */
#define SYS_TIMEOUT_POOL_CAP 8   /* from derive_kernel_pools */

int sched_tick(int now, int ready_deadline[SYS_TIMEOUT_POOL_CAP]) {
    int due = 0;
    for (int i = 0; i < SYS_TIMEOUT_POOL_CAP; i++) {
        if (ready_deadline[i] <= now) {
            due = due + 1;       /* dispatch the runnable task */
        }
    }
    return due;
}
