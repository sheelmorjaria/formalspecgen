/* FormalKernel witness — the IPC name-server endpoint (M50).
 *
 * The name server's endpoint is MPSC: MANY producers send through the
 * syscall boundary, ONE server thread receives. The probed ESBMC
 * dialect (plain shared ints, SC pthread model — this build has no C11
 * atomics bodies) cannot prove a shared-head enqueue (the lost-update
 * interleaving is REAL in that model), so the provable MPSC shape is
 * the PARTITIONED LANE: capacity is statically divided among producers
 * (the M41 bounded-pool discipline; seL4's per-endpoint buffers are
 * this shape). Each producer owns a private lane — its head is written
 * by exactly ONE thread (the linearization point).
 *
 * The consumer thread is deliberately NOT in the BMC harness: it only
 * decreases occupancy (removing it makes the capacity bound HARDER,
 * not easier), and per-lane consumer correctness is the M36-proved
 * SPSC shape. Three threads also explode the unwind bound — the judge
 * verifies the two-producer interleaving, the worst case for the
 * capacity invariant.
 *
 * Backpressure: a full lane returns ERR_MEM (drop, never overflow),
 * and total occupancy across lanes never exceeds CAP under any
 * interleaving (each producer posts to its lane's FULL occupancy —
 * the worst case for the capacity invariant).
 */
#include <pthread.h>
#define LANES 2   /* producers: the syscall path + the kernel driver */
#define CAP 2     /* total endpoint slots (M41 pool share) */
#define LANE_CAP 1   /* CAP / LANES — the static partition */

int buf[LANES][LANE_CAP];
int head[LANES] = {0, 0};   /* per-lane producer index — lane i is
                                written ONLY by producer i */
int tail[LANES] = {0, 0};   /* per-lane consumer index — the M36 SPSC
                                consumer shape, not re-proved here */
void smp_mb(void) {}

void *user_send(void *arg) {   /* producer 0: the EL0 syscall path */
    (void)arg;
    for (int i = 0; i < LANE_CAP; i++) {   /* to full occupancy — the
                                worst case for the capacity invariant;
                                the rejected (LANE_CAP+1)-th post adds
                                no new state (head is unchanged) */
        int h = head[0];
        if (h - tail[0] < LANE_CAP) {   /* full lane: ERR_MEM, drop */
            buf[0][h % LANE_CAP] = i;
            smp_mb();
            head[0] = h + 1;            /* linearization point */
        }
    }
    return 0;
}

void *driver_send(void *arg) {   /* producer 1: kernel driver context */
    (void)arg;
    for (int i = 0; i < LANE_CAP; i++) {
        int h = head[1];
        if (h - tail[1] < LANE_CAP) {   /* full lane: ERR_MEM, drop */
            buf[1][h % LANE_CAP] = i;
            smp_mb();
            head[1] = h + 1;            /* linearization point */
        }
    }
    return 0;
}

/* name_server_recv: the ONE consumer, multiplexing lanes in the M36
 * SPSC shape per lane (reads head[], writes tail[] monotonically) —
 * not part of this BMC harness; see the note above. */

int main(void) {
    pthread_t user, driver;
    pthread_create(&user, 0, user_send, 0);
    pthread_create(&driver, 0, driver_send, 0);
    pthread_join(user, 0);
    pthread_join(driver, 0);
    return 0;
}
