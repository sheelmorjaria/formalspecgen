/* FormalKernel witness — the scheduler ready runqueue.
 *
 * Producer: the timer/IRQ context waking a task (irq_wake); consumer:
 * the scheduler's pick loop (scheduler_pick) — one runnable slot array
 * with head/tail indices, the same SPSC contract as the net mbox
 * witness. ESBMC plain-int dialect (plan correction 2); smp_mb() is
 * the barrier the port layer must provide.
 */
#include <pthread.h>
#define CAP 4   /* ready-slot count (scheduler share, M41 table) */
int buf[CAP];   /* the ready-slot array */
int head = 0;
int tail = 0;
void smp_mb(void) {}

void *irq_wake(void *arg) {
    (void)arg;
    for (int i = 0; i < 3; i++) {
        int h = head;
        if (h - tail < CAP) {      /* runqueue full: the wake is dropped */
            buf[h % CAP] = i;
            smp_mb();
            head = h + 1;          /* linearization point */
        }
    }
    return 0;
}

void *scheduler_pick(void *arg) {
    (void)arg;
    for (int i = 0; i < 3; i++) {
        int t = tail;
        if (t < head) {
            buf[t % CAP];
            smp_mb();
            tail = t + 1;          /* linearization point */
        }
    }
    return 0;
}

int main(void) {
    pthread_t waker, picker;
    pthread_create(&waker, 0, irq_wake, 0);
    pthread_create(&picker, 0, scheduler_pick, 0);
    pthread_join(waker, 0);
    pthread_join(picker, 0);
    return 0;
}
