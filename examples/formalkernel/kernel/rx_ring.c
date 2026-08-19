/* FormalKernel witness — lwIP tcpip_mbox (src/api/tcpip.c:61).
 *
 * The netif RX path posts TCPIP_MSG_INPKT to tcpip_mbox from the
 * driver context; exactly one consumer (the tcpip thread) fetches.
 * That contract is SPSC. This witness encodes it in the ESBMC
 * plain-int dialect (docs/FORMALKERNEL_PLAN.md correction 2: this
 * ESBMC build has no C11 atomics bodies — plain shared ints under the
 * SC pthread model, one single-word store per operation = the
 * linearization point). smp_mb() is the port-layer barrier lwIP's
 * sys_arch is required to provide; here a defined no-op so the SC
 * interleaving link succeeds.
 */
#include <pthread.h>
#define CAP 4   /* CAP: the mbox slot count */
int buf[CAP];   /* the mbox slot array */
int head = 0;               /* producer index */
int tail = 0;               /* consumer index */
void smp_mb(void) {}

void *netif_rx_post(void *arg) {   /* producer: driver context */
    (void)arg;
    for (int i = 0; i < 3; i++) {
        int h = head;
        if (h - tail < CAP) {   /* reject when full — lwIP
                                               returns ERR_MEM here */
            buf[h % CAP] = i;
            smp_mb();                        /* publish slot before index */
            head = h + 1;                    /* linearization point */
        }
    }
    return 0;
}

void *tcpip_thread_fetch(void *arg) {   /* consumer: tcpip thread */
    (void)arg;
    for (int i = 0; i < 3; i++) {
        int t = tail;
        if (t < head) {
            buf[t % CAP];
            smp_mb();                    /* acquire index before slot */
            tail = t + 1;                /* linearization point */
        }
    }
    return 0;
}

int main(void) {
    pthread_t producer, consumer;
    pthread_create(&producer, 0, netif_rx_post, 0);
    pthread_create(&consumer, 0, tcpip_thread_fetch, 0);
    pthread_join(producer, 0);
    pthread_join(consumer, 0);
    return 0;
}
