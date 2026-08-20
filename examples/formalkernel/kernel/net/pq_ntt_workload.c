/* M60 bounded PQ arithmetic workload shape.
 * This is a timing witness, not a cryptographic implementation proof. */
#define NTT_LAYERS 8
#define NTT_WIDTH 256

extern void ntt_butterfly(unsigned int left, unsigned int right);
extern void cooperative_yield(void);

void pq_ntt_workload(void) {
    for (unsigned int layer = 0; layer < NTT_LAYERS; ++layer) {
        for (unsigned int pair = 0; pair < NTT_WIDTH / 2; ++pair) {
            ntt_butterfly(pair * 2, pair * 2 + 1);
        }
        /* Monolith boundary: one layer is the largest non-yielding chunk.
         * In the microkernel the same workload runs at EL0 and is preemptible. */
        cooperative_yield();
    }
}
