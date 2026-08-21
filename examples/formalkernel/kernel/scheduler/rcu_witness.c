#include <assert.h>
#include <pthread.h>

#define READERS 2

int global_epoch = 0;
int callback_epoch = -1;
int reader_epoch[READERS] = {0, 0};
int active[READERS] = {0, 0};
int reclaimed = 0;

void __ESBMC_atomic_begin(void);
void __ESBMC_atomic_end(void);

void *reader_zero(void *arg) {
    (void)arg;
    __ESBMC_atomic_begin();
    reader_epoch[0] = global_epoch;
    active[0] = 1;
    if (reader_epoch[0] != global_epoch) {
        active[0] = 0;
        __ESBMC_atomic_end();
        return 0;
    }
    assert(!reclaimed || reader_epoch[0] > callback_epoch);
    __ESBMC_atomic_end();
    __ESBMC_atomic_begin();
    active[0] = 0;
    __ESBMC_atomic_end();
    return 0;
}

void *reader_one(void *arg) {
    (void)arg;
    __ESBMC_atomic_begin();
    reader_epoch[1] = global_epoch;
    active[1] = 1;
    if (reader_epoch[1] != global_epoch) {
        active[1] = 0;
        __ESBMC_atomic_end();
        return 0;
    }
    assert(!reclaimed || reader_epoch[1] > callback_epoch);
    __ESBMC_atomic_end();
    __ESBMC_atomic_begin();
    active[1] = 0;
    __ESBMC_atomic_end();
    return 0;
}

void *updater(void *arg) {
    (void)arg;
    __ESBMC_atomic_begin();
    callback_epoch = global_epoch;
    global_epoch = global_epoch + 1;
    __ESBMC_atomic_end();
    __ESBMC_atomic_begin();
    if ((!active[0] || reader_epoch[0] > callback_epoch) &&
        (!active[1] || reader_epoch[1] > callback_epoch)) {
        reclaimed = 1;
    }
    if (reclaimed) {
        assert(!active[0] || reader_epoch[0] > callback_epoch);
        assert(!active[1] || reader_epoch[1] > callback_epoch);
    }
    __ESBMC_atomic_end();
    return 0;
}

int main(void) {
    pthread_t first;
    pthread_t second;
    pthread_t update;
    pthread_create(&first, 0, reader_zero, 0);
    pthread_create(&second, 0, reader_one, 0);
    pthread_create(&update, 0, updater, 0);
    pthread_join(first, 0);
    pthread_join(second, 0);
    pthread_join(update, 0);
    assert(!reclaimed || (!active[0] && !active[1]));
    return 0;
}
