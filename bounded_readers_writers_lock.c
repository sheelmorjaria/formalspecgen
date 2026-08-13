/* Deterministic contract lowered from the reviewed V2 domain 'bounded_readers_writers_lock'.
 * Human review of the reviewed artifact is required before trust. */

typedef struct {
    int read_count;
    _Bool writer_active;
} bounded_readers_writers_lock;

/*@
  requires \valid(counter);
  assigns counter->read_count, counter->writer_active;
  ensures counter->read_count == 0 && counter->writer_active == 0;
  ensures (0 <= counter->read_count) && (counter->read_count <= 2) && (!(counter->writer_active && (counter->read_count > 0)));
*/
void bounded_readers_writers_lock_init(bounded_readers_writers_lock *counter) {
    counter->read_count = 0;
    counter->writer_active = 0;
}

/*@
  requires \valid_read(counter);
  assigns \nothing;
  ensures \result == counter->read_count;
*/
int bounded_readers_writers_lock_get_read_count(const bounded_readers_writers_lock *counter) {
    return counter->read_count;
}

/*@
  requires \valid_read(counter);
  assigns \nothing;
  ensures \result == counter->writer_active;
*/
_Bool bounded_readers_writers_lock_get_writer_active(const bounded_readers_writers_lock *counter) {
    return counter->writer_active;
}

/*@
  requires \valid(counter);
  requires (0 <= counter->read_count) && (counter->read_count <= 2) && (!(counter->writer_active && (counter->read_count > 0)));
  requires !(counter->writer_active);
  requires counter->read_count < 2;
  assigns counter->read_count;
  ensures counter->read_count == \old(counter->read_count) + 1;
  ensures (0 <= counter->read_count) && (counter->read_count <= 2) && (!(counter->writer_active && (counter->read_count > 0)));
*/
void bounded_readers_writers_lock_reader_enter(bounded_readers_writers_lock *counter) {
    int pre_read_count = counter->read_count;
    counter->read_count = pre_read_count + 1;
}

/*@
  requires \valid(counter);
  requires (0 <= counter->read_count) && (counter->read_count <= 2) && (!(counter->writer_active && (counter->read_count > 0)));
  requires counter->read_count > 0;
  assigns counter->read_count;
  ensures counter->read_count == \old(counter->read_count) - 1;
  ensures (0 <= counter->read_count) && (counter->read_count <= 2) && (!(counter->writer_active && (counter->read_count > 0)));
*/
void bounded_readers_writers_lock_reader_exit(bounded_readers_writers_lock *counter) {
    int pre_read_count = counter->read_count;
    counter->read_count = pre_read_count - 1;
}

/*@
  requires \valid(counter);
  requires (0 <= counter->read_count) && (counter->read_count <= 2) && (!(counter->writer_active && (counter->read_count > 0)));
  requires !(counter->writer_active);
  requires counter->read_count == 0;
  assigns counter->writer_active;
  ensures counter->writer_active == 1;
  ensures (0 <= counter->read_count) && (counter->read_count <= 2) && (!(counter->writer_active && (counter->read_count > 0)));
*/
void bounded_readers_writers_lock_writer_enter(bounded_readers_writers_lock *counter) {
    counter->writer_active = 1;
}

/*@
  requires \valid(counter);
  requires (0 <= counter->read_count) && (counter->read_count <= 2) && (!(counter->writer_active && (counter->read_count > 0)));
  requires counter->writer_active;
  assigns counter->writer_active;
  ensures counter->writer_active == 0;
  ensures (0 <= counter->read_count) && (counter->read_count <= 2) && (!(counter->writer_active && (counter->read_count > 0)));
*/
void bounded_readers_writers_lock_writer_exit(bounded_readers_writers_lock *counter) {
    counter->writer_active = 0;
}
