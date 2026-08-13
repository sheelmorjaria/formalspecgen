/* Deterministic contract lowered from the reviewed V2 domain 'smart_lock'.
 * Human review of the reviewed artifact is required before trust. */

typedef struct {
    int door_state;
    int lock_state;
} smart_lock;

/*@
  requires \valid(counter);
  assigns counter->door_state, counter->lock_state;
  ensures counter->door_state == 1 && counter->lock_state == 0;
  ensures ((0 <= counter->door_state) && (counter->door_state <= 1)) && ((0 <= counter->lock_state) && (counter->lock_state <= 1)) && ((counter->lock_state == 1) ==> (counter->door_state == 1));
*/
void smart_lock_init(smart_lock *counter) {
    counter->door_state = 1;
    counter->lock_state = 0;
}

/*@
  requires \valid_read(counter);
  assigns \nothing;
  ensures \result == counter->door_state;
*/
int smart_lock_get_door_state(const smart_lock *counter) {
    return counter->door_state;
}

/*@
  requires \valid_read(counter);
  assigns \nothing;
  ensures \result == counter->lock_state;
*/
int smart_lock_get_lock_state(const smart_lock *counter) {
    return counter->lock_state;
}

/*@
  requires \valid(counter);
  requires ((0 <= counter->door_state) && (counter->door_state <= 1)) && ((0 <= counter->lock_state) && (counter->lock_state <= 1)) && ((counter->lock_state == 1) ==> (counter->door_state == 1));
  requires counter->door_state == 0;
  requires counter->lock_state == 0;
  assigns counter->door_state;
  ensures counter->door_state == 1;
  ensures ((0 <= counter->door_state) && (counter->door_state <= 1)) && ((0 <= counter->lock_state) && (counter->lock_state <= 1)) && ((counter->lock_state == 1) ==> (counter->door_state == 1));
*/
void smart_lock_close_door(smart_lock *counter) {
    counter->door_state = 1;
}

/*@
  requires \valid(counter);
  requires ((0 <= counter->door_state) && (counter->door_state <= 1)) && ((0 <= counter->lock_state) && (counter->lock_state <= 1)) && ((counter->lock_state == 1) ==> (counter->door_state == 1));
  requires counter->door_state == 1;
  requires counter->lock_state == 0;
  assigns counter->door_state;
  ensures counter->door_state == 0;
  ensures ((0 <= counter->door_state) && (counter->door_state <= 1)) && ((0 <= counter->lock_state) && (counter->lock_state <= 1)) && ((counter->lock_state == 1) ==> (counter->door_state == 1));
*/
void smart_lock_open_door(smart_lock *counter) {
    counter->door_state = 0;
}

/*@
  requires \valid(counter);
  requires ((0 <= counter->door_state) && (counter->door_state <= 1)) && ((0 <= counter->lock_state) && (counter->lock_state <= 1)) && ((counter->lock_state == 1) ==> (counter->door_state == 1));
  requires counter->door_state == 1;
  requires counter->lock_state == 0;
  assigns counter->lock_state;
  ensures counter->lock_state == 1;
  ensures ((0 <= counter->door_state) && (counter->door_state <= 1)) && ((0 <= counter->lock_state) && (counter->lock_state <= 1)) && ((counter->lock_state == 1) ==> (counter->door_state == 1));
*/
void smart_lock_lock_door(smart_lock *counter) {
    counter->lock_state = 1;
}

/*@
  requires \valid(counter);
  requires ((0 <= counter->door_state) && (counter->door_state <= 1)) && ((0 <= counter->lock_state) && (counter->lock_state <= 1)) && ((counter->lock_state == 1) ==> (counter->door_state == 1));
  requires counter->lock_state == 1;
  assigns counter->lock_state;
  ensures counter->lock_state == 0;
  ensures ((0 <= counter->door_state) && (counter->door_state <= 1)) && ((0 <= counter->lock_state) && (counter->lock_state <= 1)) && ((counter->lock_state == 1) ==> (counter->door_state == 1));
*/
void smart_lock_unlock_door(smart_lock *counter) {
    counter->lock_state = 0;
}
