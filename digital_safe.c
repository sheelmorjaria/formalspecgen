/* Deterministic contract lowered from the reviewed V2 domain 'digital_safe'.
 * Human review of the reviewed artifact is required before trust. */

typedef struct {
    int safe_state;
    int attempts;
} digital_safe;

/*@
  requires \valid(counter);
  assigns counter->safe_state, counter->attempts;
  ensures counter->safe_state == 0 && counter->attempts == 0;
  ensures (0 <= counter->safe_state) && (counter->safe_state <= 2) && (0 <= counter->attempts) && (counter->attempts <= 3) && ((counter->safe_state == 1) ==> (counter->attempts == 0)) && ((counter->safe_state == 2) ==> (counter->attempts == 3));
*/
void digital_safe_init(digital_safe *counter) {
    counter->safe_state = 0;
    counter->attempts = 0;
}

/*@
  requires \valid_read(counter);
  assigns \nothing;
  ensures \result == counter->safe_state;
*/
int digital_safe_get_safe_state(const digital_safe *counter) {
    return counter->safe_state;
}

/*@
  requires \valid_read(counter);
  assigns \nothing;
  ensures \result == counter->attempts;
*/
int digital_safe_get_attempts(const digital_safe *counter) {
    return counter->attempts;
}

/*@
  requires \valid(counter);
  requires (0 <= counter->safe_state) && (counter->safe_state <= 2) && (0 <= counter->attempts) && (counter->attempts <= 3) && ((counter->safe_state == 1) ==> (counter->attempts == 0)) && ((counter->safe_state == 2) ==> (counter->attempts == 3));
  requires counter->safe_state == 0;
  requires counter->attempts == 0;
  assigns counter->safe_state;
  ensures counter->safe_state == 1;
  ensures (0 <= counter->safe_state) && (counter->safe_state <= 2) && (0 <= counter->attempts) && (counter->attempts <= 3) && ((counter->safe_state == 1) ==> (counter->attempts == 0)) && ((counter->safe_state == 2) ==> (counter->attempts == 3));
*/
void digital_safe_unlock(digital_safe *counter) {
    counter->safe_state = 1;
}

/*@
  requires \valid(counter);
  requires (0 <= counter->safe_state) && (counter->safe_state <= 2) && (0 <= counter->attempts) && (counter->attempts <= 3) && ((counter->safe_state == 1) ==> (counter->attempts == 0)) && ((counter->safe_state == 2) ==> (counter->attempts == 3));
  requires counter->safe_state == 0;
  requires counter->attempts < 2;
  assigns counter->attempts;
  ensures counter->attempts == \old(counter->attempts) + 1;
  ensures (0 <= counter->safe_state) && (counter->safe_state <= 2) && (0 <= counter->attempts) && (counter->attempts <= 3) && ((counter->safe_state == 1) ==> (counter->attempts == 0)) && ((counter->safe_state == 2) ==> (counter->attempts == 3));
*/
void digital_safe_fail_attempt(digital_safe *counter) {
    int pre_attempts = counter->attempts;
    counter->attempts = pre_attempts + 1;
}

/*@
  requires \valid(counter);
  requires (0 <= counter->safe_state) && (counter->safe_state <= 2) && (0 <= counter->attempts) && (counter->attempts <= 3) && ((counter->safe_state == 1) ==> (counter->attempts == 0)) && ((counter->safe_state == 2) ==> (counter->attempts == 3));
  requires counter->safe_state == 0;
  requires counter->attempts == 2;
  assigns counter->safe_state, counter->attempts;
  ensures counter->safe_state == 2 && counter->attempts == 3;
  ensures (0 <= counter->safe_state) && (counter->safe_state <= 2) && (0 <= counter->attempts) && (counter->attempts <= 3) && ((counter->safe_state == 1) ==> (counter->attempts == 0)) && ((counter->safe_state == 2) ==> (counter->attempts == 3));
*/
void digital_safe_block_safe(digital_safe *counter) {
    counter->safe_state = 2;
    counter->attempts = 3;
}

/*@
  requires \valid(counter);
  requires (0 <= counter->safe_state) && (counter->safe_state <= 2) && (0 <= counter->attempts) && (counter->attempts <= 3) && ((counter->safe_state == 1) ==> (counter->attempts == 0)) && ((counter->safe_state == 2) ==> (counter->attempts == 3));
  requires counter->safe_state == 1;
  assigns counter->safe_state, counter->attempts;
  ensures counter->safe_state == 0 && counter->attempts == 0;
  ensures (0 <= counter->safe_state) && (counter->safe_state <= 2) && (0 <= counter->attempts) && (counter->attempts <= 3) && ((counter->safe_state == 1) ==> (counter->attempts == 0)) && ((counter->safe_state == 2) ==> (counter->attempts == 3));
*/
void digital_safe_lock(digital_safe *counter) {
    counter->safe_state = 0;
    counter->attempts = 0;
}

/*@
  requires \valid(counter);
  requires (0 <= counter->safe_state) && (counter->safe_state <= 2) && (0 <= counter->attempts) && (counter->attempts <= 3) && ((counter->safe_state == 1) ==> (counter->attempts == 0)) && ((counter->safe_state == 2) ==> (counter->attempts == 3));
  requires counter->safe_state == 2;
  assigns counter->safe_state, counter->attempts;
  ensures counter->safe_state == 0 && counter->attempts == 0;
  ensures (0 <= counter->safe_state) && (counter->safe_state <= 2) && (0 <= counter->attempts) && (counter->attempts <= 3) && ((counter->safe_state == 1) ==> (counter->attempts == 0)) && ((counter->safe_state == 2) ==> (counter->attempts == 3));
*/
void digital_safe_admin_reset(digital_safe *counter) {
    counter->safe_state = 0;
    counter->attempts = 0;
}
