/* Deterministic contract lowered from the reviewed V2 domain 'bounded_counter'.
 * Human review of the reviewed artifact is required before trust. */

typedef struct {
    int value;
} bounded_counter;

/*@
  requires \valid(counter);
  assigns counter->value;
  ensures counter->value == 0;
  ensures ((0 <= counter->value) && (counter->value <= 5)) && ((counter->value >= 0) && (counter->value <= 5));
*/
void bounded_counter_init(bounded_counter *counter) {
    counter->value = 0;
}

/*@
  requires \valid_read(counter);
  assigns \nothing;
  ensures \result == counter->value;
*/
int bounded_counter_get_value(const bounded_counter *counter) {
    return counter->value;
}

/*@
  requires \valid(counter);
  requires ((0 <= counter->value) && (counter->value <= 5)) && ((counter->value >= 0) && (counter->value <= 5));
  requires counter->value < 5;
  assigns counter->value;
  ensures counter->value == \old(counter->value) + 1;
  ensures ((0 <= counter->value) && (counter->value <= 5)) && ((counter->value >= 0) && (counter->value <= 5));
*/
void bounded_counter_increment(bounded_counter *counter) {
    int pre_value = counter->value;
    counter->value = pre_value + 1;
}

/*@
  requires \valid(counter);
  requires ((0 <= counter->value) && (counter->value <= 5)) && ((counter->value >= 0) && (counter->value <= 5));
  requires counter->value > 0;
  assigns counter->value;
  ensures counter->value == \old(counter->value) - 1;
  ensures ((0 <= counter->value) && (counter->value <= 5)) && ((counter->value >= 0) && (counter->value <= 5));
*/
void bounded_counter_decrement(bounded_counter *counter) {
    int pre_value = counter->value;
    counter->value = pre_value - 1;
}
