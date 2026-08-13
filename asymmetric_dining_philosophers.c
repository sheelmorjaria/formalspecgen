/* Deterministic contract lowered from the reviewed V2 domain 'asymmetric_dining_philosophers'.
 * Human review of the reviewed artifact is required before trust. */

typedef struct {
    int fork0;
    int fork1;
    int fork2;
    int pc0;
    int pc1;
    int pc2;
} asymmetric_dining_philosophers;

/*@
  requires \valid(counter);
  assigns counter->fork0, counter->fork1, counter->fork2, counter->pc0, counter->pc1, counter->pc2;
  ensures counter->fork0 == 0 && counter->fork1 == 0 && counter->fork2 == 0 && counter->pc0 == 0 && counter->pc1 == 0 && counter->pc2 == 0;
  ensures (0 <= counter->fork0) && (counter->fork0 <= 3) && (0 <= counter->fork1) && (counter->fork1 <= 3) && (0 <= counter->fork2) && (counter->fork2 <= 3) && (0 <= counter->pc0) && (counter->pc0 <= 3) && (0 <= counter->pc1) && (counter->pc1 <= 3) && (0 <= counter->pc2) && (counter->pc2 <= 3) && ((counter->pc0 == 3) ==> ((counter->fork0 == 1) && (counter->fork1 == 1))) && ((counter->pc1 == 3) ==> ((counter->fork1 == 2) && (counter->fork2 == 2))) && ((counter->pc2 == 3) ==> ((counter->fork2 == 3) && (counter->fork0 == 3)));
*/
void asymmetric_dining_philosophers_init(asymmetric_dining_philosophers *counter) {
    counter->fork0 = 0;
    counter->fork1 = 0;
    counter->fork2 = 0;
    counter->pc0 = 0;
    counter->pc1 = 0;
    counter->pc2 = 0;
}

/*@
  requires \valid_read(counter);
  assigns \nothing;
  ensures \result == counter->fork0;
*/
int asymmetric_dining_philosophers_get_fork0(const asymmetric_dining_philosophers *counter) {
    return counter->fork0;
}

/*@
  requires \valid_read(counter);
  assigns \nothing;
  ensures \result == counter->fork1;
*/
int asymmetric_dining_philosophers_get_fork1(const asymmetric_dining_philosophers *counter) {
    return counter->fork1;
}

/*@
  requires \valid_read(counter);
  assigns \nothing;
  ensures \result == counter->fork2;
*/
int asymmetric_dining_philosophers_get_fork2(const asymmetric_dining_philosophers *counter) {
    return counter->fork2;
}

/*@
  requires \valid_read(counter);
  assigns \nothing;
  ensures \result == counter->pc0;
*/
int asymmetric_dining_philosophers_get_pc0(const asymmetric_dining_philosophers *counter) {
    return counter->pc0;
}

/*@
  requires \valid_read(counter);
  assigns \nothing;
  ensures \result == counter->pc1;
*/
int asymmetric_dining_philosophers_get_pc1(const asymmetric_dining_philosophers *counter) {
    return counter->pc1;
}

/*@
  requires \valid_read(counter);
  assigns \nothing;
  ensures \result == counter->pc2;
*/
int asymmetric_dining_philosophers_get_pc2(const asymmetric_dining_philosophers *counter) {
    return counter->pc2;
}

/*@
  requires \valid(counter);
  requires (0 <= counter->fork0) && (counter->fork0 <= 3) && (0 <= counter->fork1) && (counter->fork1 <= 3) && (0 <= counter->fork2) && (counter->fork2 <= 3) && (0 <= counter->pc0) && (counter->pc0 <= 3) && (0 <= counter->pc1) && (counter->pc1 <= 3) && (0 <= counter->pc2) && (counter->pc2 <= 3) && ((counter->pc0 == 3) ==> ((counter->fork0 == 1) && (counter->fork1 == 1))) && ((counter->pc1 == 3) ==> ((counter->fork1 == 2) && (counter->fork2 == 2))) && ((counter->pc2 == 3) ==> ((counter->fork2 == 3) && (counter->fork0 == 3)));
  requires counter->pc0 == 0;
  assigns counter->pc0;
  ensures counter->pc0 == 1;
  ensures (0 <= counter->fork0) && (counter->fork0 <= 3) && (0 <= counter->fork1) && (counter->fork1 <= 3) && (0 <= counter->fork2) && (counter->fork2 <= 3) && (0 <= counter->pc0) && (counter->pc0 <= 3) && (0 <= counter->pc1) && (counter->pc1 <= 3) && (0 <= counter->pc2) && (counter->pc2 <= 3) && ((counter->pc0 == 3) ==> ((counter->fork0 == 1) && (counter->fork1 == 1))) && ((counter->pc1 == 3) ==> ((counter->fork1 == 2) && (counter->fork2 == 2))) && ((counter->pc2 == 3) ==> ((counter->fork2 == 3) && (counter->fork0 == 3)));
*/
void asymmetric_dining_philosophers_request_0(asymmetric_dining_philosophers *counter) {
    counter->pc0 = 1;
}

/*@
  requires \valid(counter);
  requires (0 <= counter->fork0) && (counter->fork0 <= 3) && (0 <= counter->fork1) && (counter->fork1 <= 3) && (0 <= counter->fork2) && (counter->fork2 <= 3) && (0 <= counter->pc0) && (counter->pc0 <= 3) && (0 <= counter->pc1) && (counter->pc1 <= 3) && (0 <= counter->pc2) && (counter->pc2 <= 3) && ((counter->pc0 == 3) ==> ((counter->fork0 == 1) && (counter->fork1 == 1))) && ((counter->pc1 == 3) ==> ((counter->fork1 == 2) && (counter->fork2 == 2))) && ((counter->pc2 == 3) ==> ((counter->fork2 == 3) && (counter->fork0 == 3)));
  requires counter->pc0 == 1;
  requires counter->fork1 == 0;
  assigns counter->fork1, counter->pc0;
  ensures counter->fork1 == 1 && counter->pc0 == 2;
  ensures (0 <= counter->fork0) && (counter->fork0 <= 3) && (0 <= counter->fork1) && (counter->fork1 <= 3) && (0 <= counter->fork2) && (counter->fork2 <= 3) && (0 <= counter->pc0) && (counter->pc0 <= 3) && (0 <= counter->pc1) && (counter->pc1 <= 3) && (0 <= counter->pc2) && (counter->pc2 <= 3) && ((counter->pc0 == 3) ==> ((counter->fork0 == 1) && (counter->fork1 == 1))) && ((counter->pc1 == 3) ==> ((counter->fork1 == 2) && (counter->fork2 == 2))) && ((counter->pc2 == 3) ==> ((counter->fork2 == 3) && (counter->fork0 == 3)));
*/
void asymmetric_dining_philosophers_pickup_right_0(asymmetric_dining_philosophers *counter) {
    counter->fork1 = 1;
    counter->pc0 = 2;
}

/*@
  requires \valid(counter);
  requires (0 <= counter->fork0) && (counter->fork0 <= 3) && (0 <= counter->fork1) && (counter->fork1 <= 3) && (0 <= counter->fork2) && (counter->fork2 <= 3) && (0 <= counter->pc0) && (counter->pc0 <= 3) && (0 <= counter->pc1) && (counter->pc1 <= 3) && (0 <= counter->pc2) && (counter->pc2 <= 3) && ((counter->pc0 == 3) ==> ((counter->fork0 == 1) && (counter->fork1 == 1))) && ((counter->pc1 == 3) ==> ((counter->fork1 == 2) && (counter->fork2 == 2))) && ((counter->pc2 == 3) ==> ((counter->fork2 == 3) && (counter->fork0 == 3)));
  requires counter->pc0 == 2;
  requires counter->fork1 == 1;
  requires counter->fork0 == 0;
  assigns counter->fork0, counter->pc0;
  ensures counter->fork0 == 1 && counter->pc0 == 3;
  ensures (0 <= counter->fork0) && (counter->fork0 <= 3) && (0 <= counter->fork1) && (counter->fork1 <= 3) && (0 <= counter->fork2) && (counter->fork2 <= 3) && (0 <= counter->pc0) && (counter->pc0 <= 3) && (0 <= counter->pc1) && (counter->pc1 <= 3) && (0 <= counter->pc2) && (counter->pc2 <= 3) && ((counter->pc0 == 3) ==> ((counter->fork0 == 1) && (counter->fork1 == 1))) && ((counter->pc1 == 3) ==> ((counter->fork1 == 2) && (counter->fork2 == 2))) && ((counter->pc2 == 3) ==> ((counter->fork2 == 3) && (counter->fork0 == 3)));
*/
void asymmetric_dining_philosophers_pickup_left_0(asymmetric_dining_philosophers *counter) {
    counter->fork0 = 1;
    counter->pc0 = 3;
}

/*@
  requires \valid(counter);
  requires (0 <= counter->fork0) && (counter->fork0 <= 3) && (0 <= counter->fork1) && (counter->fork1 <= 3) && (0 <= counter->fork2) && (counter->fork2 <= 3) && (0 <= counter->pc0) && (counter->pc0 <= 3) && (0 <= counter->pc1) && (counter->pc1 <= 3) && (0 <= counter->pc2) && (counter->pc2 <= 3) && ((counter->pc0 == 3) ==> ((counter->fork0 == 1) && (counter->fork1 == 1))) && ((counter->pc1 == 3) ==> ((counter->fork1 == 2) && (counter->fork2 == 2))) && ((counter->pc2 == 3) ==> ((counter->fork2 == 3) && (counter->fork0 == 3)));
  requires counter->pc0 == 3;
  requires counter->fork0 == 1;
  requires counter->fork1 == 1;
  assigns counter->fork0, counter->fork1, counter->pc0;
  ensures counter->fork0 == 0 && counter->fork1 == 0 && counter->pc0 == 0;
  ensures (0 <= counter->fork0) && (counter->fork0 <= 3) && (0 <= counter->fork1) && (counter->fork1 <= 3) && (0 <= counter->fork2) && (counter->fork2 <= 3) && (0 <= counter->pc0) && (counter->pc0 <= 3) && (0 <= counter->pc1) && (counter->pc1 <= 3) && (0 <= counter->pc2) && (counter->pc2 <= 3) && ((counter->pc0 == 3) ==> ((counter->fork0 == 1) && (counter->fork1 == 1))) && ((counter->pc1 == 3) ==> ((counter->fork1 == 2) && (counter->fork2 == 2))) && ((counter->pc2 == 3) ==> ((counter->fork2 == 3) && (counter->fork0 == 3)));
*/
void asymmetric_dining_philosophers_putdown_0(asymmetric_dining_philosophers *counter) {
    counter->fork0 = 0;
    counter->fork1 = 0;
    counter->pc0 = 0;
}

/*@
  requires \valid(counter);
  requires (0 <= counter->fork0) && (counter->fork0 <= 3) && (0 <= counter->fork1) && (counter->fork1 <= 3) && (0 <= counter->fork2) && (counter->fork2 <= 3) && (0 <= counter->pc0) && (counter->pc0 <= 3) && (0 <= counter->pc1) && (counter->pc1 <= 3) && (0 <= counter->pc2) && (counter->pc2 <= 3) && ((counter->pc0 == 3) ==> ((counter->fork0 == 1) && (counter->fork1 == 1))) && ((counter->pc1 == 3) ==> ((counter->fork1 == 2) && (counter->fork2 == 2))) && ((counter->pc2 == 3) ==> ((counter->fork2 == 3) && (counter->fork0 == 3)));
  requires counter->pc1 == 0;
  assigns counter->pc1;
  ensures counter->pc1 == 1;
  ensures (0 <= counter->fork0) && (counter->fork0 <= 3) && (0 <= counter->fork1) && (counter->fork1 <= 3) && (0 <= counter->fork2) && (counter->fork2 <= 3) && (0 <= counter->pc0) && (counter->pc0 <= 3) && (0 <= counter->pc1) && (counter->pc1 <= 3) && (0 <= counter->pc2) && (counter->pc2 <= 3) && ((counter->pc0 == 3) ==> ((counter->fork0 == 1) && (counter->fork1 == 1))) && ((counter->pc1 == 3) ==> ((counter->fork1 == 2) && (counter->fork2 == 2))) && ((counter->pc2 == 3) ==> ((counter->fork2 == 3) && (counter->fork0 == 3)));
*/
void asymmetric_dining_philosophers_request_1(asymmetric_dining_philosophers *counter) {
    counter->pc1 = 1;
}

/*@
  requires \valid(counter);
  requires (0 <= counter->fork0) && (counter->fork0 <= 3) && (0 <= counter->fork1) && (counter->fork1 <= 3) && (0 <= counter->fork2) && (counter->fork2 <= 3) && (0 <= counter->pc0) && (counter->pc0 <= 3) && (0 <= counter->pc1) && (counter->pc1 <= 3) && (0 <= counter->pc2) && (counter->pc2 <= 3) && ((counter->pc0 == 3) ==> ((counter->fork0 == 1) && (counter->fork1 == 1))) && ((counter->pc1 == 3) ==> ((counter->fork1 == 2) && (counter->fork2 == 2))) && ((counter->pc2 == 3) ==> ((counter->fork2 == 3) && (counter->fork0 == 3)));
  requires counter->pc1 == 1;
  requires counter->fork1 == 0;
  assigns counter->fork1, counter->pc1;
  ensures counter->fork1 == 2 && counter->pc1 == 2;
  ensures (0 <= counter->fork0) && (counter->fork0 <= 3) && (0 <= counter->fork1) && (counter->fork1 <= 3) && (0 <= counter->fork2) && (counter->fork2 <= 3) && (0 <= counter->pc0) && (counter->pc0 <= 3) && (0 <= counter->pc1) && (counter->pc1 <= 3) && (0 <= counter->pc2) && (counter->pc2 <= 3) && ((counter->pc0 == 3) ==> ((counter->fork0 == 1) && (counter->fork1 == 1))) && ((counter->pc1 == 3) ==> ((counter->fork1 == 2) && (counter->fork2 == 2))) && ((counter->pc2 == 3) ==> ((counter->fork2 == 3) && (counter->fork0 == 3)));
*/
void asymmetric_dining_philosophers_pickup_left_1(asymmetric_dining_philosophers *counter) {
    counter->fork1 = 2;
    counter->pc1 = 2;
}

/*@
  requires \valid(counter);
  requires (0 <= counter->fork0) && (counter->fork0 <= 3) && (0 <= counter->fork1) && (counter->fork1 <= 3) && (0 <= counter->fork2) && (counter->fork2 <= 3) && (0 <= counter->pc0) && (counter->pc0 <= 3) && (0 <= counter->pc1) && (counter->pc1 <= 3) && (0 <= counter->pc2) && (counter->pc2 <= 3) && ((counter->pc0 == 3) ==> ((counter->fork0 == 1) && (counter->fork1 == 1))) && ((counter->pc1 == 3) ==> ((counter->fork1 == 2) && (counter->fork2 == 2))) && ((counter->pc2 == 3) ==> ((counter->fork2 == 3) && (counter->fork0 == 3)));
  requires counter->pc1 == 2;
  requires counter->fork1 == 2;
  requires counter->fork2 == 0;
  assigns counter->fork2, counter->pc1;
  ensures counter->fork2 == 2 && counter->pc1 == 3;
  ensures (0 <= counter->fork0) && (counter->fork0 <= 3) && (0 <= counter->fork1) && (counter->fork1 <= 3) && (0 <= counter->fork2) && (counter->fork2 <= 3) && (0 <= counter->pc0) && (counter->pc0 <= 3) && (0 <= counter->pc1) && (counter->pc1 <= 3) && (0 <= counter->pc2) && (counter->pc2 <= 3) && ((counter->pc0 == 3) ==> ((counter->fork0 == 1) && (counter->fork1 == 1))) && ((counter->pc1 == 3) ==> ((counter->fork1 == 2) && (counter->fork2 == 2))) && ((counter->pc2 == 3) ==> ((counter->fork2 == 3) && (counter->fork0 == 3)));
*/
void asymmetric_dining_philosophers_pickup_right_1(asymmetric_dining_philosophers *counter) {
    counter->fork2 = 2;
    counter->pc1 = 3;
}

/*@
  requires \valid(counter);
  requires (0 <= counter->fork0) && (counter->fork0 <= 3) && (0 <= counter->fork1) && (counter->fork1 <= 3) && (0 <= counter->fork2) && (counter->fork2 <= 3) && (0 <= counter->pc0) && (counter->pc0 <= 3) && (0 <= counter->pc1) && (counter->pc1 <= 3) && (0 <= counter->pc2) && (counter->pc2 <= 3) && ((counter->pc0 == 3) ==> ((counter->fork0 == 1) && (counter->fork1 == 1))) && ((counter->pc1 == 3) ==> ((counter->fork1 == 2) && (counter->fork2 == 2))) && ((counter->pc2 == 3) ==> ((counter->fork2 == 3) && (counter->fork0 == 3)));
  requires counter->pc1 == 3;
  requires counter->fork1 == 2;
  requires counter->fork2 == 2;
  assigns counter->fork1, counter->fork2, counter->pc1;
  ensures counter->fork1 == 0 && counter->fork2 == 0 && counter->pc1 == 0;
  ensures (0 <= counter->fork0) && (counter->fork0 <= 3) && (0 <= counter->fork1) && (counter->fork1 <= 3) && (0 <= counter->fork2) && (counter->fork2 <= 3) && (0 <= counter->pc0) && (counter->pc0 <= 3) && (0 <= counter->pc1) && (counter->pc1 <= 3) && (0 <= counter->pc2) && (counter->pc2 <= 3) && ((counter->pc0 == 3) ==> ((counter->fork0 == 1) && (counter->fork1 == 1))) && ((counter->pc1 == 3) ==> ((counter->fork1 == 2) && (counter->fork2 == 2))) && ((counter->pc2 == 3) ==> ((counter->fork2 == 3) && (counter->fork0 == 3)));
*/
void asymmetric_dining_philosophers_putdown_1(asymmetric_dining_philosophers *counter) {
    counter->fork1 = 0;
    counter->fork2 = 0;
    counter->pc1 = 0;
}

/*@
  requires \valid(counter);
  requires (0 <= counter->fork0) && (counter->fork0 <= 3) && (0 <= counter->fork1) && (counter->fork1 <= 3) && (0 <= counter->fork2) && (counter->fork2 <= 3) && (0 <= counter->pc0) && (counter->pc0 <= 3) && (0 <= counter->pc1) && (counter->pc1 <= 3) && (0 <= counter->pc2) && (counter->pc2 <= 3) && ((counter->pc0 == 3) ==> ((counter->fork0 == 1) && (counter->fork1 == 1))) && ((counter->pc1 == 3) ==> ((counter->fork1 == 2) && (counter->fork2 == 2))) && ((counter->pc2 == 3) ==> ((counter->fork2 == 3) && (counter->fork0 == 3)));
  requires counter->pc2 == 0;
  assigns counter->pc2;
  ensures counter->pc2 == 1;
  ensures (0 <= counter->fork0) && (counter->fork0 <= 3) && (0 <= counter->fork1) && (counter->fork1 <= 3) && (0 <= counter->fork2) && (counter->fork2 <= 3) && (0 <= counter->pc0) && (counter->pc0 <= 3) && (0 <= counter->pc1) && (counter->pc1 <= 3) && (0 <= counter->pc2) && (counter->pc2 <= 3) && ((counter->pc0 == 3) ==> ((counter->fork0 == 1) && (counter->fork1 == 1))) && ((counter->pc1 == 3) ==> ((counter->fork1 == 2) && (counter->fork2 == 2))) && ((counter->pc2 == 3) ==> ((counter->fork2 == 3) && (counter->fork0 == 3)));
*/
void asymmetric_dining_philosophers_request_2(asymmetric_dining_philosophers *counter) {
    counter->pc2 = 1;
}

/*@
  requires \valid(counter);
  requires (0 <= counter->fork0) && (counter->fork0 <= 3) && (0 <= counter->fork1) && (counter->fork1 <= 3) && (0 <= counter->fork2) && (counter->fork2 <= 3) && (0 <= counter->pc0) && (counter->pc0 <= 3) && (0 <= counter->pc1) && (counter->pc1 <= 3) && (0 <= counter->pc2) && (counter->pc2 <= 3) && ((counter->pc0 == 3) ==> ((counter->fork0 == 1) && (counter->fork1 == 1))) && ((counter->pc1 == 3) ==> ((counter->fork1 == 2) && (counter->fork2 == 2))) && ((counter->pc2 == 3) ==> ((counter->fork2 == 3) && (counter->fork0 == 3)));
  requires counter->pc2 == 1;
  requires counter->fork2 == 0;
  assigns counter->fork2, counter->pc2;
  ensures counter->fork2 == 3 && counter->pc2 == 2;
  ensures (0 <= counter->fork0) && (counter->fork0 <= 3) && (0 <= counter->fork1) && (counter->fork1 <= 3) && (0 <= counter->fork2) && (counter->fork2 <= 3) && (0 <= counter->pc0) && (counter->pc0 <= 3) && (0 <= counter->pc1) && (counter->pc1 <= 3) && (0 <= counter->pc2) && (counter->pc2 <= 3) && ((counter->pc0 == 3) ==> ((counter->fork0 == 1) && (counter->fork1 == 1))) && ((counter->pc1 == 3) ==> ((counter->fork1 == 2) && (counter->fork2 == 2))) && ((counter->pc2 == 3) ==> ((counter->fork2 == 3) && (counter->fork0 == 3)));
*/
void asymmetric_dining_philosophers_pickup_left_2(asymmetric_dining_philosophers *counter) {
    counter->fork2 = 3;
    counter->pc2 = 2;
}

/*@
  requires \valid(counter);
  requires (0 <= counter->fork0) && (counter->fork0 <= 3) && (0 <= counter->fork1) && (counter->fork1 <= 3) && (0 <= counter->fork2) && (counter->fork2 <= 3) && (0 <= counter->pc0) && (counter->pc0 <= 3) && (0 <= counter->pc1) && (counter->pc1 <= 3) && (0 <= counter->pc2) && (counter->pc2 <= 3) && ((counter->pc0 == 3) ==> ((counter->fork0 == 1) && (counter->fork1 == 1))) && ((counter->pc1 == 3) ==> ((counter->fork1 == 2) && (counter->fork2 == 2))) && ((counter->pc2 == 3) ==> ((counter->fork2 == 3) && (counter->fork0 == 3)));
  requires counter->pc2 == 2;
  requires counter->fork2 == 3;
  requires counter->fork0 == 0;
  assigns counter->fork0, counter->pc2;
  ensures counter->fork0 == 3 && counter->pc2 == 3;
  ensures (0 <= counter->fork0) && (counter->fork0 <= 3) && (0 <= counter->fork1) && (counter->fork1 <= 3) && (0 <= counter->fork2) && (counter->fork2 <= 3) && (0 <= counter->pc0) && (counter->pc0 <= 3) && (0 <= counter->pc1) && (counter->pc1 <= 3) && (0 <= counter->pc2) && (counter->pc2 <= 3) && ((counter->pc0 == 3) ==> ((counter->fork0 == 1) && (counter->fork1 == 1))) && ((counter->pc1 == 3) ==> ((counter->fork1 == 2) && (counter->fork2 == 2))) && ((counter->pc2 == 3) ==> ((counter->fork2 == 3) && (counter->fork0 == 3)));
*/
void asymmetric_dining_philosophers_pickup_right_2(asymmetric_dining_philosophers *counter) {
    counter->fork0 = 3;
    counter->pc2 = 3;
}

/*@
  requires \valid(counter);
  requires (0 <= counter->fork0) && (counter->fork0 <= 3) && (0 <= counter->fork1) && (counter->fork1 <= 3) && (0 <= counter->fork2) && (counter->fork2 <= 3) && (0 <= counter->pc0) && (counter->pc0 <= 3) && (0 <= counter->pc1) && (counter->pc1 <= 3) && (0 <= counter->pc2) && (counter->pc2 <= 3) && ((counter->pc0 == 3) ==> ((counter->fork0 == 1) && (counter->fork1 == 1))) && ((counter->pc1 == 3) ==> ((counter->fork1 == 2) && (counter->fork2 == 2))) && ((counter->pc2 == 3) ==> ((counter->fork2 == 3) && (counter->fork0 == 3)));
  requires counter->pc2 == 3;
  requires counter->fork2 == 3;
  requires counter->fork0 == 3;
  assigns counter->fork2, counter->fork0, counter->pc2;
  ensures counter->fork2 == 0 && counter->fork0 == 0 && counter->pc2 == 0;
  ensures (0 <= counter->fork0) && (counter->fork0 <= 3) && (0 <= counter->fork1) && (counter->fork1 <= 3) && (0 <= counter->fork2) && (counter->fork2 <= 3) && (0 <= counter->pc0) && (counter->pc0 <= 3) && (0 <= counter->pc1) && (counter->pc1 <= 3) && (0 <= counter->pc2) && (counter->pc2 <= 3) && ((counter->pc0 == 3) ==> ((counter->fork0 == 1) && (counter->fork1 == 1))) && ((counter->pc1 == 3) ==> ((counter->fork1 == 2) && (counter->fork2 == 2))) && ((counter->pc2 == 3) ==> ((counter->fork2 == 3) && (counter->fork0 == 3)));
*/
void asymmetric_dining_philosophers_putdown_2(asymmetric_dining_philosophers *counter) {
    counter->fork2 = 0;
    counter->fork0 = 0;
    counter->pc2 = 0;
}
