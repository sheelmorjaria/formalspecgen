/* Deterministic contract lowered from the reviewed V2 domain 'peterson'.
 * Human review of the reviewed artifact is required before trust. */

typedef struct {
    int flag0;
    int flag1;
    int turn;
    int pc0;
    int pc1;
} peterson;

/*@
  requires \valid(counter);
  assigns counter->flag0, counter->flag1, counter->turn, counter->pc0, counter->pc1;
  ensures counter->flag0 == 0 && counter->flag1 == 0 && counter->turn == 0 && counter->pc0 == 0 && counter->pc1 == 0;
  ensures (0 <= counter->flag0) && (counter->flag0 <= 1) && (0 <= counter->flag1) && (counter->flag1 <= 1) && (0 <= counter->turn) && (counter->turn <= 1) && (0 <= counter->pc0) && (counter->pc0 <= 2) && (0 <= counter->pc1) && (counter->pc1 <= 2) && (!((counter->pc0 == 2) && (counter->pc1 == 2))) && ((counter->pc0 == 2) ==> (counter->flag0 == 1)) && ((counter->pc1 == 2) ==> (counter->flag1 == 1)) && ((counter->pc0 == 2) ==> ((counter->flag1 == 0) || (counter->turn == 0))) && ((counter->pc1 == 2) ==> ((counter->flag0 == 0) || (counter->turn == 1))) && ((counter->pc0 == 1) ==> (counter->flag0 == 1)) && ((counter->pc1 == 1) ==> (counter->flag1 == 1));
*/
void peterson_init(peterson *counter) {
    counter->flag0 = 0;
    counter->flag1 = 0;
    counter->turn = 0;
    counter->pc0 = 0;
    counter->pc1 = 0;
}

/*@
  requires \valid_read(counter);
  assigns \nothing;
  ensures \result == counter->flag0;
*/
int peterson_get_flag0(const peterson *counter) {
    return counter->flag0;
}

/*@
  requires \valid_read(counter);
  assigns \nothing;
  ensures \result == counter->flag1;
*/
int peterson_get_flag1(const peterson *counter) {
    return counter->flag1;
}

/*@
  requires \valid_read(counter);
  assigns \nothing;
  ensures \result == counter->turn;
*/
int peterson_get_turn(const peterson *counter) {
    return counter->turn;
}

/*@
  requires \valid_read(counter);
  assigns \nothing;
  ensures \result == counter->pc0;
*/
int peterson_get_pc0(const peterson *counter) {
    return counter->pc0;
}

/*@
  requires \valid_read(counter);
  assigns \nothing;
  ensures \result == counter->pc1;
*/
int peterson_get_pc1(const peterson *counter) {
    return counter->pc1;
}

/*@
  requires \valid(counter);
  requires (0 <= counter->flag0) && (counter->flag0 <= 1) && (0 <= counter->flag1) && (counter->flag1 <= 1) && (0 <= counter->turn) && (counter->turn <= 1) && (0 <= counter->pc0) && (counter->pc0 <= 2) && (0 <= counter->pc1) && (counter->pc1 <= 2) && (!((counter->pc0 == 2) && (counter->pc1 == 2))) && ((counter->pc0 == 2) ==> (counter->flag0 == 1)) && ((counter->pc1 == 2) ==> (counter->flag1 == 1)) && ((counter->pc0 == 2) ==> ((counter->flag1 == 0) || (counter->turn == 0))) && ((counter->pc1 == 2) ==> ((counter->flag0 == 0) || (counter->turn == 1))) && ((counter->pc0 == 1) ==> (counter->flag0 == 1)) && ((counter->pc1 == 1) ==> (counter->flag1 == 1));
  requires counter->pc0 == 0;
  assigns counter->flag0, counter->turn, counter->pc0;
  ensures counter->flag0 == 1 && counter->turn == 1 && counter->pc0 == 1;
  ensures (0 <= counter->flag0) && (counter->flag0 <= 1) && (0 <= counter->flag1) && (counter->flag1 <= 1) && (0 <= counter->turn) && (counter->turn <= 1) && (0 <= counter->pc0) && (counter->pc0 <= 2) && (0 <= counter->pc1) && (counter->pc1 <= 2) && (!((counter->pc0 == 2) && (counter->pc1 == 2))) && ((counter->pc0 == 2) ==> (counter->flag0 == 1)) && ((counter->pc1 == 2) ==> (counter->flag1 == 1)) && ((counter->pc0 == 2) ==> ((counter->flag1 == 0) || (counter->turn == 0))) && ((counter->pc1 == 2) ==> ((counter->flag0 == 0) || (counter->turn == 1))) && ((counter->pc0 == 1) ==> (counter->flag0 == 1)) && ((counter->pc1 == 1) ==> (counter->flag1 == 1));
*/
void peterson_request0(peterson *counter) {
    counter->flag0 = 1;
    counter->turn = 1;
    counter->pc0 = 1;
}

/*@
  requires \valid(counter);
  requires (0 <= counter->flag0) && (counter->flag0 <= 1) && (0 <= counter->flag1) && (counter->flag1 <= 1) && (0 <= counter->turn) && (counter->turn <= 1) && (0 <= counter->pc0) && (counter->pc0 <= 2) && (0 <= counter->pc1) && (counter->pc1 <= 2) && (!((counter->pc0 == 2) && (counter->pc1 == 2))) && ((counter->pc0 == 2) ==> (counter->flag0 == 1)) && ((counter->pc1 == 2) ==> (counter->flag1 == 1)) && ((counter->pc0 == 2) ==> ((counter->flag1 == 0) || (counter->turn == 0))) && ((counter->pc1 == 2) ==> ((counter->flag0 == 0) || (counter->turn == 1))) && ((counter->pc0 == 1) ==> (counter->flag0 == 1)) && ((counter->pc1 == 1) ==> (counter->flag1 == 1));
  requires counter->pc0 == 1;
  requires (counter->flag1 == 0) || (counter->turn == 0);
  assigns counter->pc0;
  ensures counter->pc0 == 2;
  ensures (0 <= counter->flag0) && (counter->flag0 <= 1) && (0 <= counter->flag1) && (counter->flag1 <= 1) && (0 <= counter->turn) && (counter->turn <= 1) && (0 <= counter->pc0) && (counter->pc0 <= 2) && (0 <= counter->pc1) && (counter->pc1 <= 2) && (!((counter->pc0 == 2) && (counter->pc1 == 2))) && ((counter->pc0 == 2) ==> (counter->flag0 == 1)) && ((counter->pc1 == 2) ==> (counter->flag1 == 1)) && ((counter->pc0 == 2) ==> ((counter->flag1 == 0) || (counter->turn == 0))) && ((counter->pc1 == 2) ==> ((counter->flag0 == 0) || (counter->turn == 1))) && ((counter->pc0 == 1) ==> (counter->flag0 == 1)) && ((counter->pc1 == 1) ==> (counter->flag1 == 1));
*/
void peterson_enter0(peterson *counter) {
    counter->pc0 = 2;
}

/*@
  requires \valid(counter);
  requires (0 <= counter->flag0) && (counter->flag0 <= 1) && (0 <= counter->flag1) && (counter->flag1 <= 1) && (0 <= counter->turn) && (counter->turn <= 1) && (0 <= counter->pc0) && (counter->pc0 <= 2) && (0 <= counter->pc1) && (counter->pc1 <= 2) && (!((counter->pc0 == 2) && (counter->pc1 == 2))) && ((counter->pc0 == 2) ==> (counter->flag0 == 1)) && ((counter->pc1 == 2) ==> (counter->flag1 == 1)) && ((counter->pc0 == 2) ==> ((counter->flag1 == 0) || (counter->turn == 0))) && ((counter->pc1 == 2) ==> ((counter->flag0 == 0) || (counter->turn == 1))) && ((counter->pc0 == 1) ==> (counter->flag0 == 1)) && ((counter->pc1 == 1) ==> (counter->flag1 == 1));
  requires counter->pc0 == 2;
  assigns counter->flag0, counter->pc0;
  ensures counter->flag0 == 0 && counter->pc0 == 0;
  ensures (0 <= counter->flag0) && (counter->flag0 <= 1) && (0 <= counter->flag1) && (counter->flag1 <= 1) && (0 <= counter->turn) && (counter->turn <= 1) && (0 <= counter->pc0) && (counter->pc0 <= 2) && (0 <= counter->pc1) && (counter->pc1 <= 2) && (!((counter->pc0 == 2) && (counter->pc1 == 2))) && ((counter->pc0 == 2) ==> (counter->flag0 == 1)) && ((counter->pc1 == 2) ==> (counter->flag1 == 1)) && ((counter->pc0 == 2) ==> ((counter->flag1 == 0) || (counter->turn == 0))) && ((counter->pc1 == 2) ==> ((counter->flag0 == 0) || (counter->turn == 1))) && ((counter->pc0 == 1) ==> (counter->flag0 == 1)) && ((counter->pc1 == 1) ==> (counter->flag1 == 1));
*/
void peterson_exit0(peterson *counter) {
    counter->flag0 = 0;
    counter->pc0 = 0;
}

/*@
  requires \valid(counter);
  requires (0 <= counter->flag0) && (counter->flag0 <= 1) && (0 <= counter->flag1) && (counter->flag1 <= 1) && (0 <= counter->turn) && (counter->turn <= 1) && (0 <= counter->pc0) && (counter->pc0 <= 2) && (0 <= counter->pc1) && (counter->pc1 <= 2) && (!((counter->pc0 == 2) && (counter->pc1 == 2))) && ((counter->pc0 == 2) ==> (counter->flag0 == 1)) && ((counter->pc1 == 2) ==> (counter->flag1 == 1)) && ((counter->pc0 == 2) ==> ((counter->flag1 == 0) || (counter->turn == 0))) && ((counter->pc1 == 2) ==> ((counter->flag0 == 0) || (counter->turn == 1))) && ((counter->pc0 == 1) ==> (counter->flag0 == 1)) && ((counter->pc1 == 1) ==> (counter->flag1 == 1));
  requires counter->pc1 == 0;
  assigns counter->flag1, counter->turn, counter->pc1;
  ensures counter->flag1 == 1 && counter->turn == 0 && counter->pc1 == 1;
  ensures (0 <= counter->flag0) && (counter->flag0 <= 1) && (0 <= counter->flag1) && (counter->flag1 <= 1) && (0 <= counter->turn) && (counter->turn <= 1) && (0 <= counter->pc0) && (counter->pc0 <= 2) && (0 <= counter->pc1) && (counter->pc1 <= 2) && (!((counter->pc0 == 2) && (counter->pc1 == 2))) && ((counter->pc0 == 2) ==> (counter->flag0 == 1)) && ((counter->pc1 == 2) ==> (counter->flag1 == 1)) && ((counter->pc0 == 2) ==> ((counter->flag1 == 0) || (counter->turn == 0))) && ((counter->pc1 == 2) ==> ((counter->flag0 == 0) || (counter->turn == 1))) && ((counter->pc0 == 1) ==> (counter->flag0 == 1)) && ((counter->pc1 == 1) ==> (counter->flag1 == 1));
*/
void peterson_request1(peterson *counter) {
    counter->flag1 = 1;
    counter->turn = 0;
    counter->pc1 = 1;
}

/*@
  requires \valid(counter);
  requires (0 <= counter->flag0) && (counter->flag0 <= 1) && (0 <= counter->flag1) && (counter->flag1 <= 1) && (0 <= counter->turn) && (counter->turn <= 1) && (0 <= counter->pc0) && (counter->pc0 <= 2) && (0 <= counter->pc1) && (counter->pc1 <= 2) && (!((counter->pc0 == 2) && (counter->pc1 == 2))) && ((counter->pc0 == 2) ==> (counter->flag0 == 1)) && ((counter->pc1 == 2) ==> (counter->flag1 == 1)) && ((counter->pc0 == 2) ==> ((counter->flag1 == 0) || (counter->turn == 0))) && ((counter->pc1 == 2) ==> ((counter->flag0 == 0) || (counter->turn == 1))) && ((counter->pc0 == 1) ==> (counter->flag0 == 1)) && ((counter->pc1 == 1) ==> (counter->flag1 == 1));
  requires counter->pc1 == 1;
  requires (counter->flag0 == 0) || (counter->turn == 1);
  assigns counter->pc1;
  ensures counter->pc1 == 2;
  ensures (0 <= counter->flag0) && (counter->flag0 <= 1) && (0 <= counter->flag1) && (counter->flag1 <= 1) && (0 <= counter->turn) && (counter->turn <= 1) && (0 <= counter->pc0) && (counter->pc0 <= 2) && (0 <= counter->pc1) && (counter->pc1 <= 2) && (!((counter->pc0 == 2) && (counter->pc1 == 2))) && ((counter->pc0 == 2) ==> (counter->flag0 == 1)) && ((counter->pc1 == 2) ==> (counter->flag1 == 1)) && ((counter->pc0 == 2) ==> ((counter->flag1 == 0) || (counter->turn == 0))) && ((counter->pc1 == 2) ==> ((counter->flag0 == 0) || (counter->turn == 1))) && ((counter->pc0 == 1) ==> (counter->flag0 == 1)) && ((counter->pc1 == 1) ==> (counter->flag1 == 1));
*/
void peterson_enter1(peterson *counter) {
    counter->pc1 = 2;
}

/*@
  requires \valid(counter);
  requires (0 <= counter->flag0) && (counter->flag0 <= 1) && (0 <= counter->flag1) && (counter->flag1 <= 1) && (0 <= counter->turn) && (counter->turn <= 1) && (0 <= counter->pc0) && (counter->pc0 <= 2) && (0 <= counter->pc1) && (counter->pc1 <= 2) && (!((counter->pc0 == 2) && (counter->pc1 == 2))) && ((counter->pc0 == 2) ==> (counter->flag0 == 1)) && ((counter->pc1 == 2) ==> (counter->flag1 == 1)) && ((counter->pc0 == 2) ==> ((counter->flag1 == 0) || (counter->turn == 0))) && ((counter->pc1 == 2) ==> ((counter->flag0 == 0) || (counter->turn == 1))) && ((counter->pc0 == 1) ==> (counter->flag0 == 1)) && ((counter->pc1 == 1) ==> (counter->flag1 == 1));
  requires counter->pc1 == 2;
  assigns counter->flag1, counter->pc1;
  ensures counter->flag1 == 0 && counter->pc1 == 0;
  ensures (0 <= counter->flag0) && (counter->flag0 <= 1) && (0 <= counter->flag1) && (counter->flag1 <= 1) && (0 <= counter->turn) && (counter->turn <= 1) && (0 <= counter->pc0) && (counter->pc0 <= 2) && (0 <= counter->pc1) && (counter->pc1 <= 2) && (!((counter->pc0 == 2) && (counter->pc1 == 2))) && ((counter->pc0 == 2) ==> (counter->flag0 == 1)) && ((counter->pc1 == 2) ==> (counter->flag1 == 1)) && ((counter->pc0 == 2) ==> ((counter->flag1 == 0) || (counter->turn == 0))) && ((counter->pc1 == 2) ==> ((counter->flag0 == 0) || (counter->turn == 1))) && ((counter->pc0 == 1) ==> (counter->flag0 == 1)) && ((counter->pc1 == 1) ==> (counter->flag1 == 1));
*/
void peterson_exit1(peterson *counter) {
    counter->flag1 = 0;
    counter->pc1 = 0;
}
