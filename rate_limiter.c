/* Deterministic contract lowered from the reviewed V2 domain 'rate_limiter'.
 * Human review of the reviewed artifact is required before trust. */

typedef struct {
    int tokens;
} rate_limiter;

/*@
  requires \valid(counter);
  assigns counter->tokens;
  ensures counter->tokens == 5;
  ensures (0 <= counter->tokens) && (counter->tokens <= 5);
*/
void rate_limiter_init(rate_limiter *counter) {
    counter->tokens = 5;
}

/*@
  requires \valid_read(counter);
  assigns \nothing;
  ensures \result == counter->tokens;
*/
int rate_limiter_get_tokens(const rate_limiter *counter) {
    return counter->tokens;
}

/*@
  requires \valid(counter);
  requires (0 <= counter->tokens) && (counter->tokens <= 5);
  requires counter->tokens > 0;
  assigns counter->tokens;
  ensures counter->tokens == \old(counter->tokens) - 1;
  ensures (0 <= counter->tokens) && (counter->tokens <= 5);
*/
void rate_limiter_handle_request(rate_limiter *counter) {
    int pre_tokens = counter->tokens;
    counter->tokens = pre_tokens - 1;
}

/*@
  requires \valid(counter);
  requires (0 <= counter->tokens) && (counter->tokens <= 5);
  requires counter->tokens < 5;
  assigns counter->tokens;
  ensures counter->tokens == 5;
  ensures (0 <= counter->tokens) && (counter->tokens <= 5);
*/
void rate_limiter_refill(rate_limiter *counter) {
    counter->tokens = 5;
}
