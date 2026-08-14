public class RateLimiter {
    private /*@ spec_public @*/ int tokens;

    //@ public invariant (0 <= tokens);
    //@ public invariant (tokens <= 5);

    //@ assignable \nothing;
    //@ ensures tokens == 5;
    public RateLimiter() {
        this.tokens = 5;
    }

    //@ assignable \nothing;
    //@ ensures \result == tokens;
    public /*@ pure @*/ int getTokens() { return tokens; }

    //@ requires (tokens >= 1);
    //@ assignable tokens;
    //@ ensures tokens == (\old(tokens) - 1);
    public void handleRequest() {}

    //@ requires (tokens <= 4);
    //@ assignable tokens;
    //@ ensures tokens == 5;
    public void refill() {}
}
