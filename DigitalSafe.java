public class DigitalSafe {
    private /*@ spec_public @*/ int safe_state;
    private /*@ spec_public @*/ int attempts;

    //@ public invariant (0 <= safe_state);
    //@ public invariant (safe_state <= 2);
    //@ public invariant (0 <= attempts);
    //@ public invariant (attempts <= 3);
    //@ public invariant ((safe_state == 1) ==> (attempts == 0));
    //@ public invariant ((safe_state == 2) ==> (attempts == 3));

    //@ assignable \nothing;
    //@ ensures safe_state == 0 && attempts == 0;
    public DigitalSafe() {
        this.safe_state = 0;
        this.attempts = 0;
    }

    //@ assignable \nothing;
    //@ ensures \result == safe_state;
    public /*@ pure @*/ int getSafeState() { return safe_state; }

    //@ assignable \nothing;
    //@ ensures \result == attempts;
    public /*@ pure @*/ int getAttempts() { return attempts; }

    //@ requires (safe_state == 0);
    //@ requires (attempts == 0);
    //@ assignable safe_state;
    //@ ensures safe_state == 1;
    public void unlock() {}

    //@ requires (safe_state == 0);
    //@ requires (attempts <= 1);
    //@ assignable attempts;
    //@ ensures attempts == (\old(attempts) + 1);
    public void failAttempt() {}

    //@ requires (safe_state == 0);
    //@ requires (attempts == 2);
    //@ assignable safe_state, attempts;
    //@ ensures safe_state == 2 && attempts == 3;
    public void blockSafe() {}

    //@ requires (safe_state == 1);
    //@ assignable safe_state, attempts;
    //@ ensures safe_state == 0 && attempts == 0;
    public void lock() {}

    //@ requires (safe_state == 2);
    //@ assignable safe_state, attempts;
    //@ ensures safe_state == 0 && attempts == 0;
    public void adminReset() {}
}
