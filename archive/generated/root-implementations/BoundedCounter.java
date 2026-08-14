public class BoundedCounter {
    private /*@ spec_public @*/ int value;

    //@ public invariant 0 <= value && value <= 5;
    //@ public invariant ((value >= 0) && (value <= 5));

    //@ assignable \nothing;
    //@ ensures value == 0;
    public BoundedCounter() {
        this.value = 0;
    }

    //@ assignable \nothing;
    //@ ensures \result == value;
    public /*@ pure @*/ int getValue() { return value; }

    //@ requires (value <= 4);
    //@ assignable value;
    //@ ensures value == (\old(value) + 1);
    public void increment() {}

    //@ requires (value >= 1);
    //@ assignable value;
    //@ ensures value == (\old(value) - 1);
    public void decrement() {}
}
