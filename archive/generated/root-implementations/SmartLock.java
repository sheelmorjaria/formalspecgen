public class SmartLock {
    private /*@ spec_public @*/ int door_state;
    private /*@ spec_public @*/ int lock_state;

    //@ public invariant 0 <= door_state && door_state <= 1;
    //@ public invariant 0 <= lock_state && lock_state <= 1;
    //@ public invariant ((lock_state == 1) ==> (door_state == 1));

    //@ ensures door_state == 1 && lock_state == 0;
    public SmartLock() {
        this.door_state = 1;
        this.lock_state = 0;
    }

    //@ requires (door_state == 0);
    //@ requires (lock_state == 0);
    //@ assignable door_state;
    //@ ensures door_state == 1;
    public void CloseDoor() {}

    //@ requires (door_state == 1);
    //@ requires (lock_state == 0);
    //@ assignable door_state;
    //@ ensures door_state == 0;
    public void OpenDoor() {}

    //@ requires (door_state == 1);
    //@ requires (lock_state == 0);
    //@ assignable lock_state;
    //@ ensures lock_state == 1;
    public void LockDoor() {}

    //@ requires (lock_state == 1);
    //@ assignable lock_state;
    //@ ensures lock_state == 0;
    public void UnlockDoor() {}
}
