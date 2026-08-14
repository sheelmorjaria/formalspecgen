public class RobotVacuumController {
    private /*@ spec_public @*/ int battery_level;
    private /*@ spec_public @*/ int vacuum_mode;

    //@ public invariant 0 <= battery_level && battery_level <= 5;
    //@ public invariant 0 <= vacuum_mode && vacuum_mode <= 1;
    //@ public invariant ((battery_level >= 0) && (battery_level <= 5));
    //@ public invariant ((vacuum_mode >= 0) && (vacuum_mode <= 1));
    //@ public invariant !(((vacuum_mode == 1) && (battery_level == 0)));

    //@ assignable \nothing;
    //@ ensures battery_level == 5 && vacuum_mode == 0;
    public RobotVacuumController() {
        this.battery_level = 5;
        this.vacuum_mode = 0;
    }

    //@ assignable \nothing;
    //@ ensures \result == battery_level;
    public /*@ pure @*/ int getBatteryLevel() { return battery_level; }

    //@ assignable \nothing;
    //@ ensures \result == vacuum_mode;
    public /*@ pure @*/ int getVacuumMode() { return vacuum_mode; }

    //@ requires (battery_level >= 1);
    //@ requires (vacuum_mode == 0);
    //@ assignable vacuum_mode;
    //@ ensures vacuum_mode == 1;
    public void startCleaning() {}

    //@ assignable battery_level, vacuum_mode;
    //@ ensures \result <==> ((\old(vacuum_mode) == 1) && (\old(battery_level) >= 1));
    //@ ensures \result ==> (battery_level == (\old(battery_level) - 1) && vacuum_mode == 0);
    //@ ensures !\result ==> (battery_level == \old(battery_level) && vacuum_mode == \old(vacuum_mode));
    public boolean stopCleaning() { return false; }

    //@ assignable battery_level, vacuum_mode;
    //@ ensures \result <==> (true);
    //@ ensures \result ==> (battery_level == 5 && vacuum_mode == 0);
    //@ ensures !\result ==> (battery_level == \old(battery_level) && vacuum_mode == \old(vacuum_mode));
    public boolean dock() { return false; }
}
