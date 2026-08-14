public class Peterson {
    private /*@ spec_public @*/ int flag0;
    private /*@ spec_public @*/ int flag1;
    private /*@ spec_public @*/ int turn;
    private /*@ spec_public @*/ int pc0;
    private /*@ spec_public @*/ int pc1;

    //@ public invariant (0 <= flag0);
    //@ public invariant (flag0 <= 1);
    //@ public invariant (0 <= flag1);
    //@ public invariant (flag1 <= 1);
    //@ public invariant (0 <= turn);
    //@ public invariant (turn <= 1);
    //@ public invariant (0 <= pc0);
    //@ public invariant (pc0 <= 2);
    //@ public invariant (0 <= pc1);
    //@ public invariant (pc1 <= 2);
    //@ public invariant !(((pc0 == 2) && (pc1 == 2)));
    //@ public invariant ((pc0 == 2) ==> (flag0 == 1));
    //@ public invariant ((pc1 == 2) ==> (flag1 == 1));
    //@ public invariant ((pc0 == 2) ==> ((flag1 == 0) || (turn == 0)));
    //@ public invariant ((pc1 == 2) ==> ((flag0 == 0) || (turn == 1)));
    //@ public invariant ((pc0 == 1) ==> (flag0 == 1));
    //@ public invariant ((pc1 == 1) ==> (flag1 == 1));

    //@ assignable \nothing;
    //@ ensures flag0 == 0 && flag1 == 0 && turn == 0 && pc0 == 0 && pc1 == 0;
    public Peterson() {
        this.flag0 = 0;
        this.flag1 = 0;
        this.turn = 0;
        this.pc0 = 0;
        this.pc1 = 0;
    }

    //@ assignable \nothing;
    //@ ensures \result == flag0;
    public /*@ pure @*/ int getFlag0() { return flag0; }

    //@ assignable \nothing;
    //@ ensures \result == flag1;
    public /*@ pure @*/ int getFlag1() { return flag1; }

    //@ assignable \nothing;
    //@ ensures \result == turn;
    public /*@ pure @*/ int getTurn() { return turn; }

    //@ assignable \nothing;
    //@ ensures \result == pc0;
    public /*@ pure @*/ int getPc0() { return pc0; }

    //@ assignable \nothing;
    //@ ensures \result == pc1;
    public /*@ pure @*/ int getPc1() { return pc1; }

    //@ requires (pc0 == 0);
    //@ assignable flag0, turn, pc0;
    //@ ensures flag0 == 1 && turn == 1 && pc0 == 1;
    public void request0() {}

    //@ requires (pc0 == 1);
    //@ requires ((flag1 == 0) || (turn == 0));
    //@ assignable pc0;
    //@ ensures pc0 == 2;
    public void enter0() {}

    //@ requires (pc0 == 2);
    //@ assignable flag0, pc0;
    //@ ensures flag0 == 0 && pc0 == 0;
    public void exit0() {}

    //@ requires (pc1 == 0);
    //@ assignable flag1, turn, pc1;
    //@ ensures flag1 == 1 && turn == 0 && pc1 == 1;
    public void request1() {}

    //@ requires (pc1 == 1);
    //@ requires ((flag0 == 0) || (turn == 1));
    //@ assignable pc1;
    //@ ensures pc1 == 2;
    public void enter1() {}

    //@ requires (pc1 == 2);
    //@ assignable flag1, pc1;
    //@ ensures flag1 == 0 && pc1 == 0;
    public void exit1() {}
}
