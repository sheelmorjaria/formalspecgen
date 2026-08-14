public class AtmController {
    private /*@ spec_public @*/ int account_balance;
    private /*@ spec_public @*/ int atm_cash;
    private /*@ spec_public @*/ boolean session_active;

    //@ public invariant 0 <= account_balance && account_balance <= 5;
    //@ public invariant 0 <= atm_cash && atm_cash <= 5;
    //@ public invariant ((account_balance - atm_cash) == 2);

    //@ assignable \nothing;
    //@ ensures account_balance == 4 && atm_cash == 2 && session_active == false;
    public AtmController() {
        this.account_balance = 4;
        this.atm_cash = 2;
        this.session_active = false;
    }

    //@ assignable \nothing;
    //@ ensures \result == account_balance;
    public /*@ pure @*/ int getAccountBalance() { return account_balance; }

    //@ assignable \nothing;
    //@ ensures \result == atm_cash;
    public /*@ pure @*/ int getAtmCash() { return atm_cash; }

    //@ assignable \nothing;
    //@ ensures \result == session_active;
    public /*@ pure @*/ boolean getSessionActive() { return session_active; }

    //@ requires (session_active == false);
    //@ assignable session_active;
    //@ ensures session_active == true;
    public void startSession() {}

    //@ requires (session_active == true);
    //@ assignable session_active;
    //@ ensures session_active == false;
    public void endSession() {}

    //@ requires (session_active == true);
    //@ requires (account_balance < 5);
    //@ requires (atm_cash < 5);
    //@ requires (account_balance <= 4);
    //@ requires (atm_cash <= 4);
    //@ assignable account_balance, atm_cash;
    //@ ensures account_balance == (\old(account_balance) + 1) && atm_cash == (\old(atm_cash) + 1);
    public void deposit() {}

    //@ requires (session_active == true);
    //@ requires (account_balance >= 1);
    //@ requires (atm_cash >= 1);
    //@ assignable account_balance, atm_cash;
    //@ ensures account_balance == (\old(account_balance) - 1) && atm_cash == (\old(atm_cash) - 1);
    public void withdraw() {}
}
