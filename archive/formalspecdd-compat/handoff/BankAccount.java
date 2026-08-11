public class BankAccount {
    private /*@ spec_public @*/ int balance;

    //@ public invariant balance >= 0;

    //@ ensures balance == 0;
    public BankAccount() {}

    //@ requires amount >= 0;
    //@ requires amount <= balance;
    //@ assignable balance;
    //@ ensures balance == \old(balance) - amount;
    public void withdraw(int amount) {}

    //@ ensures \result == balance;
    public /*@ pure */ int getBalance() { return 0; }
}
