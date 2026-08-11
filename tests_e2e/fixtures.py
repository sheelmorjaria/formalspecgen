COUNTER = r"""public class Counter {
  private /*@ spec_public @*/ int value;
  //@ public invariant 0 <= value && value <= 1000;
  //@ requires 0 < amount && amount <= 1000 - value;
  //@ assignable value;
  //@ ensures value == \old(value) + amount;
  public void add(int amount) { value = value + amount; }
}
"""

TRUSTED_COUNTER_STUB = COUNTER.replace(
    "{ value = value + amount; }", "{ throw new UnsupportedOperationException(); }")

LINKED = r"""public class Node {
  public int value;
  public Node next;
  //@ requires start != null;
  //@ requires target != null;
  //@ requires acyclic(start);
  //@ assignable \nothing;
  public static /*@ pure @*/ boolean reachable(Node start, Node target) {
    return start == target || (start.next != null && reachable(start.next, target));
  }
}
"""

BANKING = r"""public class Account {
  private /*@ spec_public @*/ long balance;
  //@ requires amount > 0;
  //@ assignable balance;
  //@ ensures \result <==> amount <= 4 - \old(balance);
  //@ ensures \result ==> balance == \old(balance) + amount;
  //@ ensures !\result ==> balance == \old(balance);
  public boolean deposit(long amount) { return false; }
  //@ requires amount > 0;
  //@ assignable balance;
  //@ ensures \result <==> amount <= \old(balance);
  //@ ensures \result ==> balance == \old(balance) - amount;
  //@ ensures !\result ==> balance == \old(balance);
  public boolean withdraw(long amount) { return false; }
  //@ requires from != to;
  //@ requires amount > 0;
  //@ assignable from.balance, to.balance;
  //@ ensures \result <==> (amount <= \old(from.balance) && amount <= 4 - \old(to.balance));
  //@ ensures \result ==> from.balance == \old(from.balance) - amount && to.balance == \old(to.balance) + amount;
  //@ ensures !\result ==> from.balance == \old(from.balance) && to.balance == \old(to.balance);
  public boolean transfer(Account from, Account to, long amount) { return false; }
}
"""

ACSL = r"""/*@ requires x < 2147483647;
    assigns \nothing;
    ensures \result == x + 1;
*/
int increment(int x) { return x + 1; }
"""
