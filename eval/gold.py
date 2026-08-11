"""Gold NL <-> JML cases for the eval harness.

Stubs are real JML-annotated Java skeletons (the same format formalspecDD consumes).
Counter and Power are taken from ../formalspecDD/specs/; BankAccount is the verified
output from the MVP's first real run; Thermostat is hand-authored. Each must pass
`openjml -check` on its own — run_eval validates this before scoring.
"""

CASES = [
    {
        "id": "bank_account",
        "nl": "A bank account holds a non-negative integer balance that starts at zero. "
              "A withdrawal of a non-negative amount is permitted only if it does not exceed "
              "the current balance; the balance is then reduced by the withdrawn amount. "
              "The current balance can be queried.",
        "gold": r'''public class BankAccount {
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
''',
    },
    {
        "id": "counter",
        "nl": "A counter holds a non-negative count that never exceeds 1000. It starts at zero. "
              "It can be advanced by a non-negative amount n as long as the result stays within "
              "the bound, and it can report its current count.",
        "gold": r'''public class Counter {
    private /*@ spec_public @*/ int count;

    //@ public invariant 0 <= count && count <= 1000;

    //@ ensures count == 0;
    public Counter() {}

    //@ requires n >= 0;
    //@ requires count + n <= 1000;
    //@ assignable count;
    //@ ensures count == \old(count) + n;
    public void add(int n) {}

    //@ ensures \result == count;
    public /*@ pure */ int get() { return 0; }
}
''',
    },
    {
        "id": "power",
        "nl": "Given an integer base b between 0 and 7 and an integer exponent e between 0 and 10, "
              "pow returns b raised to the power e, i.e. the product of e copies of b. The function "
              "is pure and static.",
        "gold": r'''public class Power {
    //@ requires b >= 0 && b <= 7;
    //@ requires e >= 0 && e <= 10;
    //@ ensures \result == (\product int k; 1 <= k && k <= e; b);
    public static /*@ pure */ int pow(int b, int e) { return 0; }
}
''',
    },
    {
        "id": "thermostat",
        "nl": "A thermostat holds a temperature between 15 and 30 inclusive, initially 20. The "
              "temperature can be set to any value t within range, warmed by a non-negative delta "
              "that must not push it above 30, and queried.",
        "gold": r'''public class Thermostat {
    private /*@ spec_public @*/ int temp;

    //@ public invariant 15 <= temp && temp <= 30;

    //@ ensures temp == 20;
    public Thermostat() {}

    //@ requires t >= 15 && t <= 30;
    //@ assignable temp;
    //@ ensures temp == t;
    public void set(int t) {}

    //@ requires delta >= 0;
    //@ requires temp + delta <= 30;
    //@ assignable temp;
    //@ ensures temp == \old(temp) + delta;
    public void warm(int delta) {}

    //@ ensures \result == temp;
    public /*@ pure */ int getTemp() { return 0; }
}
''',
    },
    {
        "id": "max",
        "nl": "Given two integers a and b, max returns a value that is at least both a and b "
              "and is equal to one of them.",
        "gold": r'''public class Max {
    //@ ensures \result >= a && \result >= b;
    //@ ensures \result == a || \result == b;
    public static /*@ pure */ int max(int a, int b) { return 0; }
}
''',
    },
    {
        "id": "abs",
        "nl": "Given an integer a between -1000000 and 1000000, abs returns its absolute value: "
              "always non-negative, equal to a when a is non-negative, and equal to -a when a is negative.",
        "gold": r'''public class Abs {
    //@ requires a >= -1000000 && a <= 1000000;
    //@ ensures \result >= 0;
    //@ ensures a >= 0 ==> \result == a;
    //@ ensures a < 0 ==> \result == -a;
    public static /*@ pure */ int abs(int a) { return 0; }
}
''',
    },
    {
        "id": "array_sum",
        "nl": "Given a non-null array a of length at most 100 whose elements are all non-negative "
              "and whose total sum is at most 1000000, sum returns the sum of all elements.",
        "gold": r'''public class ArraySum {
    //@ requires a != null && a.length <= 100;
    //@ requires (\sum int i; 0 <= i && i < a.length; a[i]) <= 1000000;
    //@ requires (\forall int i; 0 <= i && i < a.length; a[i] >= 0);
    //@ ensures \result == (\sum int i; 0 <= i && i < a.length; a[i]);
    public static /*@ pure */ int sum(int[] a) { return 0; }
}
''',
    },
    {
        "id": "linear_search",
        "nl": "Given a non-null, non-empty array a of length at most 100 that contains the target "
              "value at least once, search returns an index i with a[i] == target and 0 <= i < a.length.",
        "gold": r'''public class LinearSearch {
    //@ requires a != null && a.length > 0 && a.length <= 100;
    //@ requires (\exists int i; 0 <= i && i < a.length; a[i] == target);
    //@ ensures a[\result] == target && 0 <= \result && \result < a.length;
    public static /*@ pure */ int search(int[] a, int target) { return 0; }
}
''',
    },
    {
        "id": "is_sorted",
        "nl": "Given a non-null array a of length at most 100, isSorted returns true if and only if "
              "every adjacent pair is non-decreasing: a[i] <= a[i+1] for all valid i.",
        "gold": r'''public class IsSorted {
    //@ requires a != null && a.length <= 100;
    //@ ensures \result == (\forall int i; 0 <= i && i < a.length - 1; a[i] <= a[i + 1]);
    public static /*@ pure */ boolean isSorted(int[] a) { return false; }
}
''',
    },
    {
        "id": "gcd",
        "nl": "Given a > 0 and b >= 0 (each at most 1000000), gcd returns the greatest common divisor: "
              "a positive result that divides both a and b exactly, and that is >= every other positive "
              "common divisor of a and b.",
        "gold": r'''public class GCD {
    //@ requires a > 0 && b >= 0;
    //@ requires a <= 1000000 && b <= 1000000;
    //@ ensures \result > 0;
    //@ ensures a % \result == 0;
    //@ ensures b % \result == 0;
    //@ ensures (\forall int d; d > 0 && a % d == 0 && b % d == 0; d <= \result);
    public static int gcd(int a, int b) { return 0; }
}
''',
    },
]
