public class LegacyService {
    private /*@ spec_public @*/ int count;

    //@ requires count >= 0 && count <= 2147483642;
    //@ assignable count;
    //@ ensures count == \old(count) + 5;
    public void processOrder() {
        processOrderExtracted();
    }

    //@ requires count >= 0 && count <= 2147483642;
    //@ assignable count;
    //@ ensures count == \old(count) + 5;
    private void processOrderExtracted() {
        // A long, monolithic method that should be extracted
        int temp = count;
        temp = temp + 2;
        temp = temp + 3;
        temp = temp;
        temp = temp;
        temp = temp;
        temp = temp;
        temp = temp;
        temp = temp;
        temp = temp;
        temp = temp;
        temp = temp;
        temp = temp;
        temp = temp;
        temp = temp;
        temp = temp;
        temp = temp;
        temp = temp;
        temp = temp;
        temp = temp;
        temp = temp;
        temp = temp;
        temp = temp;
        temp = temp;
        temp = temp;
        temp = temp;
        temp = temp;
        temp = temp;
        temp = temp;
        temp = temp;
        temp = temp;
        temp = temp;
        temp = temp;
        temp = temp;
        temp = temp;
        temp = temp;
        temp = temp;
        temp = temp;
        temp = temp;
        temp = temp;
        temp = temp;
        temp = temp;
        temp = temp;
        temp = temp;
        temp = temp;
        temp = temp;
        temp = temp;
        temp = temp;
        temp = temp;
        temp = temp;
        temp = temp;
        temp = temp;
        temp = temp;
        temp = temp;
        temp = temp;
        temp = temp;
        temp = temp;
        temp = temp;
        temp = temp;
        temp = temp;
        temp = temp;
        temp = temp;
        temp = temp;
        count = temp;
    }
}
