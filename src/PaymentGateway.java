public interface PaymentGateway {
    //@ requires amount > 0;
    //@ ensures \result == true || \result == false;
    public boolean processPayment(int amount);
}
