public class LegacyCounter {
    private int count;

    public LegacyCounter() {
        this.count = 0;
    }

    public void increment() {
        if (this.count < 5) {
            this.count = this.count + 1;
        }
    }

    public void decrement() {
        if (this.count > 0) {
            this.count = this.count - 1;
        }
    }
}
