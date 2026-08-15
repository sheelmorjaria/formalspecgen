import static org.junit.jupiter.api.Assertions.assertThrows;
import org.junit.jupiter.api.Test;

class OutOfBoundsPoC2 {
    @Test
    void demonstratesOutOfBounds() {
        VulnerableService service = new VulnerableService();
        assertThrows(ArrayIndexOutOfBoundsException.class, () -> service.getElement(new int[]{1}, -1));
    }
}
