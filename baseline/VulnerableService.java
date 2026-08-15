public class VulnerableService {
    // WARNING: No JML preconditions! This allows negative indices.
    public int getElement(int[] arr, int index) {
        return arr[index];
    }
}
