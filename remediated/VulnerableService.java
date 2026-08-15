public class VulnerableService {
    /**
     * Retrieves an element from the array at the specified index.
     * 
     * @param arr   the array to retrieve the element from
     * @param index the index of the element to retrieve
     * @return the element at the specified index
     * @throws NullPointerException if arr is null
     * @throws IndexOutOfBoundsException if index is negative or >= arr.length
     */
    public int getElement(int[] arr, int index) {
        // JML requires: arr != null && index >= 0 && index < arr.length
        // JML ensures: result == arr[index]
        
        if (arr == null) {
            throw new NullPointerException("Array cannot be null");
        }
        
        if (index < 0) {
            throw new IndexOutOfBoundsException("Index cannot be negative: " + index);
        }
        
        if (index >= arr.length) {
            throw new IndexOutOfBoundsException("Index out of bounds: " + index + " >= " + arr.length);
        }
        
        return arr[index];
    }
}
