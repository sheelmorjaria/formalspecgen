public class SearchInsertPosition {
    //@ requires nums != null && nums.length <= 1000;
    //@ requires \forall int i; 0 <= i && i < nums.length - 1; nums[i] < nums[i + 1];
    //@ requires target >= -10000 && target <= 10000;
    //@ ensures 0 <= \result && \result <= nums.length;
    //@ ensures \result < nums.length ==> target <= nums[\result];
    //@ ensures \result > 0 ==> target > nums[\result - 1];
    public int searchInsert(int[] nums, int target) {
        int i = 0;
        //@ loop_invariant 0 <= i && i <= nums.length;
        //@ loop_invariant (\forall int j; 0 <= j && j < i ==> nums[j] < target);
        //@ decreases nums.length - i;
        while (i < nums.length && nums[i] < target) {
            i++;
        }
        return i;
    }
}
