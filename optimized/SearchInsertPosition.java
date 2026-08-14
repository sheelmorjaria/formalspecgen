public class SearchInsertPosition {
    //@ requires nums != null && nums.length <= 1000;
    //@ requires \forall int i; 0 <= i && i < nums.length - 1; nums[i] < nums[i + 1];
    //@ requires target >= -10000 && target <= 10000;
    //@ ensures 0 <= \result && \result <= nums.length;
    //@ ensures \result < nums.length ==> target <= nums[\result];
    //@ ensures \result > 0 ==> target > nums[\result - 1];
    public int searchInsert(int[] nums, int target) {
        int left = 0;
        int right = nums.length - 1;
        int result = nums.length;
        
        //@ loop_invariant 0 <= left && right < nums.length && left <= right + 1;
        //@ loop_invariant (\forall int j; 0 <= j && j < left ==> nums[j] < target);
        //@ loop_invariant (\forall int j; right < j && j < nums.length ==> target <= nums[j]);
        //@ decreases right - left;
        while (left <= right) {
            int mid = left + (right - left) / 2;
            if (nums[mid] < target) {
                left = mid + 1;
            } else {
                result = mid;
                right = mid - 1;
            }
        }
        
        return result;
    }
}
