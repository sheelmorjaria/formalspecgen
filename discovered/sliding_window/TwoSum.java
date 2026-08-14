public class TwoSum {
    //@ requires nums != null && nums.length >= 2 && nums.length <= 1000;
    //@ requires \forall int i; 0 <= i && i < nums.length; 0 <= nums[i] && nums[i] <= 10000;
    //@ requires target >= 0 && target <= 20000;
    //@ requires \exists int i, j; 0 <= i && i < j && j < nums.length; nums[i] + nums[j] == target;
    //@ ensures \result != null && \result.length == 2;
    //@ ensures (\result[0] == -1 && \result[1] == -1) ||
    //@         (0 <= \result[0] && \result[0] < \result[1] && \result[1] < nums.length &&
    //@          nums[\result[0]] + nums[\result[1]] == target);
    public int[] twoSum(int[] nums, int target) {
        int left = 0;
        int right = 1;
        
        //@ loop_invariant 0 <= left && left < nums.length;
        //@ loop_invariant 0 <= right && right <= nums.length;
        //@ loop_invariant left < right;
        //@ loop_invariant \forall int i; 0 <= i && i < left; \forall int j; right <= j && j < nums.length; nums[i] + nums[j] != target;
        while (left < nums.length - 1) {
            //@ loop_invariant left < right && right <= nums.length;
            //@ loop_invariant \forall int i; left < i && i < right; nums[left] + nums[i] != target;
            while (right < nums.length) {
                if (nums[left] + nums[right] == target) {
                    return new int[]{left, right};
                }
                right++;
            }
            left++;
            right = left + 1;
        }
        return new int[]{-1, -1};
    }
}
