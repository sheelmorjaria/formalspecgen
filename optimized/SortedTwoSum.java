public class SortedTwoSum {
    //@ requires nums != null && nums.length >= 2 && nums.length <= 1000;
    //@ requires \forall int i; 0 <= i && i < nums.length; -10000 <= nums[i] && nums[i] <= 10000;
    //@ requires \forall int i; 0 <= i && i < nums.length - 1; nums[i] <= nums[i + 1];
    //@ requires target >= -20000 && target <= 20000;
    //@ ensures \result != null && \result.length == 2;
    //@ ensures (\result[0] == -1 && \result[1] == -1) ||
    //@         (0 <= \result[0] && \result[0] < \result[1] && \result[1] < nums.length &&
    //@          nums[\result[0]] + nums[\result[1]] == target);
    public int[] twoSum(int[] nums, int target) {
        int left = 0;
        int right = nums.length - 1;
        //@ loop_invariant 0 <= left && left <= right + 1 && right < nums.length;
        //@ decreases right - left;
        while (left < right) {
            int sum = nums[left] + nums[right];
            if (sum == target) {
                return new int[]{left, right};
            } else if (sum < target) {
                left++;
            } else {
                right--;
            }
        }
        return new int[]{-1, -1};
    }
}
