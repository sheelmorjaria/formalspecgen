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
        for (int i = 0; i < nums.length; i++) {
            int lo = i + 1;
            int hi = nums.length - 1;
            //@ loop_invariant lo <= hi + 1;
            //@ loop_invariant \forall int k; i + 1 <= k && k < lo; nums[i] + nums[k] != target;
            //@ loop_invariant \forall int k; hi < k && k < nums.length; nums[i] + nums[k] != target;
            while (lo <= hi) {
                int mid = lo + (hi - lo) / 2;
                int sum = nums[i] + nums[mid];
                if (sum == target) {
                    return new int[]{i, mid};
                } else if (sum < target) {
                    lo = mid + 1;
                } else {
                    hi = mid - 1;
                }
            }
        }
        return new int[]{-1, -1};
    }
}
