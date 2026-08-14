public class SortedTwoSum {
    //@ requires nums != null && nums.length >= 2 && nums.length <= 1000;
    //@ requires \forall int i; 0 <= i && i < nums.length; 0 <= nums[i] && nums[i] <= 10000;
    //@ requires \forall int i; 0 <= i && i < nums.length - 1 ==> nums[i] <= nums[i + 1];
    //@ requires target >= 0 && target <= 20000;
    //@ requires \exists int i, j; 0 <= i && i < j && j < nums.length && nums[i] + nums[j] == target;
    //@ ensures \result != null && \result.length == 2;
    //@ ensures (\result[0] == -1 && \result[1] == -1) ||
    //@         (0 <= \result[0] && \result[0] < \result[1] && \result[1] < nums.length &&
    //@          nums[\result[0]] + nums[\result[1]] == target);
    public int[] twoSum(int[] nums, int target) {
        //@ loop_invariant 0 <= i && i <= nums.length;
        //@ loop_invariant \forall int k; 0 <= k && k < i; \forall int l; i <= l && l < nums.length; nums[k] + nums[l] != target;
        for (int i = 0; i < nums.length; i++) {
            //@ loop_invariant i <= j && j <= nums.length;
            //@ loop_invariant \forall int k; i <= k && k < j; nums[i] + nums[k] != target;
            for (int j = i + 1; j < nums.length; j++) {
                if (nums[i] + nums[j] == target) return new int[]{i, j};
            }
        }
        return new int[]{-1, -1};
    }
}
