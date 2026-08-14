public class RunningSum {
    //@ requires nums != null && nums.length <= 1000;
    //@ requires \forall int i; 0 <= i && i < nums.length; -10000 <= nums[i] && nums[i] <= 10000;
    //@ ensures \result != null && \result.length == nums.length;
    public int[] runningSum(int[] nums) {
        int[] result = new int[nums.length];
        int total = 0;
        //@ loop_invariant 0 <= i && i <= nums.length;
        //@ loop_invariant total == \sum(int j; 0; j < i; nums[j]);
        //@ loop_invariant \forall int k; 0 <= k && k < i; result[k] == \sum(int j; 0; j < k + 1; nums[j]);
        for (int i = 0; i < nums.length; i++) {
            total += nums[i];
            result[i] = total;
        }
        return result;
    }
}
