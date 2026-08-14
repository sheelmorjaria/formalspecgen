public class TwoSum {
    //@ requires nums != null && nums.length <= 1000;
    //@ requires target >= 0;
    //@ ensures \result.length == 2;
    //@ ensures nums[\result[0]] + nums[\result[1]] == target;
    public int[] twoSum(int[] nums, int target) {
        for (int i = 0; i < nums.length; i++) {
            for (int j = i + 1; j < nums.length; j++) {
                if (nums[i] + nums[j] == target) return new int[]{i, j};
            }
        }
        return new int[]{-1, -1};
    }
}
