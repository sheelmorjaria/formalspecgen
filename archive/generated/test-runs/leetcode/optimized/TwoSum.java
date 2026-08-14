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
        int[] map = new int[10001];
        //@ loop_invariant 0 <= i && i <= map.length;
        //@ loop_invariant \forall int k; 0 <= k && k < i; map[k] == -1;
        //@ decreases map.length - i;
        for (int i = 0; i < map.length; i++) {
            map[i] = -1;
        }

        //@ loop_invariant 0 <= i && i <= nums.length;
        //@ loop_invariant (\forall int v; 0 <= v && v < map.length ==> (map[v] == -1 || (0 <= map[v] && map[v] < i && nums[map[v]] == v)));
        //@ decreases nums.length - i;
        for (int i = 0; i < nums.length; i++) {
            int complement = target - nums[i];
            if (complement >= 0 && complement <= 10000 && map[complement] != -1) {
                return new int[]{map[complement], i};
            }
            map[nums[i]] = i;
        }
        return new int[]{-1, -1};
    }
}
