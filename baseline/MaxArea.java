public class MaxArea {
    //@ requires height != null && height.length >= 2 && height.length <= 1000;
    //@ requires \forall int i; 0 <= i && i < height.length; 0 <= height[i] && height[i] <= 10000;
    //@ ensures \result >= 0;
    //@ ensures \result <= 10000 * 1000;
    public int maxArea(int[] height) {
        int maxArea = 0;
        //@ loop_invariant 0 <= i && i <= height.length;
        //@ loop_invariant maxArea >= 0;
        //@ loop_invariant maxArea <= 10000 * 1000;
        for (int i = 0; i < height.length; i++) {
            //@ loop_invariant i < j && j <= height.length;
            //@ loop_invariant maxArea >= 0;
            //@ loop_invariant maxArea <= 10000 * 1000;
            for (int j = i + 1; j < height.length; j++) {
                int h = height[i] <= height[j] ? height[i] : height[j];
                int area = h * (j - i);
                if (area > maxArea) {
                    maxArea = area;
                }
            }
        }
        return maxArea;
    }
}
