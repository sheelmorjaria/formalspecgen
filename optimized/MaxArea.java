public class MaxArea {
    //@ requires height != null && height.length >= 2 && height.length <= 1000;
    //@ requires \forall int i; 0 <= i && i < height.length; 0 <= height[i] && height[i] <= 10000;
    //@ ensures \result >= 0;
    //@ ensures \result <= 10000 * 1000;
    public int maxArea(int[] height) {
        int left = 0;
        int right = height.length - 1;
        int maxArea = 0;

        //@ loop_invariant 0 <= left && left <= right && right < height.length;
        //@ loop_invariant maxArea >= 0;
        //@ loop_invariant maxArea <= 10000 * 1000;
        //@ decreases right - left;
        while (left < right) {
            int h = height[left] <= height[right] ? height[left] : height[right];
            int area = h * (right - left);
            if (area > maxArea) {
                maxArea = area;
            }
            if (height[left] <= height[right]) {
                left++;
            } else {
                right--;
            }
        }
        return maxArea;
    }
}
