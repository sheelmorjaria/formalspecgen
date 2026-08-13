#include <stddef.h>

/*@ 
  requires \valid(counter);
  requires \valid_read(max_value);
  requires *max_value >= 0;
  requires *counter >= 0;
  requires *counter <= *max_value;
  
  assigns *counter;
  
  ensures *counter == (*counter < *max_value) ? *counter + 1 : 0;
  ensures \result == (*counter < *max_value) ? 1 : 0;
*/
int reviewed_bounded_counter(int* counter, const int* max_value) {
    if (counter == NULL || max_value == NULL) {
        return 0;
    }
    
    if (*counter < *max_value) {
        (*counter)++;
        return 1;
    } else {
        *counter = 0;
        return 0;
    }
}
