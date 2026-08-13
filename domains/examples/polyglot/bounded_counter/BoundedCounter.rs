use prusti_contracts::*;

pub struct BoundedCounter {
    value: i32,
    min: i32,
    max: i32,
}

#[requires(min <= max)]
pub fn create_bounded_counter(min: i32, max: i32) -> BoundedCounter {
    BoundedCounter { value: min, min, max }
}

impl BoundedCounter {
    #[requires(self.min <= self.max)]
    #[ensures(|result: &mut Self| result.value == old(result).value + 1)]
    #[ensures(|result: &mut Self| result.min == old(result).min)]
    #[ensures(|result: &mut Self| result.max == old(result).max)]
    pub fn increment(&mut self) {
        if self.value < self.max {
            self.value += 1;
        }
    }

    #[requires(self.min <= self.max)]
    #[ensures(|result: &mut Self| result.value == old(result).value - 1)]
    #[ensures(|result: &mut Self| result.min == old(result).min)]
    #[ensures(|result: &mut Self| result.max == old(result).max)]
    pub fn decrement(&mut self) {
        if self.value > self.min {
            self.value -= 1;
        }
    }

    #[requires(self.min <= self.max)]
    #[ensures(|result: &Self| result.value >= result.min)]
    #[ensures(|result: &Self| result.value <= result.max)]
    pub fn get_value(&self) -> i32 {
        self.value
    }

    #[requires(self.min <= self.max)]
    #[ensures(|result: &Self| result.min == old(result).min)]
    #[ensures(|result: &Self| result.max == old(result).max)]
    pub fn get_min(&self) -> i32 {
        self.min
    }

    #[requires(self.min <= self.max)]
    #[ensures(|result: &Self| result.min == old(result).min)]
    #[ensures(|result: &Self| result.max == old(result).max)]
    pub fn get_max(&self) -> i32 {
        self.max
    }

    #[requires(self.min <= self.max)]
    #[ensures(|result: &mut Self| result.value == new_value)]
    #[ensures(|result: &mut Self| result.min == old(result).min)]
    #[ensures(|result: &mut Self| result.max == old(result).max)]
    pub fn set_value(&mut self, new_value: i32) {
        if new_value >= self.min && new_value <= self.max {
            self.value = new_value;
        }
    }

    #[requires(self.min <= self.max)]
    #[ensures(|result: &mut Self| result.value == old(result).min)]
    #[ensures(|result: &mut Self| result.min == old(result).min)]
    #[ensures(|result: &mut Self| result.max == old(result).max)]
    pub fn reset(&mut self) {
        self.value = self.min;
    }
}
