use prusti_contracts::*;

#[invariant((0 <= self.value) && (self.value <= 5))]
#[invariant((self.value >= 0) && (self.value <= 5))]
pub struct BoundedCounter {
    pub value: i32,
}

impl BoundedCounter {
    #[ensures(result.value == 0)]
    pub fn new() -> Self {
        Self { value: 0 }
    }

    #[pure]
    #[ensures(result == self.value)]
    pub fn get_value(&self) -> i32 {
        self.value
    }

    #[requires(self.value < 5)]
    #[ensures(self.value == old(self.value) + 1)]
    pub fn increment(&mut self) {
        let pre_value = self.value;
        self.value = pre_value + 1;
    }

    #[requires(self.value > 0)]
    #[ensures(self.value == old(self.value) - 1)]
    pub fn decrement(&mut self) {
        let pre_value = self.value;
        self.value = pre_value - 1;
    }
}
