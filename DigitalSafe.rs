use prusti_contracts::*;

pub struct DigitalSafe {
    pub safe_state: i32,
    pub attempts: i32,
}

impl DigitalSafe {
    #[ensures(result.safe_state == 0 && result.attempts == 0 && (0 <= result.safe_state) && (result.safe_state <= 2) && (0 <= result.attempts) && (result.attempts <= 3) && ((result.safe_state == 1) ==> (result.attempts == 0)) && ((result.safe_state == 2) ==> (result.attempts == 3)))]
    pub fn new() -> Self {
        Self { safe_state: 0, attempts: 0 }
    }

    #[pure]
    #[ensures(result == self.safe_state)]
    pub fn get_safe_state(&self) -> i32 {
        self.safe_state
    }

    #[pure]
    #[ensures(result == self.attempts)]
    pub fn get_attempts(&self) -> i32 {
        self.attempts
    }

    #[requires((0 <= self.safe_state) && (self.safe_state <= 2) && (0 <= self.attempts) && (self.attempts <= 3) && ((self.safe_state == 1) ==> (self.attempts == 0)) && ((self.safe_state == 2) ==> (self.attempts == 3)))]
    #[requires(self.safe_state == 0)]
    #[requires(self.attempts == 0)]
    #[ensures(self.safe_state == 1)]
    #[ensures((0 <= self.safe_state) && (self.safe_state <= 2) && (0 <= self.attempts) && (self.attempts <= 3) && ((self.safe_state == 1) ==> (self.attempts == 0)) && ((self.safe_state == 2) ==> (self.attempts == 3)))]
    pub fn unlock(&mut self) {
        self.safe_state = 1;
    }

    #[requires((0 <= self.safe_state) && (self.safe_state <= 2) && (0 <= self.attempts) && (self.attempts <= 3) && ((self.safe_state == 1) ==> (self.attempts == 0)) && ((self.safe_state == 2) ==> (self.attempts == 3)))]
    #[requires(self.safe_state == 0)]
    #[requires(self.attempts < 2)]
    #[ensures(self.attempts == old(self.attempts) + 1)]
    #[ensures((0 <= self.safe_state) && (self.safe_state <= 2) && (0 <= self.attempts) && (self.attempts <= 3) && ((self.safe_state == 1) ==> (self.attempts == 0)) && ((self.safe_state == 2) ==> (self.attempts == 3)))]
    pub fn fail_attempt(&mut self) {
        let pre_attempts = self.attempts;
        self.attempts = pre_attempts + 1;
    }

    #[requires((0 <= self.safe_state) && (self.safe_state <= 2) && (0 <= self.attempts) && (self.attempts <= 3) && ((self.safe_state == 1) ==> (self.attempts == 0)) && ((self.safe_state == 2) ==> (self.attempts == 3)))]
    #[requires(self.safe_state == 0)]
    #[requires(self.attempts == 2)]
    #[ensures(self.safe_state == 2 && self.attempts == 3)]
    #[ensures((0 <= self.safe_state) && (self.safe_state <= 2) && (0 <= self.attempts) && (self.attempts <= 3) && ((self.safe_state == 1) ==> (self.attempts == 0)) && ((self.safe_state == 2) ==> (self.attempts == 3)))]
    pub fn block_safe(&mut self) {
        self.safe_state = 2;
        self.attempts = 3;
    }

    #[requires((0 <= self.safe_state) && (self.safe_state <= 2) && (0 <= self.attempts) && (self.attempts <= 3) && ((self.safe_state == 1) ==> (self.attempts == 0)) && ((self.safe_state == 2) ==> (self.attempts == 3)))]
    #[requires(self.safe_state == 1)]
    #[ensures(self.safe_state == 0 && self.attempts == 0)]
    #[ensures((0 <= self.safe_state) && (self.safe_state <= 2) && (0 <= self.attempts) && (self.attempts <= 3) && ((self.safe_state == 1) ==> (self.attempts == 0)) && ((self.safe_state == 2) ==> (self.attempts == 3)))]
    pub fn lock(&mut self) {
        self.safe_state = 0;
        self.attempts = 0;
    }

    #[requires((0 <= self.safe_state) && (self.safe_state <= 2) && (0 <= self.attempts) && (self.attempts <= 3) && ((self.safe_state == 1) ==> (self.attempts == 0)) && ((self.safe_state == 2) ==> (self.attempts == 3)))]
    #[requires(self.safe_state == 2)]
    #[ensures(self.safe_state == 0 && self.attempts == 0)]
    #[ensures((0 <= self.safe_state) && (self.safe_state <= 2) && (0 <= self.attempts) && (self.attempts <= 3) && ((self.safe_state == 1) ==> (self.attempts == 0)) && ((self.safe_state == 2) ==> (self.attempts == 3)))]
    pub fn admin_reset(&mut self) {
        self.safe_state = 0;
        self.attempts = 0;
    }
}
