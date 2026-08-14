use prusti_contracts::*;

pub struct RateLimiter {
    pub tokens: i32,
}

impl RateLimiter {
    #[ensures(result.tokens == 5 && (0 <= result.tokens) && (result.tokens <= 5))]
    pub fn new() -> Self {
        Self { tokens: 5 }
    }

    #[pure]
    #[ensures(result == self.tokens)]
    pub fn get_tokens(&self) -> i32 {
        self.tokens
    }

    #[requires((0 <= self.tokens) && (self.tokens <= 5))]
    #[requires(self.tokens > 0)]
    #[ensures(self.tokens == old(self.tokens) - 1)]
    #[ensures((0 <= self.tokens) && (self.tokens <= 5))]
    pub fn handle_request(&mut self) {
        let pre_tokens = self.tokens;
        self.tokens = pre_tokens - 1;
    }

    #[requires((0 <= self.tokens) && (self.tokens <= 5))]
    #[requires(self.tokens < 5)]
    #[ensures(self.tokens == 5)]
    #[ensures((0 <= self.tokens) && (self.tokens <= 5))]
    pub fn refill(&mut self) {
        self.tokens = 5;
    }
}
