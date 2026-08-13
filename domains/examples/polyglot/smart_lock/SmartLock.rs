use prusti_contracts::*;

pub struct SmartLock {
    pub door_state: i32,
    pub lock_state: i32,
}

impl SmartLock {
    #[ensures(result.door_state == 1 && result.lock_state == 0 && ((0 <= result.door_state) && (result.door_state <= 1)) && ((0 <= result.lock_state) && (result.lock_state <= 1)) && ((result.lock_state == 1) ==> (result.door_state == 1)))]
    pub fn new() -> Self {
        Self { door_state: 1, lock_state: 0 }
    }

    #[pure]
    #[ensures(result == self.door_state)]
    pub fn get_door_state(&self) -> i32 {
        self.door_state
    }

    #[pure]
    #[ensures(result == self.lock_state)]
    pub fn get_lock_state(&self) -> i32 {
        self.lock_state
    }

    #[requires(((0 <= self.door_state) && (self.door_state <= 1)) && ((0 <= self.lock_state) && (self.lock_state <= 1)) && ((self.lock_state == 1) ==> (self.door_state == 1)))]
    #[requires(self.door_state == 0)]
    #[requires(self.lock_state == 0)]
    #[ensures(self.door_state == 1)]
    #[ensures(((0 <= self.door_state) && (self.door_state <= 1)) && ((0 <= self.lock_state) && (self.lock_state <= 1)) && ((self.lock_state == 1) ==> (self.door_state == 1)))]
    pub fn close_door(&mut self) {
        self.door_state = 1;
    }

    #[requires(((0 <= self.door_state) && (self.door_state <= 1)) && ((0 <= self.lock_state) && (self.lock_state <= 1)) && ((self.lock_state == 1) ==> (self.door_state == 1)))]
    #[requires(self.door_state == 1)]
    #[requires(self.lock_state == 0)]
    #[ensures(self.door_state == 0)]
    #[ensures(((0 <= self.door_state) && (self.door_state <= 1)) && ((0 <= self.lock_state) && (self.lock_state <= 1)) && ((self.lock_state == 1) ==> (self.door_state == 1)))]
    pub fn open_door(&mut self) {
        self.door_state = 0;
    }

    #[requires(((0 <= self.door_state) && (self.door_state <= 1)) && ((0 <= self.lock_state) && (self.lock_state <= 1)) && ((self.lock_state == 1) ==> (self.door_state == 1)))]
    #[requires(self.door_state == 1)]
    #[requires(self.lock_state == 0)]
    #[ensures(self.lock_state == 1)]
    #[ensures(((0 <= self.door_state) && (self.door_state <= 1)) && ((0 <= self.lock_state) && (self.lock_state <= 1)) && ((self.lock_state == 1) ==> (self.door_state == 1)))]
    pub fn lock_door(&mut self) {
        self.lock_state = 1;
    }

    #[requires(((0 <= self.door_state) && (self.door_state <= 1)) && ((0 <= self.lock_state) && (self.lock_state <= 1)) && ((self.lock_state == 1) ==> (self.door_state == 1)))]
    #[requires(self.lock_state == 1)]
    #[ensures(self.lock_state == 0)]
    #[ensures(((0 <= self.door_state) && (self.door_state <= 1)) && ((0 <= self.lock_state) && (self.lock_state <= 1)) && ((self.lock_state == 1) ==> (self.door_state == 1)))]
    pub fn unlock_door(&mut self) {
        self.lock_state = 0;
    }
}
