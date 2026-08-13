use prusti_contracts::*;

pub struct AsymmetricDiningPhilosophers {
    pub fork0: i32,
    pub fork1: i32,
    pub fork2: i32,
    pub pc0: i32,
    pub pc1: i32,
    pub pc2: i32,
}

impl AsymmetricDiningPhilosophers {
    #[ensures(result.fork0 == 0 && result.fork1 == 0 && result.fork2 == 0 && result.pc0 == 0 && result.pc1 == 0 && result.pc2 == 0 && (0 <= result.fork0) && (result.fork0 <= 3) && (0 <= result.fork1) && (result.fork1 <= 3) && (0 <= result.fork2) && (result.fork2 <= 3) && (0 <= result.pc0) && (result.pc0 <= 3) && (0 <= result.pc1) && (result.pc1 <= 3) && (0 <= result.pc2) && (result.pc2 <= 3) && ((result.pc0 == 3) ==> ((result.fork0 == 1) && (result.fork1 == 1))) && ((result.pc1 == 3) ==> ((result.fork1 == 2) && (result.fork2 == 2))) && ((result.pc2 == 3) ==> ((result.fork2 == 3) && (result.fork0 == 3))))]
    pub fn new() -> Self {
        Self { fork0: 0, fork1: 0, fork2: 0, pc0: 0, pc1: 0, pc2: 0 }
    }

    #[pure]
    #[ensures(result == self.fork0)]
    pub fn get_fork0(&self) -> i32 {
        self.fork0
    }

    #[pure]
    #[ensures(result == self.fork1)]
    pub fn get_fork1(&self) -> i32 {
        self.fork1
    }

    #[pure]
    #[ensures(result == self.fork2)]
    pub fn get_fork2(&self) -> i32 {
        self.fork2
    }

    #[pure]
    #[ensures(result == self.pc0)]
    pub fn get_pc0(&self) -> i32 {
        self.pc0
    }

    #[pure]
    #[ensures(result == self.pc1)]
    pub fn get_pc1(&self) -> i32 {
        self.pc1
    }

    #[pure]
    #[ensures(result == self.pc2)]
    pub fn get_pc2(&self) -> i32 {
        self.pc2
    }

    #[requires((0 <= self.fork0) && (self.fork0 <= 3) && (0 <= self.fork1) && (self.fork1 <= 3) && (0 <= self.fork2) && (self.fork2 <= 3) && (0 <= self.pc0) && (self.pc0 <= 3) && (0 <= self.pc1) && (self.pc1 <= 3) && (0 <= self.pc2) && (self.pc2 <= 3) && ((self.pc0 == 3) ==> ((self.fork0 == 1) && (self.fork1 == 1))) && ((self.pc1 == 3) ==> ((self.fork1 == 2) && (self.fork2 == 2))) && ((self.pc2 == 3) ==> ((self.fork2 == 3) && (self.fork0 == 3))))]
    #[requires(self.pc0 == 0)]
    #[ensures(self.pc0 == 1)]
    #[ensures((0 <= self.fork0) && (self.fork0 <= 3) && (0 <= self.fork1) && (self.fork1 <= 3) && (0 <= self.fork2) && (self.fork2 <= 3) && (0 <= self.pc0) && (self.pc0 <= 3) && (0 <= self.pc1) && (self.pc1 <= 3) && (0 <= self.pc2) && (self.pc2 <= 3) && ((self.pc0 == 3) ==> ((self.fork0 == 1) && (self.fork1 == 1))) && ((self.pc1 == 3) ==> ((self.fork1 == 2) && (self.fork2 == 2))) && ((self.pc2 == 3) ==> ((self.fork2 == 3) && (self.fork0 == 3))))]
    pub fn request_0(&mut self) {
        self.pc0 = 1;
    }

    #[requires((0 <= self.fork0) && (self.fork0 <= 3) && (0 <= self.fork1) && (self.fork1 <= 3) && (0 <= self.fork2) && (self.fork2 <= 3) && (0 <= self.pc0) && (self.pc0 <= 3) && (0 <= self.pc1) && (self.pc1 <= 3) && (0 <= self.pc2) && (self.pc2 <= 3) && ((self.pc0 == 3) ==> ((self.fork0 == 1) && (self.fork1 == 1))) && ((self.pc1 == 3) ==> ((self.fork1 == 2) && (self.fork2 == 2))) && ((self.pc2 == 3) ==> ((self.fork2 == 3) && (self.fork0 == 3))))]
    #[requires(self.pc0 == 1)]
    #[requires(self.fork1 == 0)]
    #[ensures(self.fork1 == 1 && self.pc0 == 2)]
    #[ensures((0 <= self.fork0) && (self.fork0 <= 3) && (0 <= self.fork1) && (self.fork1 <= 3) && (0 <= self.fork2) && (self.fork2 <= 3) && (0 <= self.pc0) && (self.pc0 <= 3) && (0 <= self.pc1) && (self.pc1 <= 3) && (0 <= self.pc2) && (self.pc2 <= 3) && ((self.pc0 == 3) ==> ((self.fork0 == 1) && (self.fork1 == 1))) && ((self.pc1 == 3) ==> ((self.fork1 == 2) && (self.fork2 == 2))) && ((self.pc2 == 3) ==> ((self.fork2 == 3) && (self.fork0 == 3))))]
    pub fn pickup_right_0(&mut self) {
        self.fork1 = 1;
        self.pc0 = 2;
    }

    #[requires((0 <= self.fork0) && (self.fork0 <= 3) && (0 <= self.fork1) && (self.fork1 <= 3) && (0 <= self.fork2) && (self.fork2 <= 3) && (0 <= self.pc0) && (self.pc0 <= 3) && (0 <= self.pc1) && (self.pc1 <= 3) && (0 <= self.pc2) && (self.pc2 <= 3) && ((self.pc0 == 3) ==> ((self.fork0 == 1) && (self.fork1 == 1))) && ((self.pc1 == 3) ==> ((self.fork1 == 2) && (self.fork2 == 2))) && ((self.pc2 == 3) ==> ((self.fork2 == 3) && (self.fork0 == 3))))]
    #[requires(self.pc0 == 2)]
    #[requires(self.fork1 == 1)]
    #[requires(self.fork0 == 0)]
    #[ensures(self.fork0 == 1 && self.pc0 == 3)]
    #[ensures((0 <= self.fork0) && (self.fork0 <= 3) && (0 <= self.fork1) && (self.fork1 <= 3) && (0 <= self.fork2) && (self.fork2 <= 3) && (0 <= self.pc0) && (self.pc0 <= 3) && (0 <= self.pc1) && (self.pc1 <= 3) && (0 <= self.pc2) && (self.pc2 <= 3) && ((self.pc0 == 3) ==> ((self.fork0 == 1) && (self.fork1 == 1))) && ((self.pc1 == 3) ==> ((self.fork1 == 2) && (self.fork2 == 2))) && ((self.pc2 == 3) ==> ((self.fork2 == 3) && (self.fork0 == 3))))]
    pub fn pickup_left_0(&mut self) {
        self.fork0 = 1;
        self.pc0 = 3;
    }

    #[requires((0 <= self.fork0) && (self.fork0 <= 3) && (0 <= self.fork1) && (self.fork1 <= 3) && (0 <= self.fork2) && (self.fork2 <= 3) && (0 <= self.pc0) && (self.pc0 <= 3) && (0 <= self.pc1) && (self.pc1 <= 3) && (0 <= self.pc2) && (self.pc2 <= 3) && ((self.pc0 == 3) ==> ((self.fork0 == 1) && (self.fork1 == 1))) && ((self.pc1 == 3) ==> ((self.fork1 == 2) && (self.fork2 == 2))) && ((self.pc2 == 3) ==> ((self.fork2 == 3) && (self.fork0 == 3))))]
    #[requires(self.pc0 == 3)]
    #[requires(self.fork0 == 1)]
    #[requires(self.fork1 == 1)]
    #[ensures(self.fork0 == 0 && self.fork1 == 0 && self.pc0 == 0)]
    #[ensures((0 <= self.fork0) && (self.fork0 <= 3) && (0 <= self.fork1) && (self.fork1 <= 3) && (0 <= self.fork2) && (self.fork2 <= 3) && (0 <= self.pc0) && (self.pc0 <= 3) && (0 <= self.pc1) && (self.pc1 <= 3) && (0 <= self.pc2) && (self.pc2 <= 3) && ((self.pc0 == 3) ==> ((self.fork0 == 1) && (self.fork1 == 1))) && ((self.pc1 == 3) ==> ((self.fork1 == 2) && (self.fork2 == 2))) && ((self.pc2 == 3) ==> ((self.fork2 == 3) && (self.fork0 == 3))))]
    pub fn putdown_0(&mut self) {
        self.fork0 = 0;
        self.fork1 = 0;
        self.pc0 = 0;
    }

    #[requires((0 <= self.fork0) && (self.fork0 <= 3) && (0 <= self.fork1) && (self.fork1 <= 3) && (0 <= self.fork2) && (self.fork2 <= 3) && (0 <= self.pc0) && (self.pc0 <= 3) && (0 <= self.pc1) && (self.pc1 <= 3) && (0 <= self.pc2) && (self.pc2 <= 3) && ((self.pc0 == 3) ==> ((self.fork0 == 1) && (self.fork1 == 1))) && ((self.pc1 == 3) ==> ((self.fork1 == 2) && (self.fork2 == 2))) && ((self.pc2 == 3) ==> ((self.fork2 == 3) && (self.fork0 == 3))))]
    #[requires(self.pc1 == 0)]
    #[ensures(self.pc1 == 1)]
    #[ensures((0 <= self.fork0) && (self.fork0 <= 3) && (0 <= self.fork1) && (self.fork1 <= 3) && (0 <= self.fork2) && (self.fork2 <= 3) && (0 <= self.pc0) && (self.pc0 <= 3) && (0 <= self.pc1) && (self.pc1 <= 3) && (0 <= self.pc2) && (self.pc2 <= 3) && ((self.pc0 == 3) ==> ((self.fork0 == 1) && (self.fork1 == 1))) && ((self.pc1 == 3) ==> ((self.fork1 == 2) && (self.fork2 == 2))) && ((self.pc2 == 3) ==> ((self.fork2 == 3) && (self.fork0 == 3))))]
    pub fn request_1(&mut self) {
        self.pc1 = 1;
    }

    #[requires((0 <= self.fork0) && (self.fork0 <= 3) && (0 <= self.fork1) && (self.fork1 <= 3) && (0 <= self.fork2) && (self.fork2 <= 3) && (0 <= self.pc0) && (self.pc0 <= 3) && (0 <= self.pc1) && (self.pc1 <= 3) && (0 <= self.pc2) && (self.pc2 <= 3) && ((self.pc0 == 3) ==> ((self.fork0 == 1) && (self.fork1 == 1))) && ((self.pc1 == 3) ==> ((self.fork1 == 2) && (self.fork2 == 2))) && ((self.pc2 == 3) ==> ((self.fork2 == 3) && (self.fork0 == 3))))]
    #[requires(self.pc1 == 1)]
    #[requires(self.fork1 == 0)]
    #[ensures(self.fork1 == 2 && self.pc1 == 2)]
    #[ensures((0 <= self.fork0) && (self.fork0 <= 3) && (0 <= self.fork1) && (self.fork1 <= 3) && (0 <= self.fork2) && (self.fork2 <= 3) && (0 <= self.pc0) && (self.pc0 <= 3) && (0 <= self.pc1) && (self.pc1 <= 3) && (0 <= self.pc2) && (self.pc2 <= 3) && ((self.pc0 == 3) ==> ((self.fork0 == 1) && (self.fork1 == 1))) && ((self.pc1 == 3) ==> ((self.fork1 == 2) && (self.fork2 == 2))) && ((self.pc2 == 3) ==> ((self.fork2 == 3) && (self.fork0 == 3))))]
    pub fn pickup_left_1(&mut self) {
        self.fork1 = 2;
        self.pc1 = 2;
    }

    #[requires((0 <= self.fork0) && (self.fork0 <= 3) && (0 <= self.fork1) && (self.fork1 <= 3) && (0 <= self.fork2) && (self.fork2 <= 3) && (0 <= self.pc0) && (self.pc0 <= 3) && (0 <= self.pc1) && (self.pc1 <= 3) && (0 <= self.pc2) && (self.pc2 <= 3) && ((self.pc0 == 3) ==> ((self.fork0 == 1) && (self.fork1 == 1))) && ((self.pc1 == 3) ==> ((self.fork1 == 2) && (self.fork2 == 2))) && ((self.pc2 == 3) ==> ((self.fork2 == 3) && (self.fork0 == 3))))]
    #[requires(self.pc1 == 2)]
    #[requires(self.fork1 == 2)]
    #[requires(self.fork2 == 0)]
    #[ensures(self.fork2 == 2 && self.pc1 == 3)]
    #[ensures((0 <= self.fork0) && (self.fork0 <= 3) && (0 <= self.fork1) && (self.fork1 <= 3) && (0 <= self.fork2) && (self.fork2 <= 3) && (0 <= self.pc0) && (self.pc0 <= 3) && (0 <= self.pc1) && (self.pc1 <= 3) && (0 <= self.pc2) && (self.pc2 <= 3) && ((self.pc0 == 3) ==> ((self.fork0 == 1) && (self.fork1 == 1))) && ((self.pc1 == 3) ==> ((self.fork1 == 2) && (self.fork2 == 2))) && ((self.pc2 == 3) ==> ((self.fork2 == 3) && (self.fork0 == 3))))]
    pub fn pickup_right_1(&mut self) {
        self.fork2 = 2;
        self.pc1 = 3;
    }

    #[requires((0 <= self.fork0) && (self.fork0 <= 3) && (0 <= self.fork1) && (self.fork1 <= 3) && (0 <= self.fork2) && (self.fork2 <= 3) && (0 <= self.pc0) && (self.pc0 <= 3) && (0 <= self.pc1) && (self.pc1 <= 3) && (0 <= self.pc2) && (self.pc2 <= 3) && ((self.pc0 == 3) ==> ((self.fork0 == 1) && (self.fork1 == 1))) && ((self.pc1 == 3) ==> ((self.fork1 == 2) && (self.fork2 == 2))) && ((self.pc2 == 3) ==> ((self.fork2 == 3) && (self.fork0 == 3))))]
    #[requires(self.pc1 == 3)]
    #[requires(self.fork1 == 2)]
    #[requires(self.fork2 == 2)]
    #[ensures(self.fork1 == 0 && self.fork2 == 0 && self.pc1 == 0)]
    #[ensures((0 <= self.fork0) && (self.fork0 <= 3) && (0 <= self.fork1) && (self.fork1 <= 3) && (0 <= self.fork2) && (self.fork2 <= 3) && (0 <= self.pc0) && (self.pc0 <= 3) && (0 <= self.pc1) && (self.pc1 <= 3) && (0 <= self.pc2) && (self.pc2 <= 3) && ((self.pc0 == 3) ==> ((self.fork0 == 1) && (self.fork1 == 1))) && ((self.pc1 == 3) ==> ((self.fork1 == 2) && (self.fork2 == 2))) && ((self.pc2 == 3) ==> ((self.fork2 == 3) && (self.fork0 == 3))))]
    pub fn putdown_1(&mut self) {
        self.fork1 = 0;
        self.fork2 = 0;
        self.pc1 = 0;
    }

    #[requires((0 <= self.fork0) && (self.fork0 <= 3) && (0 <= self.fork1) && (self.fork1 <= 3) && (0 <= self.fork2) && (self.fork2 <= 3) && (0 <= self.pc0) && (self.pc0 <= 3) && (0 <= self.pc1) && (self.pc1 <= 3) && (0 <= self.pc2) && (self.pc2 <= 3) && ((self.pc0 == 3) ==> ((self.fork0 == 1) && (self.fork1 == 1))) && ((self.pc1 == 3) ==> ((self.fork1 == 2) && (self.fork2 == 2))) && ((self.pc2 == 3) ==> ((self.fork2 == 3) && (self.fork0 == 3))))]
    #[requires(self.pc2 == 0)]
    #[ensures(self.pc2 == 1)]
    #[ensures((0 <= self.fork0) && (self.fork0 <= 3) && (0 <= self.fork1) && (self.fork1 <= 3) && (0 <= self.fork2) && (self.fork2 <= 3) && (0 <= self.pc0) && (self.pc0 <= 3) && (0 <= self.pc1) && (self.pc1 <= 3) && (0 <= self.pc2) && (self.pc2 <= 3) && ((self.pc0 == 3) ==> ((self.fork0 == 1) && (self.fork1 == 1))) && ((self.pc1 == 3) ==> ((self.fork1 == 2) && (self.fork2 == 2))) && ((self.pc2 == 3) ==> ((self.fork2 == 3) && (self.fork0 == 3))))]
    pub fn request_2(&mut self) {
        self.pc2 = 1;
    }

    #[requires((0 <= self.fork0) && (self.fork0 <= 3) && (0 <= self.fork1) && (self.fork1 <= 3) && (0 <= self.fork2) && (self.fork2 <= 3) && (0 <= self.pc0) && (self.pc0 <= 3) && (0 <= self.pc1) && (self.pc1 <= 3) && (0 <= self.pc2) && (self.pc2 <= 3) && ((self.pc0 == 3) ==> ((self.fork0 == 1) && (self.fork1 == 1))) && ((self.pc1 == 3) ==> ((self.fork1 == 2) && (self.fork2 == 2))) && ((self.pc2 == 3) ==> ((self.fork2 == 3) && (self.fork0 == 3))))]
    #[requires(self.pc2 == 1)]
    #[requires(self.fork2 == 0)]
    #[ensures(self.fork2 == 3 && self.pc2 == 2)]
    #[ensures((0 <= self.fork0) && (self.fork0 <= 3) && (0 <= self.fork1) && (self.fork1 <= 3) && (0 <= self.fork2) && (self.fork2 <= 3) && (0 <= self.pc0) && (self.pc0 <= 3) && (0 <= self.pc1) && (self.pc1 <= 3) && (0 <= self.pc2) && (self.pc2 <= 3) && ((self.pc0 == 3) ==> ((self.fork0 == 1) && (self.fork1 == 1))) && ((self.pc1 == 3) ==> ((self.fork1 == 2) && (self.fork2 == 2))) && ((self.pc2 == 3) ==> ((self.fork2 == 3) && (self.fork0 == 3))))]
    pub fn pickup_left_2(&mut self) {
        self.fork2 = 3;
        self.pc2 = 2;
    }

    #[requires((0 <= self.fork0) && (self.fork0 <= 3) && (0 <= self.fork1) && (self.fork1 <= 3) && (0 <= self.fork2) && (self.fork2 <= 3) && (0 <= self.pc0) && (self.pc0 <= 3) && (0 <= self.pc1) && (self.pc1 <= 3) && (0 <= self.pc2) && (self.pc2 <= 3) && ((self.pc0 == 3) ==> ((self.fork0 == 1) && (self.fork1 == 1))) && ((self.pc1 == 3) ==> ((self.fork1 == 2) && (self.fork2 == 2))) && ((self.pc2 == 3) ==> ((self.fork2 == 3) && (self.fork0 == 3))))]
    #[requires(self.pc2 == 2)]
    #[requires(self.fork2 == 3)]
    #[requires(self.fork0 == 0)]
    #[ensures(self.fork0 == 3 && self.pc2 == 3)]
    #[ensures((0 <= self.fork0) && (self.fork0 <= 3) && (0 <= self.fork1) && (self.fork1 <= 3) && (0 <= self.fork2) && (self.fork2 <= 3) && (0 <= self.pc0) && (self.pc0 <= 3) && (0 <= self.pc1) && (self.pc1 <= 3) && (0 <= self.pc2) && (self.pc2 <= 3) && ((self.pc0 == 3) ==> ((self.fork0 == 1) && (self.fork1 == 1))) && ((self.pc1 == 3) ==> ((self.fork1 == 2) && (self.fork2 == 2))) && ((self.pc2 == 3) ==> ((self.fork2 == 3) && (self.fork0 == 3))))]
    pub fn pickup_right_2(&mut self) {
        self.fork0 = 3;
        self.pc2 = 3;
    }

    #[requires((0 <= self.fork0) && (self.fork0 <= 3) && (0 <= self.fork1) && (self.fork1 <= 3) && (0 <= self.fork2) && (self.fork2 <= 3) && (0 <= self.pc0) && (self.pc0 <= 3) && (0 <= self.pc1) && (self.pc1 <= 3) && (0 <= self.pc2) && (self.pc2 <= 3) && ((self.pc0 == 3) ==> ((self.fork0 == 1) && (self.fork1 == 1))) && ((self.pc1 == 3) ==> ((self.fork1 == 2) && (self.fork2 == 2))) && ((self.pc2 == 3) ==> ((self.fork2 == 3) && (self.fork0 == 3))))]
    #[requires(self.pc2 == 3)]
    #[requires(self.fork2 == 3)]
    #[requires(self.fork0 == 3)]
    #[ensures(self.fork2 == 0 && self.fork0 == 0 && self.pc2 == 0)]
    #[ensures((0 <= self.fork0) && (self.fork0 <= 3) && (0 <= self.fork1) && (self.fork1 <= 3) && (0 <= self.fork2) && (self.fork2 <= 3) && (0 <= self.pc0) && (self.pc0 <= 3) && (0 <= self.pc1) && (self.pc1 <= 3) && (0 <= self.pc2) && (self.pc2 <= 3) && ((self.pc0 == 3) ==> ((self.fork0 == 1) && (self.fork1 == 1))) && ((self.pc1 == 3) ==> ((self.fork1 == 2) && (self.fork2 == 2))) && ((self.pc2 == 3) ==> ((self.fork2 == 3) && (self.fork0 == 3))))]
    pub fn putdown_2(&mut self) {
        self.fork2 = 0;
        self.fork0 = 0;
        self.pc2 = 0;
    }
}
