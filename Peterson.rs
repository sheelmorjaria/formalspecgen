use prusti_contracts::*;

pub struct Peterson {
    pub flag0: i32,
    pub flag1: i32,
    pub turn: i32,
    pub pc0: i32,
    pub pc1: i32,
}

impl Peterson {
    #[ensures(result.flag0 == 0 && result.flag1 == 0 && result.turn == 0 && result.pc0 == 0 && result.pc1 == 0 && (0 <= result.flag0) && (result.flag0 <= 1) && (0 <= result.flag1) && (result.flag1 <= 1) && (0 <= result.turn) && (result.turn <= 1) && (0 <= result.pc0) && (result.pc0 <= 2) && (0 <= result.pc1) && (result.pc1 <= 2) && (!((result.pc0 == 2) && (result.pc1 == 2))) && ((result.pc0 == 2) ==> (result.flag0 == 1)) && ((result.pc1 == 2) ==> (result.flag1 == 1)) && ((result.pc0 == 2) ==> ((result.flag1 == 0) || (result.turn == 0))) && ((result.pc1 == 2) ==> ((result.flag0 == 0) || (result.turn == 1))) && ((result.pc0 == 1) ==> (result.flag0 == 1)) && ((result.pc1 == 1) ==> (result.flag1 == 1)))]
    pub fn new() -> Self {
        Self { flag0: 0, flag1: 0, turn: 0, pc0: 0, pc1: 0 }
    }

    #[pure]
    #[ensures(result == self.flag0)]
    pub fn get_flag0(&self) -> i32 {
        self.flag0
    }

    #[pure]
    #[ensures(result == self.flag1)]
    pub fn get_flag1(&self) -> i32 {
        self.flag1
    }

    #[pure]
    #[ensures(result == self.turn)]
    pub fn get_turn(&self) -> i32 {
        self.turn
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

    #[requires((0 <= self.flag0) && (self.flag0 <= 1) && (0 <= self.flag1) && (self.flag1 <= 1) && (0 <= self.turn) && (self.turn <= 1) && (0 <= self.pc0) && (self.pc0 <= 2) && (0 <= self.pc1) && (self.pc1 <= 2) && (!((self.pc0 == 2) && (self.pc1 == 2))) && ((self.pc0 == 2) ==> (self.flag0 == 1)) && ((self.pc1 == 2) ==> (self.flag1 == 1)) && ((self.pc0 == 2) ==> ((self.flag1 == 0) || (self.turn == 0))) && ((self.pc1 == 2) ==> ((self.flag0 == 0) || (self.turn == 1))) && ((self.pc0 == 1) ==> (self.flag0 == 1)) && ((self.pc1 == 1) ==> (self.flag1 == 1)))]
    #[requires(self.pc0 == 0)]
    #[ensures(self.flag0 == 1 && self.turn == 1 && self.pc0 == 1)]
    #[ensures((0 <= self.flag0) && (self.flag0 <= 1) && (0 <= self.flag1) && (self.flag1 <= 1) && (0 <= self.turn) && (self.turn <= 1) && (0 <= self.pc0) && (self.pc0 <= 2) && (0 <= self.pc1) && (self.pc1 <= 2) && (!((self.pc0 == 2) && (self.pc1 == 2))) && ((self.pc0 == 2) ==> (self.flag0 == 1)) && ((self.pc1 == 2) ==> (self.flag1 == 1)) && ((self.pc0 == 2) ==> ((self.flag1 == 0) || (self.turn == 0))) && ((self.pc1 == 2) ==> ((self.flag0 == 0) || (self.turn == 1))) && ((self.pc0 == 1) ==> (self.flag0 == 1)) && ((self.pc1 == 1) ==> (self.flag1 == 1)))]
    pub fn request0(&mut self) {
        self.flag0 = 1;
        self.turn = 1;
        self.pc0 = 1;
    }

    #[requires((0 <= self.flag0) && (self.flag0 <= 1) && (0 <= self.flag1) && (self.flag1 <= 1) && (0 <= self.turn) && (self.turn <= 1) && (0 <= self.pc0) && (self.pc0 <= 2) && (0 <= self.pc1) && (self.pc1 <= 2) && (!((self.pc0 == 2) && (self.pc1 == 2))) && ((self.pc0 == 2) ==> (self.flag0 == 1)) && ((self.pc1 == 2) ==> (self.flag1 == 1)) && ((self.pc0 == 2) ==> ((self.flag1 == 0) || (self.turn == 0))) && ((self.pc1 == 2) ==> ((self.flag0 == 0) || (self.turn == 1))) && ((self.pc0 == 1) ==> (self.flag0 == 1)) && ((self.pc1 == 1) ==> (self.flag1 == 1)))]
    #[requires(self.pc0 == 1)]
    #[requires((self.flag1 == 0) || (self.turn == 0))]
    #[ensures(self.pc0 == 2)]
    #[ensures((0 <= self.flag0) && (self.flag0 <= 1) && (0 <= self.flag1) && (self.flag1 <= 1) && (0 <= self.turn) && (self.turn <= 1) && (0 <= self.pc0) && (self.pc0 <= 2) && (0 <= self.pc1) && (self.pc1 <= 2) && (!((self.pc0 == 2) && (self.pc1 == 2))) && ((self.pc0 == 2) ==> (self.flag0 == 1)) && ((self.pc1 == 2) ==> (self.flag1 == 1)) && ((self.pc0 == 2) ==> ((self.flag1 == 0) || (self.turn == 0))) && ((self.pc1 == 2) ==> ((self.flag0 == 0) || (self.turn == 1))) && ((self.pc0 == 1) ==> (self.flag0 == 1)) && ((self.pc1 == 1) ==> (self.flag1 == 1)))]
    pub fn enter0(&mut self) {
        self.pc0 = 2;
    }

    #[requires((0 <= self.flag0) && (self.flag0 <= 1) && (0 <= self.flag1) && (self.flag1 <= 1) && (0 <= self.turn) && (self.turn <= 1) && (0 <= self.pc0) && (self.pc0 <= 2) && (0 <= self.pc1) && (self.pc1 <= 2) && (!((self.pc0 == 2) && (self.pc1 == 2))) && ((self.pc0 == 2) ==> (self.flag0 == 1)) && ((self.pc1 == 2) ==> (self.flag1 == 1)) && ((self.pc0 == 2) ==> ((self.flag1 == 0) || (self.turn == 0))) && ((self.pc1 == 2) ==> ((self.flag0 == 0) || (self.turn == 1))) && ((self.pc0 == 1) ==> (self.flag0 == 1)) && ((self.pc1 == 1) ==> (self.flag1 == 1)))]
    #[requires(self.pc0 == 2)]
    #[ensures(self.flag0 == 0 && self.pc0 == 0)]
    #[ensures((0 <= self.flag0) && (self.flag0 <= 1) && (0 <= self.flag1) && (self.flag1 <= 1) && (0 <= self.turn) && (self.turn <= 1) && (0 <= self.pc0) && (self.pc0 <= 2) && (0 <= self.pc1) && (self.pc1 <= 2) && (!((self.pc0 == 2) && (self.pc1 == 2))) && ((self.pc0 == 2) ==> (self.flag0 == 1)) && ((self.pc1 == 2) ==> (self.flag1 == 1)) && ((self.pc0 == 2) ==> ((self.flag1 == 0) || (self.turn == 0))) && ((self.pc1 == 2) ==> ((self.flag0 == 0) || (self.turn == 1))) && ((self.pc0 == 1) ==> (self.flag0 == 1)) && ((self.pc1 == 1) ==> (self.flag1 == 1)))]
    pub fn exit0(&mut self) {
        self.flag0 = 0;
        self.pc0 = 0;
    }

    #[requires((0 <= self.flag0) && (self.flag0 <= 1) && (0 <= self.flag1) && (self.flag1 <= 1) && (0 <= self.turn) && (self.turn <= 1) && (0 <= self.pc0) && (self.pc0 <= 2) && (0 <= self.pc1) && (self.pc1 <= 2) && (!((self.pc0 == 2) && (self.pc1 == 2))) && ((self.pc0 == 2) ==> (self.flag0 == 1)) && ((self.pc1 == 2) ==> (self.flag1 == 1)) && ((self.pc0 == 2) ==> ((self.flag1 == 0) || (self.turn == 0))) && ((self.pc1 == 2) ==> ((self.flag0 == 0) || (self.turn == 1))) && ((self.pc0 == 1) ==> (self.flag0 == 1)) && ((self.pc1 == 1) ==> (self.flag1 == 1)))]
    #[requires(self.pc1 == 0)]
    #[ensures(self.flag1 == 1 && self.turn == 0 && self.pc1 == 1)]
    #[ensures((0 <= self.flag0) && (self.flag0 <= 1) && (0 <= self.flag1) && (self.flag1 <= 1) && (0 <= self.turn) && (self.turn <= 1) && (0 <= self.pc0) && (self.pc0 <= 2) && (0 <= self.pc1) && (self.pc1 <= 2) && (!((self.pc0 == 2) && (self.pc1 == 2))) && ((self.pc0 == 2) ==> (self.flag0 == 1)) && ((self.pc1 == 2) ==> (self.flag1 == 1)) && ((self.pc0 == 2) ==> ((self.flag1 == 0) || (self.turn == 0))) && ((self.pc1 == 2) ==> ((self.flag0 == 0) || (self.turn == 1))) && ((self.pc0 == 1) ==> (self.flag0 == 1)) && ((self.pc1 == 1) ==> (self.flag1 == 1)))]
    pub fn request1(&mut self) {
        self.flag1 = 1;
        self.turn = 0;
        self.pc1 = 1;
    }

    #[requires((0 <= self.flag0) && (self.flag0 <= 1) && (0 <= self.flag1) && (self.flag1 <= 1) && (0 <= self.turn) && (self.turn <= 1) && (0 <= self.pc0) && (self.pc0 <= 2) && (0 <= self.pc1) && (self.pc1 <= 2) && (!((self.pc0 == 2) && (self.pc1 == 2))) && ((self.pc0 == 2) ==> (self.flag0 == 1)) && ((self.pc1 == 2) ==> (self.flag1 == 1)) && ((self.pc0 == 2) ==> ((self.flag1 == 0) || (self.turn == 0))) && ((self.pc1 == 2) ==> ((self.flag0 == 0) || (self.turn == 1))) && ((self.pc0 == 1) ==> (self.flag0 == 1)) && ((self.pc1 == 1) ==> (self.flag1 == 1)))]
    #[requires(self.pc1 == 1)]
    #[requires((self.flag0 == 0) || (self.turn == 1))]
    #[ensures(self.pc1 == 2)]
    #[ensures((0 <= self.flag0) && (self.flag0 <= 1) && (0 <= self.flag1) && (self.flag1 <= 1) && (0 <= self.turn) && (self.turn <= 1) && (0 <= self.pc0) && (self.pc0 <= 2) && (0 <= self.pc1) && (self.pc1 <= 2) && (!((self.pc0 == 2) && (self.pc1 == 2))) && ((self.pc0 == 2) ==> (self.flag0 == 1)) && ((self.pc1 == 2) ==> (self.flag1 == 1)) && ((self.pc0 == 2) ==> ((self.flag1 == 0) || (self.turn == 0))) && ((self.pc1 == 2) ==> ((self.flag0 == 0) || (self.turn == 1))) && ((self.pc0 == 1) ==> (self.flag0 == 1)) && ((self.pc1 == 1) ==> (self.flag1 == 1)))]
    pub fn enter1(&mut self) {
        self.pc1 = 2;
    }

    #[requires((0 <= self.flag0) && (self.flag0 <= 1) && (0 <= self.flag1) && (self.flag1 <= 1) && (0 <= self.turn) && (self.turn <= 1) && (0 <= self.pc0) && (self.pc0 <= 2) && (0 <= self.pc1) && (self.pc1 <= 2) && (!((self.pc0 == 2) && (self.pc1 == 2))) && ((self.pc0 == 2) ==> (self.flag0 == 1)) && ((self.pc1 == 2) ==> (self.flag1 == 1)) && ((self.pc0 == 2) ==> ((self.flag1 == 0) || (self.turn == 0))) && ((self.pc1 == 2) ==> ((self.flag0 == 0) || (self.turn == 1))) && ((self.pc0 == 1) ==> (self.flag0 == 1)) && ((self.pc1 == 1) ==> (self.flag1 == 1)))]
    #[requires(self.pc1 == 2)]
    #[ensures(self.flag1 == 0 && self.pc1 == 0)]
    #[ensures((0 <= self.flag0) && (self.flag0 <= 1) && (0 <= self.flag1) && (self.flag1 <= 1) && (0 <= self.turn) && (self.turn <= 1) && (0 <= self.pc0) && (self.pc0 <= 2) && (0 <= self.pc1) && (self.pc1 <= 2) && (!((self.pc0 == 2) && (self.pc1 == 2))) && ((self.pc0 == 2) ==> (self.flag0 == 1)) && ((self.pc1 == 2) ==> (self.flag1 == 1)) && ((self.pc0 == 2) ==> ((self.flag1 == 0) || (self.turn == 0))) && ((self.pc1 == 2) ==> ((self.flag0 == 0) || (self.turn == 1))) && ((self.pc0 == 1) ==> (self.flag0 == 1)) && ((self.pc1 == 1) ==> (self.flag1 == 1)))]
    pub fn exit1(&mut self) {
        self.flag1 = 0;
        self.pc1 = 0;
    }
}
