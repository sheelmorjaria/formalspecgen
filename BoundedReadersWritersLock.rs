use prusti_contracts::*;

pub struct BoundedReadersWritersLock {
    pub read_count: i32,
    pub writer_active: bool,
}

impl BoundedReadersWritersLock {
    #[ensures(result.read_count == 0 && result.writer_active == false && (0 <= result.read_count) && (result.read_count <= 2) && (!(result.writer_active && (result.read_count > 0))))]
    pub fn new() -> Self {
        Self { read_count: 0, writer_active: false }
    }

    #[pure]
    #[ensures(result == self.read_count)]
    pub fn get_read_count(&self) -> i32 {
        self.read_count
    }

    #[pure]
    #[ensures(result == self.writer_active)]
    pub fn get_writer_active(&self) -> bool {
        self.writer_active
    }

    #[requires((0 <= self.read_count) && (self.read_count <= 2) && (!(self.writer_active && (self.read_count > 0))))]
    #[requires(!(self.writer_active))]
    #[requires(self.read_count < 2)]
    #[ensures(self.read_count == old(self.read_count) + 1)]
    #[ensures((0 <= self.read_count) && (self.read_count <= 2) && (!(self.writer_active && (self.read_count > 0))))]
    pub fn reader_enter(&mut self) {
        let pre_read_count = self.read_count;
        self.read_count = pre_read_count + 1;
    }

    #[requires((0 <= self.read_count) && (self.read_count <= 2) && (!(self.writer_active && (self.read_count > 0))))]
    #[requires(self.read_count > 0)]
    #[ensures(self.read_count == old(self.read_count) - 1)]
    #[ensures((0 <= self.read_count) && (self.read_count <= 2) && (!(self.writer_active && (self.read_count > 0))))]
    pub fn reader_exit(&mut self) {
        let pre_read_count = self.read_count;
        self.read_count = pre_read_count - 1;
    }

    #[requires((0 <= self.read_count) && (self.read_count <= 2) && (!(self.writer_active && (self.read_count > 0))))]
    #[requires(!(self.writer_active))]
    #[requires(self.read_count == 0)]
    #[ensures(self.writer_active == true)]
    #[ensures((0 <= self.read_count) && (self.read_count <= 2) && (!(self.writer_active && (self.read_count > 0))))]
    pub fn writer_enter(&mut self) {
        self.writer_active = true;
    }

    #[requires((0 <= self.read_count) && (self.read_count <= 2) && (!(self.writer_active && (self.read_count > 0))))]
    #[requires(self.writer_active)]
    #[ensures(self.writer_active == false)]
    #[ensures((0 <= self.read_count) && (self.read_count <= 2) && (!(self.writer_active && (self.read_count > 0))))]
    pub fn writer_exit(&mut self) {
        self.writer_active = false;
    }
}
