use prusti_contracts::*;

pub struct VfsBounded {
    pub inode_count: i32,
    pub free_list_head: i32,
    pub open_handle_count: i32,
    pub cached_bytes: i32,
    pub slots: [bool; 4],
}

impl VfsBounded {
    #[ensures(result.inode_count == 0 && result.free_list_head == 4 && result.open_handle_count == 0 && result.cached_bytes == 0 && (0 <= result.inode_count) && (result.inode_count <= 4) && (0 <= result.free_list_head) && (result.free_list_head <= 4) && (0 <= result.open_handle_count) && (result.open_handle_count <= 4) && (0 <= result.cached_bytes) && (result.cached_bytes <= 16) && ((result.inode_count + result.free_list_head) == 4) && (result.open_handle_count <= result.inode_count))]
    pub fn new() -> Self {
        Self {
            inode_count: 0,
            free_list_head: 4,
            open_handle_count: 0,
            cached_bytes: 0,
            slots: [false; 4],
        }
    }

    #[pure]
    #[ensures(result == self.inode_count)]
    pub fn get_inode_count(&self) -> i32 {
        self.inode_count
    }

    #[pure]
    #[ensures(result == self.free_list_head)]
    pub fn get_free_list_head(&self) -> i32 {
        self.free_list_head
    }

    #[pure]
    #[ensures(result == self.open_handle_count)]
    pub fn get_open_handle_count(&self) -> i32 {
        self.open_handle_count
    }

    #[pure]
    #[ensures(result == self.cached_bytes)]
    pub fn get_cached_bytes(&self) -> i32 {
        self.cached_bytes
    }

    #[requires((0 <= self.inode_count) && (self.inode_count <= 4) && (0 <= self.free_list_head) && (self.free_list_head <= 4) && (0 <= self.open_handle_count) && (self.open_handle_count <= 4) && (0 <= self.cached_bytes) && (self.cached_bytes <= 16) && ((self.inode_count + self.free_list_head) == 4) && (self.open_handle_count <= self.inode_count))]
    #[ensures(result == (old(self.inode_count) < 4 && old(self.free_list_head) > 0))]
    #[ensures(result ==> (self.inode_count == old(self.inode_count) + 1 && self.free_list_head == old(self.free_list_head) - 1 && self.open_handle_count == old(self.open_handle_count) + 1))]
    #[ensures(!result ==> (self.inode_count == old(self.inode_count) && self.free_list_head == old(self.free_list_head) && self.open_handle_count == old(self.open_handle_count) && self.cached_bytes == old(self.cached_bytes)))]
    #[ensures((0 <= self.inode_count) && (self.inode_count <= 4) && (0 <= self.free_list_head) && (self.free_list_head <= 4) && (0 <= self.open_handle_count) && (self.open_handle_count <= 4) && (0 <= self.cached_bytes) && (self.cached_bytes <= 16) && ((self.inode_count + self.free_list_head) == 4) && (self.open_handle_count <= self.inode_count))]
    pub fn open(&mut self) -> bool {
        let pre_free_list_head = self.free_list_head;
        let pre_inode_count = self.inode_count;
        let pre_open_handle_count = self.open_handle_count;
        if !(self.inode_count < 4 && self.free_list_head > 0) {
            return false;
        }
        self.inode_count = pre_inode_count + 1;
        self.free_list_head = pre_free_list_head - 1;
        self.open_handle_count = pre_open_handle_count + 1;
        self.slots[pre_inode_count as usize] = true;
        true
    }

    #[requires((0 <= self.inode_count) && (self.inode_count <= 4) && (0 <= self.free_list_head) && (self.free_list_head <= 4) && (0 <= self.open_handle_count) && (self.open_handle_count <= 4) && (0 <= self.cached_bytes) && (self.cached_bytes <= 16) && ((self.inode_count + self.free_list_head) == 4) && (self.open_handle_count <= self.inode_count))]
    #[ensures(result == (old(self.open_handle_count) > 0))]
    #[ensures(result ==> (self.open_handle_count == old(self.open_handle_count) - 1 && self.inode_count == old(self.inode_count) - 1 && self.free_list_head == old(self.free_list_head) + 1))]
    #[ensures(!result ==> (self.inode_count == old(self.inode_count) && self.free_list_head == old(self.free_list_head) && self.open_handle_count == old(self.open_handle_count) && self.cached_bytes == old(self.cached_bytes)))]
    #[ensures((0 <= self.inode_count) && (self.inode_count <= 4) && (0 <= self.free_list_head) && (self.free_list_head <= 4) && (0 <= self.open_handle_count) && (self.open_handle_count <= 4) && (0 <= self.cached_bytes) && (self.cached_bytes <= 16) && ((self.inode_count + self.free_list_head) == 4) && (self.open_handle_count <= self.inode_count))]
    pub fn close(&mut self) -> bool {
        let pre_free_list_head = self.free_list_head;
        let pre_inode_count = self.inode_count;
        let pre_open_handle_count = self.open_handle_count;
        if !(self.open_handle_count > 0) {
            return false;
        }
        self.open_handle_count = pre_open_handle_count - 1;
        self.inode_count = pre_inode_count - 1;
        self.free_list_head = pre_free_list_head + 1;
        self.slots[(pre_inode_count - 1) as usize] = false;
        true
    }

    #[requires((0 <= self.inode_count) && (self.inode_count <= 4) && (0 <= self.free_list_head) && (self.free_list_head <= 4) && (0 <= self.open_handle_count) && (self.open_handle_count <= 4) && (0 <= self.cached_bytes) && (self.cached_bytes <= 16) && ((self.inode_count + self.free_list_head) == 4) && (self.open_handle_count <= self.inode_count))]
    #[ensures(result == (old(self.open_handle_count) > 0))]
    #[ensures(result ==> (true))]
    #[ensures(!result ==> (self.inode_count == old(self.inode_count) && self.free_list_head == old(self.free_list_head) && self.open_handle_count == old(self.open_handle_count) && self.cached_bytes == old(self.cached_bytes)))]
    #[ensures((0 <= self.inode_count) && (self.inode_count <= 4) && (0 <= self.free_list_head) && (self.free_list_head <= 4) && (0 <= self.open_handle_count) && (self.open_handle_count <= 4) && (0 <= self.cached_bytes) && (self.cached_bytes <= 16) && ((self.inode_count + self.free_list_head) == 4) && (self.open_handle_count <= self.inode_count))]
    pub fn read(&mut self) -> bool {
        if !(self.open_handle_count > 0) {
            return false;
        }
        true
    }

    #[requires((0 <= self.inode_count) && (self.inode_count <= 4) && (0 <= self.free_list_head) && (self.free_list_head <= 4) && (0 <= self.open_handle_count) && (self.open_handle_count <= 4) && (0 <= self.cached_bytes) && (self.cached_bytes <= 16) && ((self.inode_count + self.free_list_head) == 4) && (self.open_handle_count <= self.inode_count))]
    #[ensures(result == (old(self.open_handle_count) > 0 && old(self.cached_bytes) < 16))]
    #[ensures(result ==> (self.cached_bytes == old(self.cached_bytes) + 1))]
    #[ensures(!result ==> (self.inode_count == old(self.inode_count) && self.free_list_head == old(self.free_list_head) && self.open_handle_count == old(self.open_handle_count) && self.cached_bytes == old(self.cached_bytes)))]
    #[ensures((0 <= self.inode_count) && (self.inode_count <= 4) && (0 <= self.free_list_head) && (self.free_list_head <= 4) && (0 <= self.open_handle_count) && (self.open_handle_count <= 4) && (0 <= self.cached_bytes) && (self.cached_bytes <= 16) && ((self.inode_count + self.free_list_head) == 4) && (self.open_handle_count <= self.inode_count))]
    pub fn write(&mut self) -> bool {
        let pre_cached_bytes = self.cached_bytes;
        if !(self.open_handle_count > 0 && self.cached_bytes < 16) {
            return false;
        }
        self.cached_bytes = pre_cached_bytes + 1;
        true
    }
}
