use prusti_contracts::*;

pub struct AlternatingBitProtocolWithLossyChannels {
    pub sender_bit: i32,
    pub receiver_bit: i32,
    pub msg_channel: i32,
    pub ack_channel: i32,
}

impl AlternatingBitProtocolWithLossyChannels {
    #[ensures(result.sender_bit == 0 && result.receiver_bit == 0 && result.msg_channel == -1 && result.ack_channel == -1 && (0 <= result.sender_bit) && (result.sender_bit <= 1) && (0 <= result.receiver_bit) && (result.receiver_bit <= 1) && (-1 <= result.msg_channel) && (result.msg_channel <= 1) && (-1 <= result.ack_channel) && (result.ack_channel <= 1) && ((result.msg_channel == result.receiver_bit) ==> (result.sender_bit == result.receiver_bit)) && ((result.ack_channel == result.sender_bit) ==> (result.sender_bit != result.receiver_bit)) && ((result.sender_bit == result.receiver_bit) ==> (result.ack_channel != result.sender_bit)) && ((result.sender_bit != result.receiver_bit) ==> (result.msg_channel != result.receiver_bit)))]
    pub fn new() -> Self {
        Self { sender_bit: 0, receiver_bit: 0, msg_channel: -1, ack_channel: -1 }
    }

    #[pure]
    #[ensures(result == self.sender_bit)]
    pub fn get_sender_bit(&self) -> i32 {
        self.sender_bit
    }

    #[pure]
    #[ensures(result == self.receiver_bit)]
    pub fn get_receiver_bit(&self) -> i32 {
        self.receiver_bit
    }

    #[pure]
    #[ensures(result == self.msg_channel)]
    pub fn get_msg_channel(&self) -> i32 {
        self.msg_channel
    }

    #[pure]
    #[ensures(result == self.ack_channel)]
    pub fn get_ack_channel(&self) -> i32 {
        self.ack_channel
    }

    #[requires((0 <= self.sender_bit) && (self.sender_bit <= 1) && (0 <= self.receiver_bit) && (self.receiver_bit <= 1) && (-1 <= self.msg_channel) && (self.msg_channel <= 1) && (-1 <= self.ack_channel) && (self.ack_channel <= 1) && ((self.msg_channel == self.receiver_bit) ==> (self.sender_bit == self.receiver_bit)) && ((self.ack_channel == self.sender_bit) ==> (self.sender_bit != self.receiver_bit)) && ((self.sender_bit == self.receiver_bit) ==> (self.ack_channel != self.sender_bit)) && ((self.sender_bit != self.receiver_bit) ==> (self.msg_channel != self.receiver_bit)))]
    #[requires(self.msg_channel == -1)]
    #[ensures(self.msg_channel == old(self.sender_bit))]
    #[ensures((0 <= self.sender_bit) && (self.sender_bit <= 1) && (0 <= self.receiver_bit) && (self.receiver_bit <= 1) && (-1 <= self.msg_channel) && (self.msg_channel <= 1) && (-1 <= self.ack_channel) && (self.ack_channel <= 1) && ((self.msg_channel == self.receiver_bit) ==> (self.sender_bit == self.receiver_bit)) && ((self.ack_channel == self.sender_bit) ==> (self.sender_bit != self.receiver_bit)) && ((self.sender_bit == self.receiver_bit) ==> (self.ack_channel != self.sender_bit)) && ((self.sender_bit != self.receiver_bit) ==> (self.msg_channel != self.receiver_bit)))]
    pub fn send_msg(&mut self) {
        let pre_sender_bit = self.sender_bit;
        self.msg_channel = pre_sender_bit;
    }

    #[requires((0 <= self.sender_bit) && (self.sender_bit <= 1) && (0 <= self.receiver_bit) && (self.receiver_bit <= 1) && (-1 <= self.msg_channel) && (self.msg_channel <= 1) && (-1 <= self.ack_channel) && (self.ack_channel <= 1) && ((self.msg_channel == self.receiver_bit) ==> (self.sender_bit == self.receiver_bit)) && ((self.ack_channel == self.sender_bit) ==> (self.sender_bit != self.receiver_bit)) && ((self.sender_bit == self.receiver_bit) ==> (self.ack_channel != self.sender_bit)) && ((self.sender_bit != self.receiver_bit) ==> (self.msg_channel != self.receiver_bit)))]
    #[requires(self.msg_channel != -1)]
    #[ensures(self.msg_channel == -1)]
    #[ensures((0 <= self.sender_bit) && (self.sender_bit <= 1) && (0 <= self.receiver_bit) && (self.receiver_bit <= 1) && (-1 <= self.msg_channel) && (self.msg_channel <= 1) && (-1 <= self.ack_channel) && (self.ack_channel <= 1) && ((self.msg_channel == self.receiver_bit) ==> (self.sender_bit == self.receiver_bit)) && ((self.ack_channel == self.sender_bit) ==> (self.sender_bit != self.receiver_bit)) && ((self.sender_bit == self.receiver_bit) ==> (self.ack_channel != self.sender_bit)) && ((self.sender_bit != self.receiver_bit) ==> (self.msg_channel != self.receiver_bit)))]
    pub fn drop_msg(&mut self) {
        self.msg_channel = -1;
    }

    #[requires((0 <= self.sender_bit) && (self.sender_bit <= 1) && (0 <= self.receiver_bit) && (self.receiver_bit <= 1) && (-1 <= self.msg_channel) && (self.msg_channel <= 1) && (-1 <= self.ack_channel) && (self.ack_channel <= 1) && ((self.msg_channel == self.receiver_bit) ==> (self.sender_bit == self.receiver_bit)) && ((self.ack_channel == self.sender_bit) ==> (self.sender_bit != self.receiver_bit)) && ((self.sender_bit == self.receiver_bit) ==> (self.ack_channel != self.sender_bit)) && ((self.sender_bit != self.receiver_bit) ==> (self.msg_channel != self.receiver_bit)))]
    #[requires((self.msg_channel == self.receiver_bit) && (self.ack_channel == -1))]
    #[ensures(self.ack_channel == old(self.receiver_bit) && self.msg_channel == -1 && self.receiver_bit == 1 - old(self.receiver_bit))]
    #[ensures((0 <= self.sender_bit) && (self.sender_bit <= 1) && (0 <= self.receiver_bit) && (self.receiver_bit <= 1) && (-1 <= self.msg_channel) && (self.msg_channel <= 1) && (-1 <= self.ack_channel) && (self.ack_channel <= 1) && ((self.msg_channel == self.receiver_bit) ==> (self.sender_bit == self.receiver_bit)) && ((self.ack_channel == self.sender_bit) ==> (self.sender_bit != self.receiver_bit)) && ((self.sender_bit == self.receiver_bit) ==> (self.ack_channel != self.sender_bit)) && ((self.sender_bit != self.receiver_bit) ==> (self.msg_channel != self.receiver_bit)))]
    pub fn receive_msg(&mut self) {
        let pre_receiver_bit = self.receiver_bit;
        self.ack_channel = pre_receiver_bit;
        self.msg_channel = -1;
        self.receiver_bit = 1 - pre_receiver_bit;
    }

    #[requires((0 <= self.sender_bit) && (self.sender_bit <= 1) && (0 <= self.receiver_bit) && (self.receiver_bit <= 1) && (-1 <= self.msg_channel) && (self.msg_channel <= 1) && (-1 <= self.ack_channel) && (self.ack_channel <= 1) && ((self.msg_channel == self.receiver_bit) ==> (self.sender_bit == self.receiver_bit)) && ((self.ack_channel == self.sender_bit) ==> (self.sender_bit != self.receiver_bit)) && ((self.sender_bit == self.receiver_bit) ==> (self.ack_channel != self.sender_bit)) && ((self.sender_bit != self.receiver_bit) ==> (self.msg_channel != self.receiver_bit)))]
    #[requires(self.ack_channel != -1)]
    #[ensures(self.ack_channel == -1)]
    #[ensures((0 <= self.sender_bit) && (self.sender_bit <= 1) && (0 <= self.receiver_bit) && (self.receiver_bit <= 1) && (-1 <= self.msg_channel) && (self.msg_channel <= 1) && (-1 <= self.ack_channel) && (self.ack_channel <= 1) && ((self.msg_channel == self.receiver_bit) ==> (self.sender_bit == self.receiver_bit)) && ((self.ack_channel == self.sender_bit) ==> (self.sender_bit != self.receiver_bit)) && ((self.sender_bit == self.receiver_bit) ==> (self.ack_channel != self.sender_bit)) && ((self.sender_bit != self.receiver_bit) ==> (self.msg_channel != self.receiver_bit)))]
    pub fn drop_ack(&mut self) {
        self.ack_channel = -1;
    }

    #[requires((0 <= self.sender_bit) && (self.sender_bit <= 1) && (0 <= self.receiver_bit) && (self.receiver_bit <= 1) && (-1 <= self.msg_channel) && (self.msg_channel <= 1) && (-1 <= self.ack_channel) && (self.ack_channel <= 1) && ((self.msg_channel == self.receiver_bit) ==> (self.sender_bit == self.receiver_bit)) && ((self.ack_channel == self.sender_bit) ==> (self.sender_bit != self.receiver_bit)) && ((self.sender_bit == self.receiver_bit) ==> (self.ack_channel != self.sender_bit)) && ((self.sender_bit != self.receiver_bit) ==> (self.msg_channel != self.receiver_bit)))]
    #[requires(self.ack_channel == self.sender_bit)]
    #[ensures(self.ack_channel == -1 && self.sender_bit == 1 - old(self.sender_bit))]
    #[ensures((0 <= self.sender_bit) && (self.sender_bit <= 1) && (0 <= self.receiver_bit) && (self.receiver_bit <= 1) && (-1 <= self.msg_channel) && (self.msg_channel <= 1) && (-1 <= self.ack_channel) && (self.ack_channel <= 1) && ((self.msg_channel == self.receiver_bit) ==> (self.sender_bit == self.receiver_bit)) && ((self.ack_channel == self.sender_bit) ==> (self.sender_bit != self.receiver_bit)) && ((self.sender_bit == self.receiver_bit) ==> (self.ack_channel != self.sender_bit)) && ((self.sender_bit != self.receiver_bit) ==> (self.msg_channel != self.receiver_bit)))]
    pub fn receive_ack(&mut self) {
        let pre_sender_bit = self.sender_bit;
        self.ack_channel = -1;
        self.sender_bit = 1 - pre_sender_bit;
    }

    #[requires((0 <= self.sender_bit) && (self.sender_bit <= 1) && (0 <= self.receiver_bit) && (self.receiver_bit <= 1) && (-1 <= self.msg_channel) && (self.msg_channel <= 1) && (-1 <= self.ack_channel) && (self.ack_channel <= 1) && ((self.msg_channel == self.receiver_bit) ==> (self.sender_bit == self.receiver_bit)) && ((self.ack_channel == self.sender_bit) ==> (self.sender_bit != self.receiver_bit)) && ((self.sender_bit == self.receiver_bit) ==> (self.ack_channel != self.sender_bit)) && ((self.sender_bit != self.receiver_bit) ==> (self.msg_channel != self.receiver_bit)))]
    #[requires(((self.msg_channel != -1) && (self.msg_channel != self.receiver_bit)) && (self.ack_channel == -1))]
    #[ensures(self.ack_channel == old(self.msg_channel) && self.msg_channel == -1)]
    #[ensures((0 <= self.sender_bit) && (self.sender_bit <= 1) && (0 <= self.receiver_bit) && (self.receiver_bit <= 1) && (-1 <= self.msg_channel) && (self.msg_channel <= 1) && (-1 <= self.ack_channel) && (self.ack_channel <= 1) && ((self.msg_channel == self.receiver_bit) ==> (self.sender_bit == self.receiver_bit)) && ((self.ack_channel == self.sender_bit) ==> (self.sender_bit != self.receiver_bit)) && ((self.sender_bit == self.receiver_bit) ==> (self.ack_channel != self.sender_bit)) && ((self.sender_bit != self.receiver_bit) ==> (self.msg_channel != self.receiver_bit)))]
    pub fn resend_ack(&mut self) {
        let pre_msg_channel = self.msg_channel;
        self.ack_channel = pre_msg_channel;
        self.msg_channel = -1;
    }
}
