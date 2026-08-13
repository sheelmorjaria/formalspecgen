/* Deterministic contract lowered from the reviewed V2 domain 'alternating_bit_protocol_with_lossy_channels'.
 * Human review of the reviewed artifact is required before trust. */

typedef struct {
    int sender_bit;
    int receiver_bit;
    int msg_channel;
    int ack_channel;
} alternating_bit_protocol_with_lossy_channels;

/*@
  requires \valid(counter);
  assigns counter->sender_bit, counter->receiver_bit, counter->msg_channel, counter->ack_channel;
  ensures counter->sender_bit == 0 && counter->receiver_bit == 0 && counter->msg_channel == -1 && counter->ack_channel == -1;
  ensures (0 <= counter->sender_bit) && (counter->sender_bit <= 1) && (0 <= counter->receiver_bit) && (counter->receiver_bit <= 1) && (-1 <= counter->msg_channel) && (counter->msg_channel <= 1) && (-1 <= counter->ack_channel) && (counter->ack_channel <= 1) && ((counter->msg_channel == counter->receiver_bit) ==> (counter->sender_bit == counter->receiver_bit)) && ((counter->ack_channel == counter->sender_bit) ==> (counter->sender_bit != counter->receiver_bit)) && ((counter->sender_bit == counter->receiver_bit) ==> (counter->ack_channel != counter->sender_bit)) && ((counter->sender_bit != counter->receiver_bit) ==> (counter->msg_channel != counter->receiver_bit));
*/
void alternating_bit_protocol_with_lossy_channels_init(alternating_bit_protocol_with_lossy_channels *counter) {
    counter->sender_bit = 0;
    counter->receiver_bit = 0;
    counter->msg_channel = -1;
    counter->ack_channel = -1;
}

/*@
  requires \valid_read(counter);
  assigns \nothing;
  ensures \result == counter->sender_bit;
*/
int alternating_bit_protocol_with_lossy_channels_get_sender_bit(const alternating_bit_protocol_with_lossy_channels *counter) {
    return counter->sender_bit;
}

/*@
  requires \valid_read(counter);
  assigns \nothing;
  ensures \result == counter->receiver_bit;
*/
int alternating_bit_protocol_with_lossy_channels_get_receiver_bit(const alternating_bit_protocol_with_lossy_channels *counter) {
    return counter->receiver_bit;
}

/*@
  requires \valid_read(counter);
  assigns \nothing;
  ensures \result == counter->msg_channel;
*/
int alternating_bit_protocol_with_lossy_channels_get_msg_channel(const alternating_bit_protocol_with_lossy_channels *counter) {
    return counter->msg_channel;
}

/*@
  requires \valid_read(counter);
  assigns \nothing;
  ensures \result == counter->ack_channel;
*/
int alternating_bit_protocol_with_lossy_channels_get_ack_channel(const alternating_bit_protocol_with_lossy_channels *counter) {
    return counter->ack_channel;
}

/*@
  requires \valid(counter);
  requires (0 <= counter->sender_bit) && (counter->sender_bit <= 1) && (0 <= counter->receiver_bit) && (counter->receiver_bit <= 1) && (-1 <= counter->msg_channel) && (counter->msg_channel <= 1) && (-1 <= counter->ack_channel) && (counter->ack_channel <= 1) && ((counter->msg_channel == counter->receiver_bit) ==> (counter->sender_bit == counter->receiver_bit)) && ((counter->ack_channel == counter->sender_bit) ==> (counter->sender_bit != counter->receiver_bit)) && ((counter->sender_bit == counter->receiver_bit) ==> (counter->ack_channel != counter->sender_bit)) && ((counter->sender_bit != counter->receiver_bit) ==> (counter->msg_channel != counter->receiver_bit));
  requires counter->msg_channel == -1;
  assigns counter->msg_channel;
  ensures counter->msg_channel == \old(counter->sender_bit);
  ensures (0 <= counter->sender_bit) && (counter->sender_bit <= 1) && (0 <= counter->receiver_bit) && (counter->receiver_bit <= 1) && (-1 <= counter->msg_channel) && (counter->msg_channel <= 1) && (-1 <= counter->ack_channel) && (counter->ack_channel <= 1) && ((counter->msg_channel == counter->receiver_bit) ==> (counter->sender_bit == counter->receiver_bit)) && ((counter->ack_channel == counter->sender_bit) ==> (counter->sender_bit != counter->receiver_bit)) && ((counter->sender_bit == counter->receiver_bit) ==> (counter->ack_channel != counter->sender_bit)) && ((counter->sender_bit != counter->receiver_bit) ==> (counter->msg_channel != counter->receiver_bit));
*/
void alternating_bit_protocol_with_lossy_channels_send_msg(alternating_bit_protocol_with_lossy_channels *counter) {
    int pre_sender_bit = counter->sender_bit;
    counter->msg_channel = pre_sender_bit;
}

/*@
  requires \valid(counter);
  requires (0 <= counter->sender_bit) && (counter->sender_bit <= 1) && (0 <= counter->receiver_bit) && (counter->receiver_bit <= 1) && (-1 <= counter->msg_channel) && (counter->msg_channel <= 1) && (-1 <= counter->ack_channel) && (counter->ack_channel <= 1) && ((counter->msg_channel == counter->receiver_bit) ==> (counter->sender_bit == counter->receiver_bit)) && ((counter->ack_channel == counter->sender_bit) ==> (counter->sender_bit != counter->receiver_bit)) && ((counter->sender_bit == counter->receiver_bit) ==> (counter->ack_channel != counter->sender_bit)) && ((counter->sender_bit != counter->receiver_bit) ==> (counter->msg_channel != counter->receiver_bit));
  requires counter->msg_channel != -1;
  assigns counter->msg_channel;
  ensures counter->msg_channel == -1;
  ensures (0 <= counter->sender_bit) && (counter->sender_bit <= 1) && (0 <= counter->receiver_bit) && (counter->receiver_bit <= 1) && (-1 <= counter->msg_channel) && (counter->msg_channel <= 1) && (-1 <= counter->ack_channel) && (counter->ack_channel <= 1) && ((counter->msg_channel == counter->receiver_bit) ==> (counter->sender_bit == counter->receiver_bit)) && ((counter->ack_channel == counter->sender_bit) ==> (counter->sender_bit != counter->receiver_bit)) && ((counter->sender_bit == counter->receiver_bit) ==> (counter->ack_channel != counter->sender_bit)) && ((counter->sender_bit != counter->receiver_bit) ==> (counter->msg_channel != counter->receiver_bit));
*/
void alternating_bit_protocol_with_lossy_channels_drop_msg(alternating_bit_protocol_with_lossy_channels *counter) {
    counter->msg_channel = -1;
}

/*@
  requires \valid(counter);
  requires (0 <= counter->sender_bit) && (counter->sender_bit <= 1) && (0 <= counter->receiver_bit) && (counter->receiver_bit <= 1) && (-1 <= counter->msg_channel) && (counter->msg_channel <= 1) && (-1 <= counter->ack_channel) && (counter->ack_channel <= 1) && ((counter->msg_channel == counter->receiver_bit) ==> (counter->sender_bit == counter->receiver_bit)) && ((counter->ack_channel == counter->sender_bit) ==> (counter->sender_bit != counter->receiver_bit)) && ((counter->sender_bit == counter->receiver_bit) ==> (counter->ack_channel != counter->sender_bit)) && ((counter->sender_bit != counter->receiver_bit) ==> (counter->msg_channel != counter->receiver_bit));
  requires (counter->msg_channel == counter->receiver_bit) && (counter->ack_channel == -1);
  assigns counter->ack_channel, counter->msg_channel, counter->receiver_bit;
  ensures counter->ack_channel == \old(counter->receiver_bit) && counter->msg_channel == -1 && counter->receiver_bit == 1 - \old(counter->receiver_bit);
  ensures (0 <= counter->sender_bit) && (counter->sender_bit <= 1) && (0 <= counter->receiver_bit) && (counter->receiver_bit <= 1) && (-1 <= counter->msg_channel) && (counter->msg_channel <= 1) && (-1 <= counter->ack_channel) && (counter->ack_channel <= 1) && ((counter->msg_channel == counter->receiver_bit) ==> (counter->sender_bit == counter->receiver_bit)) && ((counter->ack_channel == counter->sender_bit) ==> (counter->sender_bit != counter->receiver_bit)) && ((counter->sender_bit == counter->receiver_bit) ==> (counter->ack_channel != counter->sender_bit)) && ((counter->sender_bit != counter->receiver_bit) ==> (counter->msg_channel != counter->receiver_bit));
*/
void alternating_bit_protocol_with_lossy_channels_receive_msg(alternating_bit_protocol_with_lossy_channels *counter) {
    int pre_receiver_bit = counter->receiver_bit;
    counter->ack_channel = pre_receiver_bit;
    counter->msg_channel = -1;
    counter->receiver_bit = 1 - pre_receiver_bit;
}

/*@
  requires \valid(counter);
  requires (0 <= counter->sender_bit) && (counter->sender_bit <= 1) && (0 <= counter->receiver_bit) && (counter->receiver_bit <= 1) && (-1 <= counter->msg_channel) && (counter->msg_channel <= 1) && (-1 <= counter->ack_channel) && (counter->ack_channel <= 1) && ((counter->msg_channel == counter->receiver_bit) ==> (counter->sender_bit == counter->receiver_bit)) && ((counter->ack_channel == counter->sender_bit) ==> (counter->sender_bit != counter->receiver_bit)) && ((counter->sender_bit == counter->receiver_bit) ==> (counter->ack_channel != counter->sender_bit)) && ((counter->sender_bit != counter->receiver_bit) ==> (counter->msg_channel != counter->receiver_bit));
  requires counter->ack_channel != -1;
  assigns counter->ack_channel;
  ensures counter->ack_channel == -1;
  ensures (0 <= counter->sender_bit) && (counter->sender_bit <= 1) && (0 <= counter->receiver_bit) && (counter->receiver_bit <= 1) && (-1 <= counter->msg_channel) && (counter->msg_channel <= 1) && (-1 <= counter->ack_channel) && (counter->ack_channel <= 1) && ((counter->msg_channel == counter->receiver_bit) ==> (counter->sender_bit == counter->receiver_bit)) && ((counter->ack_channel == counter->sender_bit) ==> (counter->sender_bit != counter->receiver_bit)) && ((counter->sender_bit == counter->receiver_bit) ==> (counter->ack_channel != counter->sender_bit)) && ((counter->sender_bit != counter->receiver_bit) ==> (counter->msg_channel != counter->receiver_bit));
*/
void alternating_bit_protocol_with_lossy_channels_drop_ack(alternating_bit_protocol_with_lossy_channels *counter) {
    counter->ack_channel = -1;
}

/*@
  requires \valid(counter);
  requires (0 <= counter->sender_bit) && (counter->sender_bit <= 1) && (0 <= counter->receiver_bit) && (counter->receiver_bit <= 1) && (-1 <= counter->msg_channel) && (counter->msg_channel <= 1) && (-1 <= counter->ack_channel) && (counter->ack_channel <= 1) && ((counter->msg_channel == counter->receiver_bit) ==> (counter->sender_bit == counter->receiver_bit)) && ((counter->ack_channel == counter->sender_bit) ==> (counter->sender_bit != counter->receiver_bit)) && ((counter->sender_bit == counter->receiver_bit) ==> (counter->ack_channel != counter->sender_bit)) && ((counter->sender_bit != counter->receiver_bit) ==> (counter->msg_channel != counter->receiver_bit));
  requires counter->ack_channel == counter->sender_bit;
  assigns counter->ack_channel, counter->sender_bit;
  ensures counter->ack_channel == -1 && counter->sender_bit == 1 - \old(counter->sender_bit);
  ensures (0 <= counter->sender_bit) && (counter->sender_bit <= 1) && (0 <= counter->receiver_bit) && (counter->receiver_bit <= 1) && (-1 <= counter->msg_channel) && (counter->msg_channel <= 1) && (-1 <= counter->ack_channel) && (counter->ack_channel <= 1) && ((counter->msg_channel == counter->receiver_bit) ==> (counter->sender_bit == counter->receiver_bit)) && ((counter->ack_channel == counter->sender_bit) ==> (counter->sender_bit != counter->receiver_bit)) && ((counter->sender_bit == counter->receiver_bit) ==> (counter->ack_channel != counter->sender_bit)) && ((counter->sender_bit != counter->receiver_bit) ==> (counter->msg_channel != counter->receiver_bit));
*/
void alternating_bit_protocol_with_lossy_channels_receive_ack(alternating_bit_protocol_with_lossy_channels *counter) {
    int pre_sender_bit = counter->sender_bit;
    counter->ack_channel = -1;
    counter->sender_bit = 1 - pre_sender_bit;
}

/*@
  requires \valid(counter);
  requires (0 <= counter->sender_bit) && (counter->sender_bit <= 1) && (0 <= counter->receiver_bit) && (counter->receiver_bit <= 1) && (-1 <= counter->msg_channel) && (counter->msg_channel <= 1) && (-1 <= counter->ack_channel) && (counter->ack_channel <= 1) && ((counter->msg_channel == counter->receiver_bit) ==> (counter->sender_bit == counter->receiver_bit)) && ((counter->ack_channel == counter->sender_bit) ==> (counter->sender_bit != counter->receiver_bit)) && ((counter->sender_bit == counter->receiver_bit) ==> (counter->ack_channel != counter->sender_bit)) && ((counter->sender_bit != counter->receiver_bit) ==> (counter->msg_channel != counter->receiver_bit));
  requires ((counter->msg_channel != -1) && (counter->msg_channel != counter->receiver_bit)) && (counter->ack_channel == -1);
  assigns counter->ack_channel, counter->msg_channel;
  ensures counter->ack_channel == \old(counter->msg_channel) && counter->msg_channel == -1;
  ensures (0 <= counter->sender_bit) && (counter->sender_bit <= 1) && (0 <= counter->receiver_bit) && (counter->receiver_bit <= 1) && (-1 <= counter->msg_channel) && (counter->msg_channel <= 1) && (-1 <= counter->ack_channel) && (counter->ack_channel <= 1) && ((counter->msg_channel == counter->receiver_bit) ==> (counter->sender_bit == counter->receiver_bit)) && ((counter->ack_channel == counter->sender_bit) ==> (counter->sender_bit != counter->receiver_bit)) && ((counter->sender_bit == counter->receiver_bit) ==> (counter->ack_channel != counter->sender_bit)) && ((counter->sender_bit != counter->receiver_bit) ==> (counter->msg_channel != counter->receiver_bit));
*/
void alternating_bit_protocol_with_lossy_channels_resend_ack(alternating_bit_protocol_with_lossy_channels *counter) {
    int pre_msg_channel = counter->msg_channel;
    counter->ack_channel = pre_msg_channel;
    counter->msg_channel = -1;
}
