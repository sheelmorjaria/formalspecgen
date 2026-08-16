/*
 * lwIP-style bounded TCP connection state tracker (the shape real stacks
 * use: enum constants + switch dispatch on the pcb state field). The
 * Rosetta-Stone lane resolves the enum, segments the switch, and lowers a
 * Prusti-verified Rust port of the same machine.
 */
#include <stdint.h>

enum tcp_state {
  CLOSED = 0,
  SYN_SENT,
  ESTABLISHED,
  FIN_WAIT_1,
  LAST_ACK
};

struct tcp_pcb {
  enum tcp_state state;
};

void tcp_connect(struct tcp_pcb *pcb) {
    if (pcb->state == CLOSED) {
        pcb->state = SYN_SENT;
    }
}

void tcp_process(struct tcp_pcb *pcb, uint8_t flags) {
    switch (pcb->state) {
        case SYN_SENT:
            if (flags == 0x10) { /* ACK */
                pcb->state = ESTABLISHED;
            }
            break;
        case ESTABLISHED:
            if (flags == 0x01) { /* FIN */
                pcb->state = FIN_WAIT_1;
            }
            break;
        case FIN_WAIT_1:
            pcb->state = LAST_ACK;
            break;
        case LAST_ACK:
            pcb->state = CLOSED;
            break;
        default:
            break;
    }
}
