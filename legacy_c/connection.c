/*
 * Legacy bounded TCP connection state machine (representative of the
 * CWE-125/416/476-prone C found in protocol handlers). The Rosetta-Stone
 * lane extracts this bounded machine, promotes its math after human review,
 * and lowers a Prusti-verified Rust port.
 */
struct Connection {
    int conn_state;
};

enum { CONN_CLOSED = 0, CONN_LISTEN = 1, CONN_ESTABLISHED = 2 };

int connection_state_valid(struct Connection *c) {
    return c->conn_state <= 2;
}

void connection_open(struct Connection *c) {
    if (c->conn_state == 0) {
        c->conn_state = 1;
    }
}

void connection_establish(struct Connection *c) {
    if (c->conn_state == 1) {
        c->conn_state = 2;
    }
}

void connection_close(struct Connection *c) {
    if (c->conn_state != 0) {
        c->conn_state = 0;
    }
}
