/* M59 extraction fixture: bounded mbedTLS-style handshake control flow.
 * Cryptographic calls are opaque external outcomes, never proof claims. */
enum tls_state {
    TLS_CLIENT_HELLO,
    TLS_KEY_EXCHANGE,
    TLS_FINISHED,
    TLS_ESTABLISHED,
    TLS_FAILED
};

enum tls_state tls_step(enum tls_state state, int external_ok) {
    switch (state) {
    case TLS_CLIENT_HELLO:
        return external_ok ? TLS_KEY_EXCHANGE : TLS_FAILED;
    case TLS_KEY_EXCHANGE:
        return external_ok ? TLS_FINISHED : TLS_FAILED;
    case TLS_FINISHED:
        return external_ok ? TLS_ESTABLISHED : TLS_FAILED;
    case TLS_ESTABLISHED:
        return TLS_ESTABLISHED;
    case TLS_FAILED:
        return TLS_FAILED;
    }
    return TLS_FAILED;
}
