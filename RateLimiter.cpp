#include <cassert>

class RateLimiter {
private:
    int tokens;

    void check_invariants() const {
        assert((0 <= tokens) && (tokens <= 5));
    }

public:
    RateLimiter() : tokens(5) {
        check_invariants();
    }

    void handle_request() {
        assert((tokens > 0));
        const int pre_tokens = tokens;
        tokens = (pre_tokens - 1);
        check_invariants();
    }

    void refill() {
        assert((tokens < 5));
        tokens = 5;
        check_invariants();
    }
};
