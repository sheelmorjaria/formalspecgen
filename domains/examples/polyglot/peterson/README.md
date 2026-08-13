# Peterson mutual-exclusion evaluation

This benchmark represents Peterson's two-process protocol as six atomic V2
transitions over scalar state. `pc0` and `pc1` encode `IDLE = 0`, `WAITING = 1`,
and `CRITICAL = 2`. It is an abstract sequential transition system, not a proof
of a concrete weak-memory or lock-free implementation.

## Results

- TLC 2.19: `VALIDATED`, 10 reachable states and 16 reachable transitions from
  a state-space upper bound of 72.
- Prusti 0.2.2: `VERIFIED`, 12/12 items.
- Frama-C WP 33.0 with Z3 4.8.12: `VERIFIED`, 87/87 goals. The standard
  unaligned-pointer and indirect-function-call RTE caveats remain; neither
  feature occurs in this artifact.
- Rust refinement: 6/6 operations, certificate
  `756ec9f6fcbfc10fc16e7d4ef92eafaba50148918ce9193d48deef684da1eade`.
- C refinement: 6/6 operations, certificate
  `7cd2bbaffdb91fbd2c9d08e2089275c451dfbf64323c2e362a0fc58b03c4b4d1`.

## Reference comparison

The reviewed transitions preserve the textbook protocol:

- process 0 requests by setting `flag0 = 1` and yielding `turn = 1`;
- process 0 enters only when `flag1 = 0 || turn = 0`;
- process 0 exits by clearing `flag0`;
- process 1 is the symmetric case.

The explicit program counters split the textbook busy-wait loop into atomic
`request`, enabled `enter`, and `exit` transitions. They make critical-section
occupancy observable for the mutual-exclusion invariant.

The evaluation also found that the reachable-state invariant needed four
auxiliary inductive facts for modular native proof: waiting implies the process's
flag is raised, and critical occupancy implies the corresponding entry condition
still holds. TLC accepted each weaker invariant set over reachable states, while
Prusti rejected the under-strengthened method contracts.

## Artifacts

- Candidate: `domains/candidates/peterson.v2.yaml`
- Validation evidence: `domains/candidates/peterson.v2.validation.json`
- Reviewed model: `domains/v2/peterson.json`
- Generated sources: `Peterson.java`, `Peterson.rs`, and `peterson.c`
