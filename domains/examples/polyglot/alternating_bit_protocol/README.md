# Alternating Bit Protocol evaluation

This benchmark was generated through `formalspecgen domain` using Ollama; its
V2 YAML was not manually authored. It scalar-expands an unreliable network into
one data channel and one acknowledgement channel, each holding `-1` (empty),
`0`, or `1`.

## Accepted model

- Integer state: `sender_bit` and `receiver_bit` in 0..1;
  `msg_channel` and `ack_channel` in -1..1.
- Operations: `send_msg`, `drop_msg`, `receive_msg`, `drop_ack`,
  `receive_ack`, and `resend_ack`.
- Loss is environmental nondeterminism represented by the two drop actions.
- Four phase-consistency invariants distinguish current data, accepted data,
  matching acknowledgements, and stale retransmissions.

## Results

- TLC 2.19: `VALIDATED`, 18 reachable states and 36 reachable transitions from
  a state-space upper bound of 36.
- Prusti 0.2.2: `VERIFIED`, 11/11 items.
- Frama-C WP 33.0 with Z3 4.8.12: `VERIFIED`, 82/82 goals: 36 Qed, 24 Z3,
  11 terminating, and 11 unreachable. The standard unaligned-pointer and
  indirect-function-call RTE caveats remain; neither feature is used here.
- Rust refinement: 6/6 operations proved.
- C refinement: 6/6 operations proved.

## Boundary findings

The evaluation exposed four deterministic compiler boundaries that are now
unit-pinned:

- unary negative integer literals such as `-1` lower into V2 integer nodes;
- compact-manifest frames are derived from the ordered effect-map targets;
- mixed Boolean/integer expressions and incorrectly typed effects fail schema
  validation;
- the TLA+ renderer imports `Integers` only when negative values occur, keeping
  positive-only canonical hashes stable.

## Assurance scope

This proves bounded safety under arbitrary loss transitions and atomic
source/model refinement for the generated Rust and C implementations. It does
not establish eventual delivery, fairness, asynchronous network-code
refinement, concurrent linearizability, or correctness under a concrete network
or hardware memory model. No Java ABP proof was run in this evaluation.

## Artifacts

- Candidate:
  `domains/candidates/alternating_bit_protocol_with_lossy_channels.v2.yaml`
- Validation evidence:
  `domains/candidates/alternating_bit_protocol_with_lossy_channels.v2.validation.json`
- Reviewed model:
  `domains/v2/alternating_bit_protocol_with_lossy_channels.json`
- Generated sources: `AlternatingBitProtocol.rs` and
  `alternating_bit_protocol.c`
