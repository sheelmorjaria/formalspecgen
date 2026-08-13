# Bounded Readers-Writers evaluation

This benchmark was generated through `formalspecgen domain`; its V2 YAML was
not manually authored. The accepted abstraction records three actors (two
readers and one writer) while intentionally aggregating reader identity into
`read_count`.

## Generator evaluation

The initial Ollama generation failed schema validation after emitting singular
`tlc_invariant`/`invariant` keys. A saved-clarification retry produced a valid
candidate, but incorrectly recorded `actors: 1`; that candidate was validated
but not promoted. A second explicit GLM elicitation produced the accepted
three-actor candidate. This demonstrates that schema and human-review gates
prevent syntactically invalid or semantically mismatched model output from
entering the trusted path.

## Accepted model and results

- Actors: 3, represented by aggregate scalar state.
- State: `read_count` in 0..2 and Boolean `writer_active`.
- Operations: `reader_enter`, `reader_exit`, `writer_enter`, `writer_exit`.
- Safety: a writer and any reader are never active together.
- TLC: `VALIDATED`, 4 reachable states and 6 transitions from an upper bound
  of 6.
- Prusti 0.2.2: `VERIFIED`, 7/7 items.
- Frama-C WP 33.0 with Z3 4.8.12: `VERIFIED`, 47/47 goals. The usual
  unaligned-pointer and indirect-function-call RTE caveats remain; neither
  feature is used here.
- Rust refinement: 4/4 operations, certificate
  `2095d2ac8af6bf45fcfad9c577c2ce1e4c988ec63a85f1791be5a3b1c7fcd44a`.
- C refinement: 4/4 operations, certificate
  `8981218779800482746da6c67391ac042d6d877f09bfd7a78e2d24641db1e1b5`.

No auxiliary invariant was needed. Typed bounds plus the operation guards were
already inductive: reader entry proves the upper bound, reader exit proves the
lower bound, and the cross-variable exclusion invariant is preserved by the
writer/reader guards and exact frames.

This is a safety-only atomic abstraction. It does not establish reader/writer
fairness, starvation freedom, scheduling progress, or correctness of a concrete
concurrent lock under a hardware memory model.

## Artifacts

- Accepted candidate: `domains/candidates/bounded_readers_writers_lock.v2.yaml`
- Validation evidence: `domains/candidates/bounded_readers_writers_lock.v2.validation.json`
- Reviewed model: `domains/v2/bounded_readers_writers_lock.json`
- Generated sources: `BoundedReadersWritersLock.rs` and
  `bounded_readers_writers_lock.c`
- Rejected one-actor candidate: `domains/candidates/readers_writers_lock.v2.yaml`
