# Resumable V2 domain sessions

The V2 session adapter connects requirements and clarification to an immutable,
**unreviewed** candidate. It reuses the CLI question elicitor and typed V2 compiler.
It performs no verification, scaffolding, promotion or signing. Caller-supplied
answers are not authenticated human decisions, and candidate generation does not
establish specification adequacy.

The MCP sequence is:

1. `start_domain_session(idea, provider="ollama", model=null)` returns an opaque
   session ID, revision, questions and required unanswered questions.
2. `continue_domain_session(session_id, answers, expected_revision)` saves answers
   keyed by question ID. Repeat until status is `READY`. Inspect with
   `get_domain_session(session_id)` after a restart or revision conflict.
3. `finalize_domain_candidate(session_id, expected_revision)` compiles a typed,
   unreviewed V2 candidate. It returns its exact-byte artifact binding, semantic
   candidate digest, and the complete `validate_domain` request.
4. Pass that request to `validate_domain`. Successful bounded validation returns
   a validation artifact. Pass its path and the returned `promotion_candidate`
   to `request_domain_promotion`, then use the existing external human decision
   and protected completion workflow.

Each session is bound to its authenticated principal, workspace, output root,
provider and model. Its lifetime is 24 hours. Updates require the inspected
revision; competing updates cannot silently replace answers. Finalization freezes
clarifications. A new interpretation requires a new session.

## Operator setup

Configure `FORMALSPECGEN_SESSION_ROOT` to an existing, protected directory outside
all agent workspaces, free of symlinks and group/world writes. Set
`FORMALSPECGEN_SESSION_PRINCIPAL` from the operator-authenticated server identity;
it is never an MCP argument. Different principals cannot inspect or continue each
other's sessions. Do not share one configured principal among mutually untrusted
users. Use the existing operator-controlled provider endpoint/credential settings
and `FORMALSPECGEN_MCP_OUTPUT_ROOT`.

Only start and finalize have `provider_access`, limited to the declared GLM,
OpenAI and Ollama providers. Inspection and answers require service-state effects
only. No session stage has external-execution, approval or signing authority.

Inputs are bounded to 16 KiB per requirement, 256 bytes per model identifier and
4 KiB per answer. The existing elicitor limits question count and length.
Generation permits 32 compiler/elicitor calls, at most 256 KiB per HTTP response,
128 KiB per decoded content response and 1 MiB of decoded content in total.
HTTP limits are context-local and cannot widen an enclosing workflow's limit.
Provider timeout and retry behavior remains that of the configured provider.

Session history has explicit schema `formalspecgen-workflow-session-v1`, at most
128 revisions and 1 MiB per record. Immutable revision files bind their predecessor
hash. These integrity hashes do not authenticate a human or replace protection of
the session directory.

## Publication and retries

Candidates are published under the designated output root at
`domain-sessions/<session_id>/domains/candidates/<module>.v2.yaml`. The bytes are
deterministically serialized typed JSON, also valid YAML, rather than provider-supplied YAML text.
Publication uses the shared descriptor-safe, no-replace MCP artifact publisher.
It cannot overwrite a reviewed domain, another session or an existing destination.
The returned project root lets the existing validation adapter capture that exact
candidate without adding a new validation path interface.

Finalization first durably records `PREPARED` and the exact candidate bytes, then
publishes, then records `FINALIZED`. Retry with the original finalization revision
or the current prepared/finalized revision. It reuses the captured bytes rather
than calling the provider again. Missing finalized candidates, changed bytes and
symlinks require a new session; they are never silently repaired or replaced.

## Scope and qualification

These four tools implement one V2 domain workflow. They do not establish full
`domain` CLI parity: legacy V1 scaffolding, force/replacement flags, terminal
restart behavior and downstream verification remain separate. The checked-in
parity report stays evidence-free and whole-command completion remains partial.

Unit tests cover resumption, ownership, expiry, concurrent revision conflicts,
malformed/tampered history, bounded providers, candidate changes and interrupted
publication. Provisioned acceptance exercises real MCP stdio across restarted
servers and a local provider fixture, then feeds the candidate into real isolated
TLC validation and the authenticated human promotion handoff. A local pass does not
qualify an uncommitted revision; trusted exact-revision CI is required.

CI exports exact session revisions, candidate/validation/reviewed bytes, observed
MCP schemas and signed approval controls. At the clean tested revision, replay a
downloaded trusted bundle with:

```bash
python -m scripts.qualify_domain_sessions \
  --evidence /path/to/domain-session-acceptance/session.json \
  --output /tmp/domain-session-qualification.json
```

The replay checks revision/tree and plan identity, state transitions, transport
schemas, artifact digests, applicability bindings and the authenticated human
decision. Obtaining the bundle from trusted CI remains necessary; its hashes do
not turn a locally authored bundle into CI evidence.
