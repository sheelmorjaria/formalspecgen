From radium Require Import lang notation.
From refinedrust Require Import typing shims.
From refinedrust.examples.formalkernel_refinedrust_smoke.generated Require Import generated_code_formalkernel_refinedrust_smoke generated_specs_formalkernel_refinedrust_smoke generated_template_preserve.

Set Default Proof Using "Type".

Section proof.
Context `{RRGS : !refinedrustGS Σ}.

Lemma preserve_proof (π : thread_id) :
  preserve_lemma π.
Proof.
  preserve_prelude.

  rep <-! liRStep; liShow.

  all: print_remaining_goal.
  Unshelve. all: sidecond_solver.
  Unshelve. all: sidecond_hammer.
  Unshelve. all: print_remaining_sidecond.
Qed.
End proof.
