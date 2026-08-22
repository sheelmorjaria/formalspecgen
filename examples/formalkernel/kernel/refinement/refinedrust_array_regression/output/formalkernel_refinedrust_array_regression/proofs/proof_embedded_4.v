From radium Require Import lang notation.
From refinedrust Require Import typing shims.
From refinedrust.examples.formalkernel_refinedrust_array_regression.generated Require Import generated_code_formalkernel_refinedrust_array_regression generated_specs_formalkernel_refinedrust_array_regression generated_template_embedded_4.

Set Default Proof Using "Type".

Section proof.
Context `{RRGS : !refinedrustGS Σ}.

Lemma embedded_4_proof (π : thread_id) :
  embedded_4_lemma π.
Proof.
  embedded_4_prelude.

  rep <-! liRStep; liShow.

  all: print_remaining_goal.
  Unshelve. all: sidecond_solver.
  Unshelve. all: sidecond_hammer.
  Unshelve. all: print_remaining_sidecond.
Qed.
End proof.
