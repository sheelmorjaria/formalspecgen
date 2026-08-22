From radium Require Import lang notation.
From refinedrust Require Import typing shims.
From refinedrust.examples.formalkernel_refinedrust_array_regression.generated Require Import generated_code_formalkernel_refinedrust_array_regression generated_specs_formalkernel_refinedrust_array_regression generated_template_embedded_1.

Set Default Proof Using "Type".

Section proof.
Context `{RRGS : !refinedrustGS Σ}.

Lemma embedded_1_proof (π : thread_id) :
  embedded_1_lemma π.
Proof.
  embedded_1_prelude.

  rep <-! liRStep; liShow.

  all: print_remaining_goal.
  Unshelve. all: sidecond_solver.
  Unshelve. all: sidecond_hammer.
  Unshelve. all: print_remaining_sidecond.
Qed.
End proof.
