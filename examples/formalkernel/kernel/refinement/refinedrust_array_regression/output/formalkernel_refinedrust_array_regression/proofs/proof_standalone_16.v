From radium Require Import lang notation.
From refinedrust Require Import typing shims.
From refinedrust.examples.formalkernel_refinedrust_array_regression.generated Require Import generated_code_formalkernel_refinedrust_array_regression generated_specs_formalkernel_refinedrust_array_regression generated_template_standalone_16.

Set Default Proof Using "Type".

Section proof.
Context `{RRGS : !refinedrustGS Σ}.

Lemma standalone_16_proof (π : thread_id) :
  standalone_16_lemma π.
Proof.
  standalone_16_prelude.

  rep <-! liRStep; liShow.

  all: print_remaining_goal.
  Unshelve. all: sidecond_solver.
  Unshelve. all: sidecond_hammer.
  Unshelve. all: print_remaining_sidecond.
Qed.
End proof.
