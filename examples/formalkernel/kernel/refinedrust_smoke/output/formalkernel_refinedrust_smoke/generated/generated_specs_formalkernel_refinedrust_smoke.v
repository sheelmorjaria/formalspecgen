From radium Require Import lang notation.
From refinedrust Require Import typing shims.
From refinedrust.examples.formalkernel_refinedrust_smoke Require Export generated_code_formalkernel_refinedrust_smoke.

Section closure_attrs.
Context `{RRGS : !refinedrustGS Σ}.
End closure_attrs.

Section specs.
Context `{RRGS : !refinedrustGS Σ}.

Definition trait_incl_of_preserve  : (spec_with _ _ Prop) :=
  spec! ( *[]) : 0 | ( *[]) : ([] : list RT), (True).

Definition type_of_preserve  :=
  fn(∀ ( *[]) : 0 | ( *[]) : ([] : list (RT * syn_type)%type) | 
      (* params....... *) (value) : ((_)),
      (* elctx........ *) (λ ϝ, []);
      (* args......... *) value :@: (int I32);
      (* precondition. *) (λ π : thread_id, True) |
      (* trait reqs... *) (λ π : thread_id, True)) →
      (* existential.. *) ∃ _ : unit, value @ (int I32);
      (* postcondition *) (λ π : thread_id, True) |
      (* unwind post... *) False.




End specs.
