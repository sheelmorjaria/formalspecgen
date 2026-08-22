From radium Require Import lang notation.
From refinedrust Require Import typing shims.
From refinedrust.examples.formalkernel_refinedrust_smoke Require Export generated_code_formalkernel_refinedrust_smoke generated_specs_formalkernel_refinedrust_smoke.

Set Default Proof Using "Type".

Section proof.
Context `{RRGS : !refinedrustGS Σ}.
Definition preserve_lemma (π : thread_id) : Prop :=
  ⊢ typed_function π (preserve_def ) (<tag_type> spec! ( *[]) : 0 | ( *[]) : ([] : list RT), fn_spec_add_late_pre (type_of_preserve -[] -[]) (λ π, (True)
  ∗ (⌜(trait_incl_of_preserve-[] -[])%Z⌝))).
End proof.

Ltac preserve_prelude :=
  unfold preserve_lemma;
  set (FN_NAME := FUNCTION_NAME "preserve");
  intros;
  iStartProof;
  let ϝ := fresh "ϝ" in
  let fid := fresh "fid" in
  let value := fresh "value" in
  start_function "preserve" ϝ fid ( [] ) ( [] ) (  value ) ( value );
  intros arg_value;
  let π := get_π in
  let Σ := get_Σ in
  specialize (pose_bb_inv (PolyNil)) as loop_map;
  init_lfts π fid (("_flft", ϝ) :: ("static", static) :: [] );
  init_tyvars ( ∅ );
  unfold_generic_inst; simpl;
  generalize RR_CONFIG_DO_STRICT_RESOLUTION; intros ?.
