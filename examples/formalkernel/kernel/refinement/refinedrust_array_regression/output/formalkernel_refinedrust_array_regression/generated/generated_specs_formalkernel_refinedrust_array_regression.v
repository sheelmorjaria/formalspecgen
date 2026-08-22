From radium Require Import lang notation.
From refinedrust Require Import typing shims.
From refinedrust.examples.formalkernel_refinedrust_array_regression Require Export generated_code_formalkernel_refinedrust_array_regression.

Section Slots0_ty.
  Context `{RRGS : !(refinedrustGS Σ)}.
  Definition Slots0_ty  : (spec_with 0 [] ((type (plist place_rfnRT [list ((place_rfnRT bool)) : RT])))).
  Proof.
    exact (spec! ( *[]) : 0 | ( *[]) : ([] : list RT), (struct_t Slots0_sls +[((array_t 0 bool_t))])).
  Defined.

  Definition Slots0_rt  : RT.
  Proof using  .
    let __a := (normalized_rt_of_spec_ty (Slots0_ty)) in exact __a.
  Defined.

  #[global] Typeclasses Transparent Slots0_rt.
  #[global] Typeclasses Transparent Slots0_ty.
End Slots0_ty.
#[global] Arguments Slots0_rt : clear implicits.

#[global] Arguments Slots0_ty : clear implicits.

#[global] Arguments Slots0_ty {_ _}  .


Section Slots1_ty.
  Context `{RRGS : !(refinedrustGS Σ)}.
  Definition Slots1_ty  : (spec_with 0 [] ((type (plist place_rfnRT [list ((place_rfnRT bool)) : RT])))).
  Proof.
    exact (spec! ( *[]) : 0 | ( *[]) : ([] : list RT), (struct_t Slots1_sls +[((array_t 1 bool_t))])).
  Defined.

  Definition Slots1_rt  : RT.
  Proof using  .
    let __a := (normalized_rt_of_spec_ty (Slots1_ty)) in exact __a.
  Defined.

  #[global] Typeclasses Transparent Slots1_rt.
  #[global] Typeclasses Transparent Slots1_ty.
End Slots1_ty.
#[global] Arguments Slots1_rt : clear implicits.

#[global] Arguments Slots1_ty : clear implicits.

#[global] Arguments Slots1_ty {_ _}  .


Section Slots16_ty.
  Context `{RRGS : !(refinedrustGS Σ)}.
  Definition Slots16_ty  : (spec_with 0 [] ((type (plist place_rfnRT [list ((place_rfnRT bool)) : RT])))).
  Proof.
    exact (spec! ( *[]) : 0 | ( *[]) : ([] : list RT), (struct_t Slots16_sls +[((array_t 16 bool_t))])).
  Defined.

  Definition Slots16_rt  : RT.
  Proof using  .
    let __a := (normalized_rt_of_spec_ty (Slots16_ty)) in exact __a.
  Defined.

  #[global] Typeclasses Transparent Slots16_rt.
  #[global] Typeclasses Transparent Slots16_ty.
End Slots16_ty.
#[global] Arguments Slots16_rt : clear implicits.

#[global] Arguments Slots16_ty : clear implicits.

#[global] Arguments Slots16_ty {_ _}  .


Section Slots2_ty.
  Context `{RRGS : !(refinedrustGS Σ)}.
  Definition Slots2_ty  : (spec_with 0 [] ((type (plist place_rfnRT [list ((place_rfnRT bool)) : RT])))).
  Proof.
    exact (spec! ( *[]) : 0 | ( *[]) : ([] : list RT), (struct_t Slots2_sls +[((array_t 2 bool_t))])).
  Defined.

  Definition Slots2_rt  : RT.
  Proof using  .
    let __a := (normalized_rt_of_spec_ty (Slots2_ty)) in exact __a.
  Defined.

  #[global] Typeclasses Transparent Slots2_rt.
  #[global] Typeclasses Transparent Slots2_ty.
End Slots2_ty.
#[global] Arguments Slots2_rt : clear implicits.

#[global] Arguments Slots2_ty : clear implicits.

#[global] Arguments Slots2_ty {_ _}  .


Section Slots4_ty.
  Context `{RRGS : !(refinedrustGS Σ)}.
  Definition Slots4_ty  : (spec_with 0 [] ((type (plist place_rfnRT [list ((place_rfnRT bool)) : RT])))).
  Proof.
    exact (spec! ( *[]) : 0 | ( *[]) : ([] : list RT), (struct_t Slots4_sls +[((array_t 4 bool_t))])).
  Defined.

  Definition Slots4_rt  : RT.
  Proof using  .
    let __a := (normalized_rt_of_spec_ty (Slots4_ty)) in exact __a.
  Defined.

  #[global] Typeclasses Transparent Slots4_rt.
  #[global] Typeclasses Transparent Slots4_ty.
End Slots4_ty.
#[global] Arguments Slots4_rt : clear implicits.

#[global] Arguments Slots4_ty : clear implicits.

#[global] Arguments Slots4_ty {_ _}  .


Section closure_attrs.
Context `{RRGS : !refinedrustGS Σ}.
End closure_attrs.

Section specs.
Context `{RRGS : !refinedrustGS Σ}.

Definition trait_incl_of_embedded_0  : (spec_with _ _ Prop) :=
  spec! ( *[]) : 0 | ( *[]) : ([] : list RT), (True).

Definition type_of_embedded_0  :=
  fn(∀ ( *[]) : 0 | ( *[]) : ([] : list (RT * syn_type)%type) | 
      (* params....... *) (value) : ((_)),
      (* elctx........ *) (λ ϝ, []);
      (* args......... *) value :@: (Slots0_ty  -[] -[]);
      (* precondition. *) (λ π : thread_id, True) |
      (* trait reqs... *) (λ π : thread_id, True)) →
      (* existential.. *) ∃ (ret) : ((_)), ret @ (Slots0_ty  -[] -[]);
      (* postcondition *) (λ π : thread_id, True) |
      (* unwind post... *) False.

Definition trait_incl_of_embedded_1  : (spec_with _ _ Prop) :=
  spec! ( *[]) : 0 | ( *[]) : ([] : list RT), (True).

Definition type_of_embedded_1  :=
  fn(∀ ( *[]) : 0 | ( *[]) : ([] : list (RT * syn_type)%type) | 
      (* params....... *) (value) : ((_)),
      (* elctx........ *) (λ ϝ, []);
      (* args......... *) value :@: (Slots1_ty  -[] -[]);
      (* precondition. *) (λ π : thread_id, True) |
      (* trait reqs... *) (λ π : thread_id, True)) →
      (* existential.. *) ∃ (ret) : ((_)), ret @ (Slots1_ty  -[] -[]);
      (* postcondition *) (λ π : thread_id, True) |
      (* unwind post... *) False.

Definition trait_incl_of_embedded_16  : (spec_with _ _ Prop) :=
  spec! ( *[]) : 0 | ( *[]) : ([] : list RT), (True).

Definition type_of_embedded_16  :=
  fn(∀ ( *[]) : 0 | ( *[]) : ([] : list (RT * syn_type)%type) | 
      (* params....... *) (value) : ((_)),
      (* elctx........ *) (λ ϝ, []);
      (* args......... *) value :@: (Slots16_ty  -[] -[]);
      (* precondition. *) (λ π : thread_id, True) |
      (* trait reqs... *) (λ π : thread_id, True)) →
      (* existential.. *) ∃ (ret) : ((_)), ret @ (Slots16_ty  -[] -[]);
      (* postcondition *) (λ π : thread_id, True) |
      (* unwind post... *) False.

Definition trait_incl_of_embedded_2  : (spec_with _ _ Prop) :=
  spec! ( *[]) : 0 | ( *[]) : ([] : list RT), (True).

Definition type_of_embedded_2  :=
  fn(∀ ( *[]) : 0 | ( *[]) : ([] : list (RT * syn_type)%type) | 
      (* params....... *) (value) : ((_)),
      (* elctx........ *) (λ ϝ, []);
      (* args......... *) value :@: (Slots2_ty  -[] -[]);
      (* precondition. *) (λ π : thread_id, True) |
      (* trait reqs... *) (λ π : thread_id, True)) →
      (* existential.. *) ∃ (ret) : ((_)), ret @ (Slots2_ty  -[] -[]);
      (* postcondition *) (λ π : thread_id, True) |
      (* unwind post... *) False.

Definition trait_incl_of_embedded_4  : (spec_with _ _ Prop) :=
  spec! ( *[]) : 0 | ( *[]) : ([] : list RT), (True).

Definition type_of_embedded_4  :=
  fn(∀ ( *[]) : 0 | ( *[]) : ([] : list (RT * syn_type)%type) | 
      (* params....... *) (value) : ((_)),
      (* elctx........ *) (λ ϝ, []);
      (* args......... *) value :@: (Slots4_ty  -[] -[]);
      (* precondition. *) (λ π : thread_id, True) |
      (* trait reqs... *) (λ π : thread_id, True)) →
      (* existential.. *) ∃ (ret) : ((_)), ret @ (Slots4_ty  -[] -[]);
      (* postcondition *) (λ π : thread_id, True) |
      (* unwind post... *) False.

Definition trait_incl_of_standalone_0  : (spec_with _ _ Prop) :=
  spec! ( *[]) : 0 | ( *[]) : ([] : list RT), (True).

Definition type_of_standalone_0  :=
  fn(∀ ( *[]) : 0 | ( *[]) : ([] : list (RT * syn_type)%type) | 
      (* params....... *) (value) : ((_)),
      (* elctx........ *) (λ ϝ, []);
      (* args......... *) value :@: (array_t 0 bool_t);
      (* precondition. *) (λ π : thread_id, True) |
      (* trait reqs... *) (λ π : thread_id, True)) →
      (* existential.. *) ∃ (ret) : ((_)), ret @ (array_t 0 bool_t);
      (* postcondition *) (λ π : thread_id, True) |
      (* unwind post... *) False.

Definition trait_incl_of_standalone_1  : (spec_with _ _ Prop) :=
  spec! ( *[]) : 0 | ( *[]) : ([] : list RT), (True).

Definition type_of_standalone_1  :=
  fn(∀ ( *[]) : 0 | ( *[]) : ([] : list (RT * syn_type)%type) | 
      (* params....... *) (value) : ((_)),
      (* elctx........ *) (λ ϝ, []);
      (* args......... *) value :@: (array_t 1 bool_t);
      (* precondition. *) (λ π : thread_id, True) |
      (* trait reqs... *) (λ π : thread_id, True)) →
      (* existential.. *) ∃ (ret) : ((_)), ret @ (array_t 1 bool_t);
      (* postcondition *) (λ π : thread_id, True) |
      (* unwind post... *) False.

Definition trait_incl_of_standalone_16  : (spec_with _ _ Prop) :=
  spec! ( *[]) : 0 | ( *[]) : ([] : list RT), (True).

Definition type_of_standalone_16  :=
  fn(∀ ( *[]) : 0 | ( *[]) : ([] : list (RT * syn_type)%type) | 
      (* params....... *) (value) : ((_)),
      (* elctx........ *) (λ ϝ, []);
      (* args......... *) value :@: (array_t 16 bool_t);
      (* precondition. *) (λ π : thread_id, True) |
      (* trait reqs... *) (λ π : thread_id, True)) →
      (* existential.. *) ∃ (ret) : ((_)), ret @ (array_t 16 bool_t);
      (* postcondition *) (λ π : thread_id, True) |
      (* unwind post... *) False.

Definition trait_incl_of_standalone_2  : (spec_with _ _ Prop) :=
  spec! ( *[]) : 0 | ( *[]) : ([] : list RT), (True).

Definition type_of_standalone_2  :=
  fn(∀ ( *[]) : 0 | ( *[]) : ([] : list (RT * syn_type)%type) | 
      (* params....... *) (value) : ((_)),
      (* elctx........ *) (λ ϝ, []);
      (* args......... *) value :@: (array_t 2 bool_t);
      (* precondition. *) (λ π : thread_id, True) |
      (* trait reqs... *) (λ π : thread_id, True)) →
      (* existential.. *) ∃ (ret) : ((_)), ret @ (array_t 2 bool_t);
      (* postcondition *) (λ π : thread_id, True) |
      (* unwind post... *) False.

Definition trait_incl_of_standalone_4  : (spec_with _ _ Prop) :=
  spec! ( *[]) : 0 | ( *[]) : ([] : list RT), (True).

Definition type_of_standalone_4  :=
  fn(∀ ( *[]) : 0 | ( *[]) : ([] : list (RT * syn_type)%type) | 
      (* params....... *) (value) : ((_)),
      (* elctx........ *) (λ ϝ, []);
      (* args......... *) value :@: (array_t 4 bool_t);
      (* precondition. *) (λ π : thread_id, True) |
      (* trait reqs... *) (λ π : thread_id, True)) →
      (* existential.. *) ∃ (ret) : ((_)), ret @ (array_t 4 bool_t);
      (* postcondition *) (λ π : thread_id, True) |
      (* unwind post... *) False.




End specs.
