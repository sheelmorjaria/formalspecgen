From radium Require Import lang notation.
From refinedrust Require Import typing shims.
Section code.
Context `{!LayoutAlg}.
Open Scope printing_sugar.

Program Definition preserve_def  : function :=
  {|
     f_args := [
      ("value", (it_layout I32) : layout)
     ];
     f_code :=
      <[
     "_bb0" :=
      local_live{ (IntSynType I32) } "__0";
      "__0" <-{ (IntOp I32) } copy{ (IntOp I32) } ("value");
      return (move{ (IntOp I32) } ("__0"))
     ]>%E $
      ∅;
     f_init := "_bb0";
    |}.
Next Obligation.
  solve_fn_vars_nodup.
Qed.




(* closure shims *)
End code.