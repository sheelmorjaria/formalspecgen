From Coq Require Import ZArith Lia.
Open Scope Z_scope.

Record State := mkState {
  inode_count : Z;
  free_list_head : Z;
  open_handle_count : Z;
  cached_bytes : Z
}.

Definition Inv (s : State) : Prop :=
  0 <= inode_count s <= 4 /\
  0 <= free_list_head s <= 4 /\
  0 <= open_handle_count s <= 4 /\
  0 <= cached_bytes s <= 16 /\
  inode_count s + free_list_head s = 4 /\
  open_handle_count s <= inode_count s.

Definition initial : State := mkState 0 4 0 0.

Definition open_enabled (s : State) : Prop :=
  inode_count s < 4 /\ free_list_head s > 0.

Definition open_post (s : State) : State :=
  mkState (inode_count s + 1) (free_list_head s - 1)
          (open_handle_count s + 1) (cached_bytes s).

Definition close_enabled (s : State) : Prop := open_handle_count s > 0.

Definition close_post (s : State) : State :=
  mkState (inode_count s - 1) (free_list_head s + 1)
          (open_handle_count s - 1) (cached_bytes s).

Definition read_enabled (s : State) : Prop := open_handle_count s > 0.
Definition read_post (s : State) : State := s.

Definition write_enabled (s : State) : Prop :=
  open_handle_count s > 0 /\ cached_bytes s < 16.

Definition write_post (s : State) : State :=
  mkState (inode_count s) (free_list_head s) (open_handle_count s)
          (cached_bytes s + 1).

Theorem initial_preserves : Inv initial.
Proof. unfold Inv, initial; simpl; lia. Qed.

Theorem open_preserves : forall s,
  Inv s -> open_enabled s -> Inv (open_post s).
Proof.
  intros s Hinv Henabled.
  destruct s; unfold Inv, open_enabled, open_post in *; simpl in *; lia.
Qed.

Theorem close_preserves : forall s,
  Inv s -> close_enabled s -> Inv (close_post s).
Proof.
  intros s Hinv Henabled.
  destruct s; unfold Inv, close_enabled, close_post in *; simpl in *; lia.
Qed.

Theorem read_preserves : forall s,
  Inv s -> read_enabled s -> Inv (read_post s).
Proof. intros s Hinv _; exact Hinv. Qed.

Theorem write_preserves : forall s,
  Inv s -> write_enabled s -> Inv (write_post s).
Proof.
  intros s Hinv Henabled.
  destruct s; unfold Inv, write_enabled, write_post in *; simpl in *; lia.
Qed.

Theorem failure_stutter_preserves : forall s, Inv s -> Inv s.
Proof. auto. Qed.
