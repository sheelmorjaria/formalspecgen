------------------------ MODULE SmpSchedulerRefinement ------------------------
EXTENDS FiniteSets

CONSTANTS CPUs, Tasks, None, Affinity
VARIABLE owner

vars == <<owner>>

TypeOK ==
    /\ None \notin CPUs
    /\ Affinity \in [Tasks -> SUBSET CPUs]
    /\ owner \in [Tasks -> CPUs \cup {None}]

AffinityOK == \A t \in Tasks : owner[t] # None => owner[t] \in Affinity[t]
Inv == TypeOK /\ AffinityOK

Init == owner = [t \in Tasks |-> None]

Enqueue(t, c) ==
    /\ t \in Tasks /\ c \in CPUs /\ c \in Affinity[t]
    /\ owner[t] = None
    /\ owner' = [owner EXCEPT ![t] = c]

Dequeue(t, c) ==
    /\ t \in Tasks /\ c \in CPUs /\ owner[t] = c
    /\ owner' = [owner EXCEPT ![t] = None]

Migrate(t, from, to) ==
    /\ t \in Tasks /\ from \in CPUs /\ to \in CPUs
    /\ owner[t] = from /\ to \in Affinity[t]
    /\ owner' = [owner EXCEPT ![t] = to]

Next ==
    \/ \E t \in Tasks, c \in CPUs : Enqueue(t, c)
    \/ \E t \in Tasks, c \in CPUs : Dequeue(t, c)
    \/ \E t \in Tasks, from \in CPUs, to \in CPUs : Migrate(t, from, to)

THEOREM InitImpliesInv == TypeOK /\ Init => Inv
<1>1. TypeOK /\ Init => AffinityOK BY DEF TypeOK, Init, AffinityOK
<1>. QED BY <1>1 DEF Inv

THEOREM InvIsInductive == Inv /\ [Next]_vars => Inv'
<1>1. Inv /\ Next => Inv'
    BY DEF Inv, TypeOK, AffinityOK, Next, Enqueue, Dequeue, Migrate, vars
<1>2. Inv /\ UNCHANGED vars => Inv'
    BY DEF Inv, TypeOK, AffinityOK, vars
<1>. QED BY <1>1, <1>2 DEF vars

THEOREM MigrationConservesRunnable ==
    \A t \in Tasks, from \in CPUs, to \in CPUs :
    Inv /\ Migrate(t, from, to) =>
      Cardinality({x \in Tasks : owner[x] # None}) =
      Cardinality({x \in Tasks : owner'[x] # None})
    BY DEF Inv, TypeOK, Migrate
=============================================================================
