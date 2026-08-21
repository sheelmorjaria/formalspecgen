----------------------------- MODULE RCURefinement -----------------------------
EXTENDS Naturals, FiniteSets

CONSTANT Readers
VARIABLES epoch, active, readerEpoch, callbackEpoch, reclaimed

vars == <<epoch, active, readerEpoch, callbackEpoch, reclaimed>>

TypeOK ==
    /\ epoch \in Nat
    /\ active \subseteq Readers
    /\ readerEpoch \in [Readers -> Nat]
    /\ callbackEpoch \in Nat
    /\ reclaimed \in BOOLEAN

Safe ==
    /\ reclaimed => epoch > callbackEpoch
    /\ reclaimed => \A r \in active : readerEpoch[r] > callbackEpoch

Inv == TypeOK /\ Safe

Init ==
    /\ epoch = 0
    /\ active = {}
    /\ readerEpoch = [r \in Readers |-> 0]
    /\ callbackEpoch = 0
    /\ reclaimed = FALSE

ReaderEnter(r) ==
    /\ r \in Readers
    /\ ~reclaimed \/ epoch > callbackEpoch
    /\ active' = active \cup {r}
    /\ readerEpoch' = [readerEpoch EXCEPT ![r] = epoch]
    /\ UNCHANGED <<epoch, callbackEpoch, reclaimed>>

ReaderExit(r) ==
    /\ r \in active
    /\ active' = active \ {r}
    /\ UNCHANGED <<epoch, readerEpoch, callbackEpoch, reclaimed>>

StartGrace ==
    /\ callbackEpoch' = epoch
    /\ epoch' = epoch + 1
    /\ reclaimed' = FALSE
    /\ UNCHANGED <<active, readerEpoch>>

Reclaim ==
    /\ ~reclaimed
    /\ \A r \in active : readerEpoch[r] > callbackEpoch
    /\ epoch > callbackEpoch
    /\ reclaimed' = TRUE
    /\ UNCHANGED <<epoch, active, readerEpoch, callbackEpoch>>

Next ==
    \/ \E r \in Readers : ReaderEnter(r)
    \/ \E r \in Readers : ReaderExit(r)
    \/ StartGrace
    \/ Reclaim

THEOREM InitImpliesInv == Init => Inv
<1>1. Init => TypeOK BY DEF Init, TypeOK
<1>2. Init => Safe BY DEF Init, Safe
<1>. QED BY <1>1, <1>2 DEF Inv

THEOREM InvIsInductive == Inv /\ [Next]_vars => Inv'
<1>1. Inv /\ Next => Inv'
    BY DEF Inv, TypeOK, Safe, Next, ReaderEnter, ReaderExit,
           StartGrace, Reclaim, vars
<1>2. Inv /\ UNCHANGED vars => Inv'
    BY DEF Inv, TypeOK, Safe, vars
<1>. QED BY <1>1, <1>2 DEF vars
=============================================================================
