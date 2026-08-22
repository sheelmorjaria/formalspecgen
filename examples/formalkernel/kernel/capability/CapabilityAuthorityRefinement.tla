---------------------- MODULE CapabilityAuthorityRefinement ----------------------
EXTENDS Naturals, FiniteSets

CONSTANTS CapabilityIds, Principals, Objects, Rights, RootAuthorities, NullCap

ASSUME /\ CapabilityIds # {}
       /\ Principals # {}
       /\ Objects # {}
       /\ Rights # {}
       /\ RootAuthorities \subseteq Principals
       /\ NullCap \notin CapabilityIds

Capability ==
    [id: CapabilityIds,
     object: Objects,
     rights: SUBSET Rights,
     owner: Principals,
     generation: Nat,
     parent: CapabilityIds \cup {NullCap},
     parentRights: SUBSET Rights,
     parentObject: Objects,
     origin: {"root", "derive", "delegate"}]

VARIABLE live
vars == <<live>>

TypeOK == live \subseteq Capability

AuthorityAttenuated ==
    \A c \in live :
        c.origin \in {"derive", "delegate"} =>
            /\ c.parent \in CapabilityIds
            /\ c.rights \subseteq c.parentRights
            /\ c.object = c.parentObject

CreationClosed ==
    \A c \in live :
        \/ /\ c.origin = "root"
           /\ c.owner \in RootAuthorities
           /\ c.parent = NullCap
        \/ /\ c.origin \in {"derive", "delegate"}
           /\ c.parent \in CapabilityIds
           /\ c.rights \subseteq c.parentRights
           /\ c.object = c.parentObject

Inv == TypeOK /\ AuthorityAttenuated /\ CreationClosed

Init == live = {}

MintRoot(newId, caller, newObject, newRights, generation) ==
    /\ newId \in CapabilityIds
    /\ caller \in RootAuthorities
    /\ newObject \in Objects
    /\ newRights \subseteq Rights
    /\ generation \in Nat
    /\ LET new == [id |-> newId, object |-> newObject, rights |-> newRights,
                   owner |-> caller, generation |-> generation,
                   parent |-> NullCap, parentRights |-> {},
                   parentObject |-> newObject, origin |-> "root"]
       IN  /\ \A c \in live : c.id # newId
           /\ live' = live \cup {new}

Derive(parent, newId, newOwner, newObject, newRights, generation) ==
    /\ parent \in live
    /\ newId \in CapabilityIds
    /\ newOwner \in Principals
    /\ newObject = parent.object
    /\ newRights \subseteq parent.rights
    /\ generation \in Nat
    /\ LET new == [id |-> newId, object |-> newObject, rights |-> newRights,
                   owner |-> newOwner, generation |-> generation,
                   parent |-> parent.id, parentRights |-> parent.rights,
                   parentObject |-> parent.object, origin |-> "derive"]
       IN  /\ \A c \in live : c.id # newId
           /\ live' = live \cup {new}

Delegate(parent, newId, newOwner, newRights, generation) ==
    /\ parent \in live
    /\ newId \in CapabilityIds
    /\ newOwner \in Principals
    /\ newRights \subseteq parent.rights
    /\ generation \in Nat
    /\ LET new == [id |-> newId, object |-> parent.object, rights |-> newRights,
                   owner |-> newOwner, generation |-> generation,
                   parent |-> parent.id, parentRights |-> parent.rights,
                   parentObject |-> parent.object, origin |-> "delegate"]
       IN  /\ \A c \in live : c.id # newId
           /\ live' = live \cup {new}

Revoke(cap) == /\ cap \in live
               /\ live' = live \ {cap}

Check == UNCHANGED live

Next ==
    \/ \E i \in CapabilityIds, p \in Principals, o \in Objects,
          rs \in SUBSET Rights, g \in Nat : MintRoot(i, p, o, rs, g)
    \/ \E p \in live, i \in CapabilityIds, q \in Principals,
          o \in Objects, rs \in SUBSET Rights, g \in Nat : Derive(p, i, q, o, rs, g)
    \/ \E p \in live, i \in CapabilityIds, q \in Principals,
          rs \in SUBSET Rights, g \in Nat : Delegate(p, i, q, rs, g)
    \/ \E c \in live : Revoke(c)
    \/ Check

THEOREM InitImpliesInv == Init => Inv
<1>1. Init => TypeOK BY DEF Init, TypeOK
<1>2. Init => AuthorityAttenuated BY DEF Init, AuthorityAttenuated
<1>3. Init => CreationClosed BY DEF Init, CreationClosed
<1>. QED BY <1>1, <1>2, <1>3 DEF Inv

THEOREM InvIsInductive == Inv /\ [Next]_vars => Inv'
<1>1. Inv /\ Next => Inv'
    BY DEF Inv, TypeOK, AuthorityAttenuated, CreationClosed, Next,
           MintRoot, Derive, Delegate, Revoke, Check, vars, Capability
<1>2. Inv /\ UNCHANGED vars => Inv'
    BY DEF Inv, TypeOK, AuthorityAttenuated, CreationClosed, vars
<1>. QED BY <1>1, <1>2 DEF vars
=============================================================================
