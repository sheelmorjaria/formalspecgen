---------------------- MODULE CapabilityRevocationRefinement ----------------------
EXTENDS Naturals, FiniteSets

CONSTANTS CapabilityIds, Principals, Objects, Rights, RootAuthorities

ASSUME /\ CapabilityIds # {}
       /\ Principals # {}
       /\ Objects # {}
       /\ Rights # {}
       /\ RootAuthorities \subseteq Principals

Key == [id: CapabilityIds, generation: Nat]
Token ==
    [key: Key,
     object: Objects,
     rights: SUBSET Rights,
     owner: Principals,
     ancestors: SUBSET Key,
     origin: {"root", "derive", "delegate"}]

VARIABLES live, issued, revoked
vars == <<live, issued, revoked>>

TypeOK ==
    /\ live \subseteq Token
    /\ issued \subseteq Key
    /\ revoked \subseteq issued
    /\ \A t \in live : t.key \in issued

Valid(t) ==
    /\ t \in live
    /\ t.key \notin revoked
    /\ t.ancestors \cap revoked = {}

ValidNext(t) ==
    /\ t \in live'
    /\ t.key \notin revoked'
    /\ t.ancestors \cap revoked' = {}

RevokedAncestorBlocksAuthorization ==
    \A t \in live :
        (t.key \in revoked \/ t.ancestors \cap revoked # {}) => ~Valid(t)

StaleGenerationRejected ==
    \A old \in live : old.key \in revoked => ~Valid(old)

Inv == TypeOK

Init == /\ live = {}
        /\ issued = {}
        /\ revoked = {}

MintRoot(newId, generation, caller, newObject, newRights) ==
    /\ caller \in RootAuthorities
    /\ newId \in CapabilityIds
    /\ generation \in Nat
    /\ [id |-> newId, generation |-> generation] \notin issued
    /\ newObject \in Objects
    /\ newRights \subseteq Rights
    /\ LET key == [id |-> newId, generation |-> generation]
           new == [key |-> key, object |-> newObject, rights |-> newRights,
                   owner |-> caller, ancestors |-> {}, origin |-> "root"]
       IN  /\ new \in Token
           /\ key \notin revoked
           /\ new.ancestors \cap revoked = {}
           /\ live' = live \cup {new}
           /\ \A t \in live : t.key # key
           /\ issued' = issued \cup {key}
           /\ revoked' = revoked

Derive(parent, newId, generation, newOwner, newRights) ==
    /\ Valid(parent)
    /\ newId \in CapabilityIds
    /\ generation \in Nat
    /\ [id |-> newId, generation |-> generation] \notin issued
    /\ newOwner \in Principals
    /\ newRights \subseteq parent.rights
    /\ LET key == [id |-> newId, generation |-> generation]
           new == [key |-> key, object |-> parent.object, rights |-> newRights,
                   owner |-> newOwner,
                   ancestors |-> parent.ancestors \cup {parent.key},
                   origin |-> "derive"]
       IN  /\ new \in Token
           /\ key \notin revoked
           /\ live' = live \cup {new}
           /\ \A t \in live : t.key # key
           /\ issued' = issued \cup {key}
           /\ revoked' = revoked

Delegate(parent, newId, generation, newOwner, newRights) ==
    /\ Valid(parent)
    /\ newId \in CapabilityIds
    /\ generation \in Nat
    /\ [id |-> newId, generation |-> generation] \notin issued
    /\ newOwner \in Principals
    /\ newRights \subseteq parent.rights
    /\ LET key == [id |-> newId, generation |-> generation]
           new == [key |-> key, object |-> parent.object, rights |-> newRights,
                   owner |-> newOwner,
                   ancestors |-> parent.ancestors \cup {parent.key},
                   origin |-> "delegate"]
       IN  /\ new \in Token
           /\ key \notin revoked
           /\ live' = live \cup {new}
           /\ \A t \in live : t.key # key
           /\ issued' = issued \cup {key}
           /\ revoked' = revoked

Revoke(token) ==
    /\ Valid(token)
    /\ live' = live
    /\ issued' = issued
    /\ revoked' = revoked \cup {token.key}

RejectStale(token) ==
    /\ token \in live
    /\ ~Valid(token)
    /\ UNCHANGED vars

Check(token) == /\ Valid(token)
                /\ UNCHANGED vars

Next ==
    \/ \E i \in CapabilityIds, g \in Nat, p \in Principals,
          o \in Objects, rs \in SUBSET Rights : MintRoot(i, g, p, o, rs)
    \/ \E p \in live, i \in CapabilityIds, g \in Nat,
          q \in Principals, rs \in SUBSET Rights : Derive(p, i, g, q, rs)
    \/ \E p \in live, i \in CapabilityIds, g \in Nat,
          q \in Principals, rs \in SUBSET Rights : Delegate(p, i, g, q, rs)
    \/ \E t \in live : Revoke(t)
    \/ \E t \in live : RejectStale(t)
    \/ \E t \in live : Check(t)

THEOREM RevocationPersists == Next => revoked \subseteq revoked'
BY DEF Next, MintRoot, Derive, Delegate, Revoke, RejectStale, Check, vars

THEOREM RevokeBlocksDescendants ==
    \A root, descendant \in live :
        /\ Revoke(root)
        /\ (descendant.key = root.key \/ root.key \in descendant.ancestors)
        => ~ValidNext(descendant)
BY DEF Revoke, ValidNext

THEOREM RevokePreservesUnrelatedAuthority ==
    \A root, other \in live :
        /\ Revoke(root)
        /\ Valid(other)
        /\ other.key # root.key
        /\ root.key \notin other.ancestors
        => ValidNext(other)
BY DEF Revoke, Valid, ValidNext

THEOREM RevokedAncestorBlocksAuthorizationTheorem ==
    TypeOK => RevokedAncestorBlocksAuthorization
BY DEF TypeOK, RevokedAncestorBlocksAuthorization, Valid

THEOREM StaleTokenCannotCreate ==
    \A t \in live : ~Valid(t) =>
        /\ ~\E i \in CapabilityIds, g \in Nat, q \in Principals,
              rs \in SUBSET Rights : Derive(t, i, g, q, rs)
        /\ ~\E i \in CapabilityIds, g \in Nat, q \in Principals,
              rs \in SUBSET Rights : Delegate(t, i, g, q, rs)
BY DEF Derive, Delegate

THEOREM StaleTokenCannotCheck ==
    \A t \in live : ~Valid(t) => ~Check(t)
BY DEF Check

THEOREM StaleTokenCannotRevoke ==
    \A t \in live : ~Valid(t) => ~Revoke(t)
BY DEF Revoke

THEOREM GenerationReuseRejectsOld ==
    TypeOK => \A old, fresh \in live :
        /\ old.key.id = fresh.key.id
        /\ old.key.generation # fresh.key.generation
        /\ old.key \in revoked
        => ~Valid(old)
BY DEF TypeOK, Valid

THEOREM MintRequiresFreshGeneration ==
    \A i \in CapabilityIds, g \in Nat, p \in Principals,
       o \in Objects, rs \in SUBSET Rights :
        MintRoot(i, g, p, o, rs) =>
            [id |-> i, generation |-> g] \notin issued
BY DEF MintRoot

THEOREM FailedStaleOperationStutters ==
    \A t \in live : RejectStale(t) => UNCHANGED vars
BY DEF RejectStale
=============================================================================
