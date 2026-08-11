# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0

"""Typed bounded-model IR and deterministic TLA+ serialization.

The LLM (or a deterministic domain recognizer) may choose values in this IR.  It
never owns TLA+ expressions, operators, module text, or TLC configuration syntax.
"""
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .transition_ir import MethodTransitionIR


Operation = Literal["deposit", "withdraw", "transfer"]
Invariant = Literal["type_ok", "balance_non_negative", "balance_bounded"]
Abstraction = Literal["atomic_operations", "lock_protocol"]
GuardId = Literal[
    "positive_amount", "source_has_funds", "destination_has_capacity",
    "distinct_accounts",
]
EffectId = Literal["atomic_deposit", "atomic_withdraw", "atomic_transfer"]
FrameId = Literal["receiver_balance", "source_balance", "destination_balance"]


class BankingOperationIR(BaseModel):
    """Reviewed semantic facts extracted from one JML method contract."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    operation: Operation
    guard_ids: list[GuardId]
    effect_id: EffectId
    frame_ids: list[FrameId]
    result_constrained: bool
    failure_preserves_frame: bool

    @model_validator(mode="after")
    def validate_mapping(self) -> "BankingOperationIR":
        expected_effect = {
            "deposit": "atomic_deposit", "withdraw": "atomic_withdraw",
            "transfer": "atomic_transfer",
        }[self.operation]
        if self.effect_id != expected_effect:
            raise ValueError(f"{self.operation} cannot use effect {self.effect_id}")
        if len(set(self.guard_ids)) != len(self.guard_ids):
            raise ValueError("guard_ids must be unique")
        if len(set(self.frame_ids)) != len(self.frame_ids):
            raise ValueError("frame_ids must be unique")
        return self


class BankingConcurrencyMetadata(BaseModel):
    """Concurrency facts originating in authoritative clarification answers."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    abstraction: Abstraction
    linearization: Literal["method_atomic", "ordered_account_locks"]
    lock_order: Literal["not_modeled", "ascending_immutable_account_id"]
    account_ids_immutable: bool


class BankingTlaModel(BaseModel):
    """The complete, intentionally small banking abstraction supported by v1."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    domain: Literal["bank_account"] = "bank_account"
    accounts: int = Field(default=2, ge=2, le=4)
    actors: int = Field(default=2, ge=1, le=4)
    max_balance: int = Field(default=4, ge=1, le=20)
    amounts: list[int] = Field(default_factory=lambda: [1, 2], min_length=1, max_length=5)
    operations: list[Operation] = Field(
        default_factory=lambda: ["deposit", "withdraw", "transfer"])
    invariants: list[Invariant] = Field(
        default_factory=lambda: ["type_ok", "balance_non_negative", "balance_bounded"])
    abstraction: Abstraction = "atomic_operations"
    operation_ir: list[BankingOperationIR] = Field(default_factory=list)
    transitions: list[MethodTransitionIR] = Field(default_factory=list)
    concurrency: BankingConcurrencyMetadata | None = None

    @model_validator(mode="after")
    def validate_semantics(self) -> "BankingTlaModel":
        if len(set(self.amounts)) != len(self.amounts) or any(
                amount <= 0 or amount > self.max_balance for amount in self.amounts):
            raise ValueError("amounts must be unique, positive, and no greater than max_balance")
        if len(set(self.operations)) != len(self.operations) or not self.operations:
            raise ValueError("operations must be a non-empty unique list")
        if len(set(self.invariants)) != len(self.invariants) or not self.invariants:
            raise ValueError("invariants must be a non-empty unique list")
        if self.operation_ir and [item.operation for item in self.operation_ir] != self.operations:
            raise ValueError("operation_ir must correspond exactly to operations")
        if self.transitions and [item.name for item in self.transitions] != self.operations:
            raise ValueError("transitions must correspond exactly to operations")
        if self.concurrency and self.concurrency.abstraction != self.abstraction:
            raise ValueError("concurrency abstraction does not match model abstraction")
        return self


class TLCConfig(BaseModel):
    """Typed configuration; renderer code exclusively owns CFG serialization."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    specification: Literal["Spec"] = "Spec"
    invariants: list[Literal[
        "TypeOK", "BalanceNonNegative", "BalanceBounded"
    ]]
    check_deadlock: bool = False


_INVARIANT_NAMES = {
    "type_ok": "TypeOK",
    "balance_non_negative": "BalanceNonNegative",
    "balance_bounded": "BalanceBounded",
}


def default_banking_ir() -> BankingTlaModel:
    return BankingTlaModel()


def render_banking_model(model: BankingTlaModel) -> tuple[str, str]:
    """Serialize a validated banking IR using only reviewed TLA+ fragments."""
    if model.abstraction == "lock_protocol":
        return _render_lock_protocol(model)
    accounts = ", ".join(str(value) for value in range(1, model.accounts + 1))
    actors = ", ".join(str(value) for value in range(1, model.actors + 1))
    amounts = ", ".join(str(value) for value in model.amounts)

    actions = {
        "deposit": r"""Deposit(actor, account, amount) ==
    /\ actor \in Actors
    /\ account \in Accounts
    /\ amount \in Amounts
    /\ balances[account] + amount <= MaxBalance
    /\ balances' = [balances EXCEPT ![account] = @ + amount]
    /\ lastActor' = actor""",
        "withdraw": r"""Withdraw(actor, account, amount) ==
    /\ actor \in Actors
    /\ account \in Accounts
    /\ amount \in Amounts
    /\ amount <= balances[account]
    /\ balances' = [balances EXCEPT ![account] = @ - amount]
    /\ lastActor' = actor""",
        "transfer": r"""Transfer(actor, source, destination, amount) ==
    /\ actor \in Actors
    /\ source \in Accounts
    /\ destination \in Accounts
    /\ source /= destination
    /\ amount \in Amounts
    /\ amount <= balances[source]
    /\ balances[destination] + amount <= MaxBalance
    /\ balances' = [balances EXCEPT
                        ![source] = @ - amount,
                        ![destination] = @ + amount]
    /\ lastActor' = actor""",
    }
    next_branches = {
        "deposit": r"\/ \E actor \in Actors, account \in Accounts, amount \in Amounts : Deposit(actor, account, amount)",
        "withdraw": r"\/ \E actor \in Actors, account \in Accounts, amount \in Amounts : Withdraw(actor, account, amount)",
        "transfer": r"\/ \E actor \in Actors, source \in Accounts, destination \in Accounts, amount \in Amounts : Transfer(actor, source, destination, amount)",
    }
    action_text = "\n\n".join(actions[name] for name in model.operations)
    next_text = "\n    ".join(next_branches[name] for name in model.operations)
    tla = f"""---- MODULE BoundedBankAccounts ----
EXTENDS Naturals

Accounts == {{{accounts}}}
Actors == {{{actors}}}
Amounts == {{{amounts}}}
MaxBalance == {model.max_balance}

VARIABLES balances, lastActor
vars == <<balances, lastActor>>

Init ==
    /\\ balances = [account \\in Accounts |-> 0]
    /\\ lastActor = 0

{action_text}

Next ==
    {next_text}

TypeOK ==
    /\\ balances \\in [Accounts -> 0..MaxBalance]
    /\\ lastActor \\in Actors \\cup {{0}}
BalanceNonNegative == \\A account \\in Accounts : balances[account] >= 0
BalanceBounded == \\A account \\in Accounts : balances[account] <= MaxBalance

Spec == Init /\\ [][Next]_vars
===="""
    cfg_model = TLCConfig(invariants=[_INVARIANT_NAMES[name] for name in model.invariants])
    return tla, render_cfg(cfg_model)


def _render_lock_protocol(model: BankingTlaModel) -> tuple[str, str]:
    """Render intermediate lock-acquisition states so ordering is model-checkable."""
    accounts = ", ".join(str(value) for value in range(1, model.accounts + 1))
    actors = ", ".join(str(value) for value in range(1, model.actors + 1))
    amounts = ", ".join(str(value) for value in model.amounts)
    tla = f"""---- MODULE BoundedBankLockProtocol ----
EXTENDS Naturals

Accounts == {{{accounts}}}
Actors == {{{actors}}}
Amounts == {{{amounts}}}
MaxBalance == {model.max_balance}
Idle == "idle"
HaveFirst == "haveFirst"
HaveBoth == "haveBoth"

VARIABLES balances, locks, pc, source, destination, transferAmount
vars == <<balances, locks, pc, source, destination, transferAmount>>

Init ==
    /\\ balances = [account \\in Accounts |-> 0]
    /\\ locks = [account \\in Accounts |-> 0]
    /\\ pc = [actor \\in Actors |-> Idle]
    /\\ source = [actor \\in Actors |-> 1]
    /\\ destination = [actor \\in Actors |-> 2]
    /\\ transferAmount = [actor \\in Actors |-> 1]

First(actor) == IF source[actor] < destination[actor] THEN source[actor] ELSE destination[actor]
Second(actor) == IF source[actor] < destination[actor] THEN destination[actor] ELSE source[actor]

BeginTransfer(actor, from, to, amount) ==
    /\\ actor \\in Actors
    /\\ pc[actor] = Idle
    /\\ from \\in Accounts
    /\\ to \\in Accounts
    /\\ from /= to
    /\\ amount \\in Amounts
    /\\ locks[IF from < to THEN from ELSE to] = 0
    /\\ source' = [source EXCEPT ![actor] = from]
    /\\ destination' = [destination EXCEPT ![actor] = to]
    /\\ transferAmount' = [transferAmount EXCEPT ![actor] = amount]
    /\\ locks' = [locks EXCEPT ![IF from < to THEN from ELSE to] = actor]
    /\\ pc' = [pc EXCEPT ![actor] = HaveFirst]
    /\\ UNCHANGED balances

AcquireSecond(actor) ==
    /\\ actor \\in Actors
    /\\ pc[actor] = HaveFirst
    /\\ locks[First(actor)] = actor
    /\\ locks[Second(actor)] = 0
    /\\ locks' = [locks EXCEPT ![Second(actor)] = actor]
    /\\ pc' = [pc EXCEPT ![actor] = HaveBoth]
    /\\ UNCHANGED <<balances, source, destination, transferAmount>>

CompleteTransfer(actor) ==
    /\\ actor \\in Actors
    /\\ pc[actor] = HaveBoth
    /\\ locks[First(actor)] = actor
    /\\ locks[Second(actor)] = actor
    /\\ transferAmount[actor] <= balances[source[actor]]
    /\\ balances[destination[actor]] + transferAmount[actor] <= MaxBalance
    /\\ balances' = [balances EXCEPT
          ![source[actor]] = @ - transferAmount[actor],
          ![destination[actor]] = @ + transferAmount[actor]]
    /\\ locks' = [locks EXCEPT ![First(actor)] = 0, ![Second(actor)] = 0]
    /\\ pc' = [pc EXCEPT ![actor] = Idle]
    /\\ UNCHANGED <<source, destination, transferAmount>>

RejectTransfer(actor) ==
    /\\ actor \\in Actors
    /\\ pc[actor] = HaveBoth
    /\\ \\/ transferAmount[actor] > balances[source[actor]]
       \\/ balances[destination[actor]] + transferAmount[actor] > MaxBalance
    /\\ locks' = [locks EXCEPT ![First(actor)] = 0, ![Second(actor)] = 0]
    /\\ pc' = [pc EXCEPT ![actor] = Idle]
    /\\ UNCHANGED <<balances, source, destination, transferAmount>>

Next ==
    \\/ \\E actor \\in Actors, from \\in Accounts, to \\in Accounts, amount \\in Amounts :
           BeginTransfer(actor, from, to, amount)
    \\/ \\E actor \\in Actors : AcquireSecond(actor)
    \\/ \\E actor \\in Actors : CompleteTransfer(actor)
    \\/ \\E actor \\in Actors : RejectTransfer(actor)

TypeOK ==
    /\\ balances \\in [Accounts -> 0..MaxBalance]
    /\\ locks \\in [Accounts -> Actors \\cup {{0}}]
    /\\ pc \\in [Actors -> {{Idle, HaveFirst, HaveBoth}}]
    /\\ source \\in [Actors -> Accounts]
    /\\ destination \\in [Actors -> Accounts]
    /\\ transferAmount \\in [Actors -> Amounts]
BalanceNonNegative == \\A account \\in Accounts : balances[account] >= 0
BalanceBounded == \\A account \\in Accounts : balances[account] <= MaxBalance
OrderedLocking == \\A actor \\in Actors : pc[actor] = HaveFirst => First(actor) < Second(actor)

Spec == Init /\\ [][Next]_vars
===="""
    invariant_names = [_INVARIANT_NAMES[name] for name in model.invariants]
    cfg = render_cfg(TLCConfig(invariants=invariant_names, check_deadlock=True))
    cfg += "\nINVARIANT OrderedLocking"
    return tla, cfg


def render_cfg(config: TLCConfig) -> str:
    lines = [f"SPECIFICATION {config.specification}"]
    lines.extend(f"INVARIANT {name}" for name in config.invariants)
    if not config.check_deadlock:
        lines.append("CHECK_DEADLOCK FALSE")
    return "\n".join(lines)


_FORBIDDEN_TLA = (
    "=== END ===", "SPECIFICATION ", "INVARIANT ", "public class",
    "//@", "#[requires", "#[ensures", "method ",
)


def preflight_tla(source: str) -> list[str]:
    """Reject cross-language/config contamination before invoking SANY/TLC."""
    errors: list[str] = []
    if not source.startswith("---- MODULE "):
        errors.append("missing TLA+ module header")
    if not source.rstrip().endswith("===="):
        errors.append("missing TLA+ module terminator")
    for token in _FORBIDDEN_TLA:
        if token in source:
            errors.append(f"forbidden module syntax: {token!r}")
    return errors
