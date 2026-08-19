# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""M50: the IPC name server — the endpoint table as a deterministic gate.

The name server is the first user-space-facing service behind the M49
syscall boundary, and its table is decidable arithmetic (the
M39/M48/M49 family) BEFORE any message moves:

1. every endpoint id fits the SVC imm16 the boundary carries (an id
   hardware cannot encode is unreachable by construction);
2. ids and names are unique — two endpoints for one id (or one name)
   is a dispatch ambiguity, not a naming convenience;
3. an endpoint with fewer than two lanes is NOT MPSC — the multi-
   producer claim is vacuous for it and the gate refuses to mint;
4. capacity is statically partitioned: slots divide evenly across
   lanes (the provable MPSC shape — a shared-head enqueue has a real
   lost-update interleaving), each endpoint fits the message pool,
   and the SUM of all endpoints' slots never exceeds the pool — the
   (pool+1)-th message is rejected by arithmetic, not by hope;
5. CROSS-ARTIFACT ROUTING: every endpoint's declared syscall exists
   in the M49 dispatch table — an endpoint no declared syscall can
   reach is unreachable, and a route around the boundary table is a
   boundary bypass.

Honest scope: ``IPC_ENDPOINT_TABLE_PROVED`` is decidable arithmetic
over the declared table. The concurrency claim lives in the MPSC lane
(``MPSC_BOUNDED_PARTITION_PROVED`` via ESBMC over the witness); the
runtime sample (a user process sending through svc, backpressure
observed on emulated silicon) is ceilinged at RUNTIME_SAMPLE.
"""
from __future__ import annotations

_SVC_IMM16_MAX = 0xFFFF


def _fail(code: str, message: str, **extra) -> dict:
    return {"status": "IPC_TABLE_VERIFICATION_FAILED", "claim": "NO_PROOF",
            "code": code, "message": message, **extra}


def verify_ipc_table(artifact: dict,
                     syscall_artifact: dict | None = None) -> dict:
    """Prove the declared endpoint table is bounded, partitioned, and
    routed through the syscall boundary.

    artifact: {message_pool {capacity}, endpoints [{name, id, syscall,
    lanes, slots}]}. syscall_artifact: the M49 syscalls.json (required
    when any endpoint declares a route — the table never trusts a
    route it cannot check).
    """
    endpoints = artifact.get("endpoints")
    if not isinstance(endpoints, list) or not endpoints:
        return _fail("endpoints_missing",
                     "no endpoints declared — an empty name table "
                     "proves nothing about the service (vacuous), the "
                     "gate refuses it")
    pool = artifact.get("message_pool")
    if not isinstance(pool, dict) or not isinstance(pool.get("capacity"),
                                                    int) \
            or isinstance(pool.get("capacity"), bool) \
            or pool["capacity"] <= 0:
        return _fail("message_pool_invalid",
                     "message_pool {capacity} must be a positive integer "
                     "— the pool bound is a human declaration")

    declared_syscalls: set[int] = set()
    if syscall_artifact is not None:
        for entry in syscall_artifact.get("syscalls") or []:
            if isinstance(entry, dict) and isinstance(entry.get("id"),
                                                      int):
                declared_syscalls.add(entry["id"])

    seen_ids: set[int] = set()
    seen_names: set[str] = set()
    total_slots = 0
    for entry in endpoints:
        if not isinstance(entry, dict) \
                or not isinstance(entry.get("name"), str) \
                or not entry["name"] \
                or not isinstance(entry.get("id"), int) \
                or isinstance(entry.get("id"), bool) \
                or not isinstance(entry.get("lanes"), int) \
                or not isinstance(entry.get("slots"), int):
            return _fail("endpoint_field_invalid",
                         "each endpoint needs a name, an integer id, "
                         "lanes, and slots")
        if not 0 <= entry["id"] <= _SVC_IMM16_MAX:
            return _fail("ENDPOINT_ID_UNENCODABLE",
                         f"endpoint {entry['name']!r} id {entry['id']} "
                         "does not fit the SVC imm16 — an id hardware "
                         "cannot carry is unreachable by construction")
        if entry["id"] in seen_ids:
            return _fail("ENDPOINT_ID_CONFLICT",
                         f"endpoint id {entry['id']} declared twice — "
                         "two endpoints for one id is a dispatch "
                         "ambiguity")
        seen_ids.add(entry["id"])
        if entry["name"] in seen_names:
            return _fail("ENDPOINT_NAME_CONFLICT",
                         f"endpoint name {entry['name']!r} declared "
                         "twice — names are the addressing surface")
        seen_names.add(entry["name"])
        if entry["lanes"] < 2:
            return _fail("ENDPOINT_NOT_MPSC",
                         f"endpoint {entry['name']!r} has "
                         f"{entry['lanes']} lane(s) — a single-producer "
                         "endpoint is the SPSC shape; the MPSC claim "
                         "would be vacuous for it")
        if entry["slots"] < entry["lanes"]:
            return _fail("SLOTS_BELOW_LANES",
                         f"endpoint {entry['name']!r} has "
                         f"{entry['slots']} slots for {entry['lanes']} "
                         "lanes — a lane with no slot can never carry "
                         "a message")
        if entry["slots"] % entry["lanes"] != 0:
            return _fail("SLOT_PARTITION_UNEVEN",
                         f"endpoint {entry['name']!r}: {entry['slots']} "
                         f"slots do not divide evenly across "
                         f"{entry['lanes']} lanes — the static "
                         "partition must account for every slot")
        if entry["slots"] > pool["capacity"]:
            return _fail("ENDPOINT_SLOTS_EXCEED_POOL",
                         f"endpoint {entry['name']!r} declares "
                         f"{entry['slots']} slots but the message pool "
                         f"holds {pool['capacity']} — capacity is a "
                         "fact, not a hope")
        route = entry.get("syscall", entry["id"])
        if syscall_artifact is None:
            return _fail("ENDPOINT_SYSCALL_TABLE_MISSING",
                         f"endpoint {entry['name']!r} routes via "
                         f"syscall {route} but no dispatch table was "
                         "supplied — a route the gate cannot check is "
                         "a route it refuses")
        if route not in declared_syscalls:
            return _fail("ENDPOINT_SYSCALL_UNROUTED",
                         f"endpoint {entry['name']!r} routes via "
                         f"syscall {route} which the M49 dispatch "
                         "table does not declare — an endpoint around "
                         "the boundary is a boundary bypass")
        total_slots += entry["slots"]

    if total_slots > pool["capacity"]:
        return _fail("POOL_OVERSUBSCRIBED",
                     f"endpoints declare {total_slots} slots against a "
                     f"{pool['capacity']}-slot message pool — the "
                     "arithmetic closes before the silicon does: the "
                     "(pool+1)-th message is rejected by the table")
    return {
        "status": "IPC_ENDPOINT_TABLE_PROVED",
        "claim": "IPC_ENDPOINT_TABLE_PROVED",
        "scope": "deterministic_capacity_partition",
        "judge": "deterministic_gate",
        "endpoints_checked": len(endpoints),
        "message_pool_capacity": pool["capacity"],
        "total_slots": total_slots,
        "note": "the declared table is bounded, partitioned, and routed "
                "through the M49 syscall boundary by decidable "
                "arithmetic; the concurrency claim is the MPSC lane's "
                "(ESBMC witness); runtime backpressure is observed on "
                "QEMU, never proved here",
    }
