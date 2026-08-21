# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""M54/M66 deployment profiles — one source tree, explicit boundaries.

The verified core (the C witnesses, the ESBMC/Prusti/Kani proofs, the
bounded pools) is deployment-agnostic: the math is true at EL1 and at
EL0 alike. What DIFFERS between a monolithic deployment (drivers
compiled in, direct calls) and a microkernel deployment (drivers at
EL0, svc + IPC) is the BOUNDARY — and only the boundary:

- a monolith mints the concurrency/capacity/composition claims but
  CANNOT mint SPATIAL_ISOLATION_PROVED, SYSCALL_BOUNDARY_PROVED, or
  the IPC endpoint table: the driver is inside the kernel, a driver
  fault IS a kernel fault, and there is no dispatch table to route;
- a microkernel mints everything above them.

This gate makes the omissions ENFORCED, not accidental: a manifest
that declares itself monolithic while carrying boundary artifacts is
a CONTRADICTION and refuses by name. A single repository can mint
both bundles from byte-identical witnesses; the shared claims are the
same (claim, scope, judge, source) tuples in both — the anti-drift
guarantee is structural, because both bundles are compiled from the
same lanes over the same files.
"""
from __future__ import annotations

# lanes whose artifacts assert a user/kernel boundary — meaningless
# (and unclaimable) when the driver is compiled into the kernel
BOUNDARY_LANES = {
    "mmu": "the frame map (SPATIAL_ISOLATION)",
    "syscalls": "the dispatch table (SYSCALL_BOUNDARY)",
    "ipc": "the endpoint table (IPC_ENDPOINT_TABLE routing)",
    "elf_loader": "the EL0 ELF loader (permission and process boundary)",
    "exception_transition": "the EL1/EL0 exception transition model",
    "user_heap": "the bounded EL0 process heap",
    "server_capabilities": "the EL0 multi-server capability table",
}

_VALID = ("monolithic", "microkernel", "unikernel")


def _fail(code: str, message: str, **extra) -> dict:
    return {"status": "DEPLOYMENT_PROFILE_INVALID", "claim": "NO_PROOF",
            "code": code, "message": message, **extra}


def verify_deployment_profile(manifest: dict) -> dict:
    """Check the manifest's declared deployment against the lanes it
    carries — the profile IS the honest scope."""
    deployment = manifest.get("deployment")
    if not deployment:
        return _fail(
            "deployment_missing",
            "the manifest declares no deployment profile — a kernel "
            "tree minting evidence must say monolithic, microkernel, or "
            "unikernel; the profile is what makes each bundle's "
            "omissions honest")
    if deployment not in _VALID:
        return _fail("deployment_unknown",
                     f"unknown deployment {deployment!r} — expected one "
                     f"of {_VALID}")
    if deployment in {"monolithic", "unikernel"}:
        carried = {lane: why for lane, why in BOUNDARY_LANES.items()
                   if manifest.get(lane) is not None}
        if carried:
            lanes = ", ".join(f"{lane} ({why})" for lane, why in
                              carried.items())
            return _fail(
                ("MONOLITH_BOUNDARY_CONTRADICTION" if deployment == "monolithic"
                 else "UNIKERNEL_BOUNDARY_CONTRADICTION"),
                f"a {deployment} deployment carries {lanes} — the driver "
                "is compiled in: a driver fault is a kernel fault, "
                "there is no user/kernel boundary to isolate or route "
                "through, and these claims cannot be minted. Drop the "
                "boundary lanes or declare microkernel; the profile "
                "refuses to overclaim")
    if deployment == "unikernel" and not manifest.get("unikernel_build"):
        return _fail("UNIKERNEL_BUILD_MISSING",
                     "a unikernel deployment must bind its feature-gated build manifest")
    return {
        "status": "DEPLOYMENT_PROFILE_OK",
        "deployment": deployment,
        "boundary_lanes": sorted(BOUNDARY_LANES) if deployment ==
        "microkernel" else [],
        "note": "microkernel: boundary lanes may be declared — the "
                "driver runs at EL0 behind the verified door" if
                deployment == "microkernel" else
                "unikernel: MMU, syscall, IPC, ELF, EL0 heap, and server "
                "capability boundaries are stripped; services execute as "
                "direct calls in one EL1 image" if deployment == "unikernel" else
                "monolithic: no boundary lane is claimable — the "
                "driver is the kernel; its concurrency, capacity, and "
                "composition claims stand, containment does not exist",
    }
