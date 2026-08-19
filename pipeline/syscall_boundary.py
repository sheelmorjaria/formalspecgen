# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""M49: the syscall boundary — the dispatch table as a deterministic gate.

User-space is a privilege transition, and the boundary is decidable
arithmetic BEFORE any silicon sees it:

1. the user image lives entirely inside the declared USER_FRAMES region
   and overlaps no kernel pool, DMA window, or declared kernel resource
   (the worst outcome — an image inside kernel memory IS the break — is
   checked first and names the range);
2. no kernel resource sits inside user frames — a "kernel resource" the
   user can already touch is not one;
3. every syscall carries an id the SVC instruction can encode (imm16),
   a named handler, and resource names that are kernel-owned: the user
   may NAME kernel resources through the table, never touch them;
4. ids are unique — two handlers for one id is a dispatch ambiguity.

Honest scope: ``SYSCALL_BOUNDARY_PROVED`` is decidable arithmetic over
the declared table and ranges — the same epistemic class as M48's
SPATIAL_ISOLATION_PROVED. It is NOT a proof that hardware performs the
EL1<->EL0 transition correctly; the live QEMU boot (unverified user
image, SVC answered, illegal kernel access from EL0 trapped and
contained) provides the runtime sample, ceilinged at RUNTIME_SAMPLE.
"""
from __future__ import annotations

_SVC_IMM16_MAX = 0xFFFF   # the SVC instruction carries a 16-bit immediate


def _fail(code: str, message: str, **extra) -> dict:
    return {"status": "SYSCALL_BOUNDARY_FAILED", "claim": "NO_PROOF",
            "code": code, "message": message, **extra}


def _overlaps(a: tuple[int, int], b: tuple[int, int]) -> bool:
    return a[0] < b[1] and b[0] < a[1]


def _contains(outer: tuple[int, int], inner: tuple[int, int]) -> bool:
    return outer[0] <= inner[0] and inner[1] <= outer[1]


def _span(raw) -> tuple[int, int] | None:
    if not isinstance(raw, (list, tuple)) or len(raw) != 2:
        return None
    try:
        span = (int(raw[0]), int(raw[1]))
    except (TypeError, ValueError):
        return None
    return span if span[0] < span[1] else None


def verify_syscall_boundary(artifact: dict) -> dict:
    """Prove the declared syscall table is a real privilege boundary.

    artifact: {memory_map (M48 family), user_image {start, end},
    kernel_resources {name: [start, end]}, syscalls [{id, name,
    handler, resources}]} — all human-owned declarations.
    """
    syscalls = artifact.get("syscalls")
    if not isinstance(syscalls, list) or not syscalls:
        return _fail("syscall_table_missing",
                     "no syscalls declared — an empty dispatch table "
                     "proves nothing about the boundary (vacuous), the "
                     "gate refuses it")

    image = artifact.get("user_image")
    if not isinstance(image, dict):
        return _fail("user_image_missing",
                     "user_image {start, end} is required — where the "
                     "unverified image will live is a human declaration")
    image_span = _span([image.get("start"), image.get("end")])
    if image_span is None:
        return _fail("user_image_invalid",
                     "user_image must be {start, end} with start < end")

    memory_map = artifact.get("memory_map")
    if not isinstance(memory_map, dict):
        return _fail("memory_map_incomplete",
                     "memory_map is required — the boundary is proved "
                     "against the declared physical map")
    pools = memory_map.get("kernel_pools")
    user = memory_map.get("user_frames")
    if not isinstance(pools, dict) or not pools:
        return _fail("memory_map_incomplete",
                     "kernel_pools ranges are required — isolation is "
                     "proved against declared kernel memory")
    user_span = _span(user)
    if user_span is None:
        return _fail("memory_map_incomplete",
                     "user_frames [start, end] with start < end is "
                     "required — user physical memory is a declaration")
    dma_windows = memory_map.get("dma_windows") or {}

    resources = artifact.get("kernel_resources")
    if not isinstance(resources, dict):
        return _fail("kernel_resources_missing",
                     "kernel_resources {name: [start, end]} is required — "
                     "a syscall may only name resources the kernel owns "
                     "by declaration")
    resource_spans: dict[str, tuple[int, int]] = {}
    for name, raw in resources.items():
        span = _span(raw)
        if span is None:
            return _fail("kernel_resources_invalid",
                         f"range for {name!r} must be [start, end] with "
                         "start < end")
        resource_spans[name] = span

    # the worst outcome FIRST: a user image inside kernel memory is the
    # isolation break itself, not merely a placement error
    kernel_spans: dict[str, tuple[int, int]] = {}
    for name, raw in {**pools, **dma_windows}.items():
        span = _span(raw)
        if span is None:
            return _fail("memory_map_incomplete",
                         f"range for {name!r} must be [start, end] with "
                         "start < end")
        kernel_spans[name] = span
    kernel_spans.update(resource_spans)
    for name, span in kernel_spans.items():
        if _overlaps(image_span, span):
            return _fail(
                "USER_IMAGE_OVERLAPS_KERNEL",
                f"user image [{image_span[0]:#x}, {image_span[1]:#x}) "
                f"overlaps {name} [{span[0]:#x}, {span[1]:#x})"
                " — the privilege boundary is broken before it exists",
                pool=name)
    if not _contains(user_span, image_span):
        return _fail("USER_IMAGE_OUTSIDE_USER_FRAMES",
                     f"user image [{image_span[0]:#x}, {image_span[1]:#x})"
                     f" is outside user_frames "
                     f"[{user_span[0]:#x}, {user_span[1]:#x}) — the "
                     "unverified image may only live in declared user "
                     "memory")
    for name, span in resource_spans.items():
        if _overlaps(span, user_span):
            return _fail("KERNEL_RESOURCE_IN_USER_REGION",
                         f"kernel resource {name!r} "
                         f"[{span[0]:#x}, {span[1]:#x}) lies inside "
                         f"user_frames [{user_span[0]:#x}, "
                         f"{user_span[1]:#x}) — a resource the user can "
                         "already touch is not a kernel resource")

    seen_ids: set[int] = set()
    checked = 0
    for entry in syscalls:
        if not isinstance(entry, dict):
            return _fail("syscall_field_invalid",
                         "each syscall must be an object with id/handler/"
                         "resources")
        sid = entry.get("id")
        handler = entry.get("handler")
        res = entry.get("resources")
        if not isinstance(sid, int) or isinstance(sid, bool) \
                or not isinstance(res, list) \
                or not all(isinstance(r, str) for r in res):
            return _fail("syscall_field_invalid",
                         "each syscall needs an integer id, a handler "
                         "name, and a list of resource names")
        if not isinstance(handler, str) or not handler:
            return _fail("HANDLER_MISSING",
                         f"syscall {sid} declares no handler — an id "
                         "with nothing to dispatch to is not a syscall")
        if not 0 <= sid <= _SVC_IMM16_MAX:
            return _fail("SYSCALL_ID_UNENCODABLE",
                         f"syscall id {sid} does not fit the SVC "
                         "instruction's imm16 — an id hardware cannot "
                         "carry can never be dispatched")
        if sid in seen_ids:
            return _fail("SYSCALL_ID_CONFLICT",
                         f"syscall id {sid} declared twice — two handlers "
                         "for one id is a dispatch ambiguity")
        seen_ids.add(sid)
        for name in res:
            if name not in resource_spans:
                return _fail("RESOURCE_NOT_KERNEL_OWNED",
                             f"syscall {sid} names resource {name!r} "
                             "which is not a declared kernel resource — "
                             "the user may only NAME kernel-owned "
                             "resources through the table")
        checked += 1

    return {
        "status": "SYSCALL_BOUNDARY_PROVED",
        "claim": "SYSCALL_BOUNDARY_PROVED",
        "scope": "deterministic_dispatch_table",
        "judge": "deterministic_gate",
        "syscalls_checked": checked,
        "syscall_ids": sorted(seen_ids),
        "user_image": [image_span[0], image_span[1]],
        "user_frames": [user_span[0], user_span[1]],
        "kernel_resources": {k: list(v) for k, v in resource_spans.items()},
        "judge_pending": "hardware_exception_level_transition",
        "note": "the declared table is a privilege boundary by decidable "
                "arithmetic (image placement, resource ownership, "
                "dispatch totality); the silicon EL1<->EL0 transition "
                "is observed at runtime (QEMU: SVC answered, EL0 "
                "kernel-access trapped), never proved here",
    }
