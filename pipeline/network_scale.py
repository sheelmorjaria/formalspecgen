import hashlib
import json
import shutil
import subprocess
from pathlib import Path


def _fail(code, message=""):
    return {"status": "NETWORK_SCALE_FAILED", "claim": "NO_PROOF", "code": code, "message": message}


def render_network_model(module):
    tla = f'''---- MODULE {module} ----
Principals == {{"tenant", "system"}}
Protocols == {{"IPv6_TCP", "IPv6_UDP"}}
Destinations == {{"public", "internal", "invalid"}}
States == {{"Idle", "Classified", "Forwarded", "Dropped", "Backpressured"}}
VARIABLES state, principal, protocol, destination, queueFull
vars == <<state, principal, protocol, destination, queueFull>>
Init == /\\ state = "Idle" /\\ principal = "tenant" /\\ protocol = "IPv6_TCP"
        /\\ destination = "invalid" /\\ queueFull = FALSE
Receive(p, proto, dst, full) == /\\ state = "Idle" /\\ p \\in Principals
 /\\ proto \\in Protocols /\\ dst \\in Destinations /\\ full \\in BOOLEAN
 /\\ state' = "Classified" /\\ principal' = p /\\ protocol' = proto
 /\\ destination' = dst /\\ queueFull' = full
Allowed == destination = "public" \\/ (principal = "system" /\\ destination = "internal")
Route == /\\ state = "Classified" /\\ Allowed /\\ ~queueFull
         /\\ state' = "Forwarded" /\\ UNCHANGED <<principal, protocol, destination, queueFull>>
Drop == /\\ state = "Classified" /\\ ~Allowed
        /\\ state' = "Dropped" /\\ UNCHANGED <<principal, protocol, destination, queueFull>>
Backpressure == /\\ state = "Classified" /\\ Allowed /\\ queueFull
                /\\ state' = "Backpressured" /\\ UNCHANGED <<principal, protocol, destination, queueFull>>
Next == (\\E p \\in Principals, proto \\in Protocols, dst \\in Destinations, full \\in BOOLEAN : Receive(p, proto, dst, full)) \\/ Route \\/ Drop \\/ Backpressure
TypeOK == /\\ state \\in States /\\ principal \\in Principals /\\ protocol \\in Protocols
          /\\ destination \\in Destinations /\\ queueFull \\in BOOLEAN
Firewall == state = "Forwarded" => Allowed
TerminalDecision == state = "Classified" => ENABLED Route \\/ ENABLED Drop \\/ ENABLED Backpressure
Spec == Init /\\ [][Next]_vars
====
'''
    cfg = "SPECIFICATION Spec\nINVARIANT TypeOK\nINVARIANT Firewall\nINVARIANT TerminalDecision\nCHECK_DEADLOCK FALSE\n"
    return tla, cfg


def verify_network_scale(path):
    path = Path(path)
    try:
        raw = path.read_bytes(); artifact = json.loads(raw)
        evidence = json.loads((path.parent / artifact["validation"]).read_text())
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return _fail("NETWORK_SCALE_ARTIFACT_INVALID", str(exc))
    partitions = artifact.get("queue_partitions")
    if partitions != {"tenant": [0, 1], "system": [2, 3]} or \
            artifact.get("queue_depth") != 64 or artifact.get("principal_quota") != 128 or \
            artifact.get("total_descriptors") != 256:
        return _fail("NETWORK_PARTITION_POLICY_INVALID")
    ceilings = ("full_ipv6_conformance_proved", "native_network_stack_refinement_proved",
                "physical_rss_msix_delivery_proved", "physical_packet_delivery_proved",
                "cryptographic_packet_authenticity_proved")
    if artifact.get("firewall_default") != "drop" or any(artifact.get(x) is not False for x in ceilings):
        return _fail("NETWORK_SCALE_EPISTEMIC_BOUNDARY_INVALID")
    tla, _ = render_network_model(artifact["module"]); tla_hash = hashlib.sha256(tla.encode()).hexdigest()
    if evidence.get("status") != "NETWORK_ROUTING_MODEL_PROVED" or evidence.get("tla_sha256") != tla_hash or evidence.get("deadlock_free") is not True:
        return _fail("NETWORK_TLC_EVIDENCE_BINDING_MISMATCH")
    z3 = shutil.which("z3")
    if z3 is None:
        return {"status": "judge_pending", "claim": "NO_PROOF", "code": "z3_unavailable", "judge_pending": "z3"}
    smt = """(set-logic QF_LIA)
(declare-const t0 Int)(declare-const t1 Int)(declare-const s2 Int)(declare-const s3 Int)
(assert (and (>= t0 0)(<= t0 64)(>= t1 0)(<= t1 64)(>= s2 0)(<= s2 64)(>= s3 0)(<= s3 64)))
(assert (or (> (+ t0 t1) 128) (> (+ s2 s3) 128) (> (+ t0 t1 s2 s3) 256)))
(check-sat)
"""
    run = subprocess.run([z3, "-in"], input=smt, capture_output=True, text=True, timeout=30)
    if run.returncode or run.stdout.strip() != "unsat":
        return _fail("NETWORK_PARTITION_COUNTEREXAMPLE", run.stdout)
    return {"status": "NETWORK_RESOURCE_PARTITION_PROVED", "claim": "NETWORK_RESOURCE_PARTITION_PROVED",
            "judge": "tlc+z3", "scope": "two_principal_ipv6_udp_tcp_four_queue_fabric",
            "artifact_sha256": hashlib.sha256(raw).hexdigest(), "tla_sha256": tla_hash,
            "smt_sha256": hashlib.sha256(smt.encode()).hexdigest(),
            "distinct_states": evidence.get("distinct_states"), "queue_count": 4,
            "deterministic_backpressure": True, **{x: False for x in ceilings}}
