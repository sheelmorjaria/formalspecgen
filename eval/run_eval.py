"""Run the eval harness: generate a draft per gold case and score it.

Measures generation quality at max_attempts=1 by default (raw drafting, no repair loop);
pass --max-attempts N to measure the full loop. Reports check-pass rate, mean clause
token-F1, and mean LLM-judge semantic score.

Usage:
  python -m eval.run_eval
  python -m eval.run_eval --max-attempts 3
  python -m eval.run_eval --no-judge        # skip the LLM judge (faster, no extra tokens)
"""
import argparse
import json
import time
from pathlib import Path

from pipeline import orchestrator
from pipeline.llm import glm_judge
from eval import gold
from eval.metrics import extract_clauses, clause_overlap, check_pass


def run_one(case, max_attempts=1, judge=True):
    nl = case["nl"]
    out_dir = str(Path("runs/eval") / case["id"] / time.strftime("%Y%m%d-%H%M%S"))
    res = orchestrator.run(nl, max_attempts=max_attempts, out_dir=out_dir)
    stub = Path(res.stub_path).read_text() if res.stub_path and Path(res.stub_path).exists() else ""

    ok, errs = check_pass(stub)
    ov = clause_overlap(extract_clauses(case["gold"]), extract_clauses(stub))
    row = {
        "id": case["id"], "nl": nl,
        "check_pass": ok, "check_errors": errs[:5],
        "clause_recall": ov["recall"], "clause_precision": ov["precision"], "clause_f1": ov["f1"],
        "assumptions": res.assumptions, "missing_info": res.missing_info,
        "attempts": len(res.attempts), "gen_status": res.final_status,
        "stop_reason": res.stop_reason, "tokens": res.tokens.get("total", 0),
        "generated_stub": stub,
    }
    if judge:
        j = glm_judge(case["gold"], stub, nl)
        row["judge_score"] = j["score"]
        row["judge_verdict"] = j["verdict"]
        row["judge_missing"] = j["missing"]
        row["judge_extra"] = j["extra_or_wrong"]
    return row


def main():
    ap = argparse.ArgumentParser(description="formalspecgen eval harness")
    ap.add_argument("--max-attempts", type=int, default=1)
    ap.add_argument("--no-judge", action="store_true")
    args = ap.parse_args()

    print("=== validating gold stubs (must each pass openjml -check) ===")
    for c in gold.CASES:
        ok, errs = check_pass(c["gold"])
        print(f"  gold {c['id']:12s}: {'OK' if ok else 'BAD — ' + '; '.join(errs)}")
        if not ok:
            print("    (a failing gold reference invalidates the eval; fix the gold stub.)")

    rows = []
    print(f"\n=== running eval (max_attempts={args.max_attempts}, judge={'off' if args.no_judge else 'on'}) ===")
    for c in gold.CASES:
        t = time.time()
        row = run_one(c, max_attempts=args.max_attempts, judge=not args.no_judge)
        row["seconds"] = round(time.time() - t, 1)
        rows.append(row)
        js = f" judge={row['judge_score']:.2f}" if "judge_score" in row else ""
        print(f"  {c['id']:12s}: check={'Y' if row['check_pass'] else 'N'}  "
              f"clause_f1={row['clause_f1']:.2f}{js}  "
              f"({row['seconds']}s, {row['attempts']} att)")

    from collections import Counter
    n = len(rows)
    judged = [r for r in rows if "judge_score" in r]
    first_try = sum(1 for r in rows if r["attempts"] == 1)
    total_tok = sum(r.get("tokens", 0) for r in rows)
    verdicts = Counter(r.get("judge_verdict") for r in judged)
    agg = {
        "n": n, "max_attempts": args.max_attempts,
        "check_pass_rate": sum(r["check_pass"] for r in rows) / n,
        "mean_clause_f1": sum(r["clause_f1"] for r in rows) / n,
        "mean_judge_score": (sum(r["judge_score"] for r in judged) / len(judged)) if judged else None,
        "first_try_rate": first_try / n,
        "total_tokens": total_tok,
        "tokens_per_case": round(total_tok / n) if n else 0,
        "judge_verdict_counts": dict(verdicts),
        "gen_status_counts": dict(Counter(r["gen_status"] for r in rows)),
    }
    report = {"cases": rows, "aggregate": agg, "ts": time.strftime("%Y%m%d-%H%M%S")}
    outp = Path("eval/reports") / f"report_{report['ts']}.json"
    outp.parent.mkdir(parents=True, exist_ok=True)
    outp.write_text(json.dumps(report, indent=2, ensure_ascii=False))

    print("\n=== aggregate ===")
    print(f"  check_pass_rate  : {agg['check_pass_rate']:.0%}")
    print(f"  mean clause_f1   : {agg['mean_clause_f1']:.3f}")
    if agg["mean_judge_score"] is not None:
        print(f"  mean judge_score : {agg['mean_judge_score']:.3f}")
    print(f"  first_try_rate   : {agg['first_try_rate']:.0%}   tokens: {total_tok} ({agg['tokens_per_case']}/case)")
    if verdicts:
        print(f"  judge verdicts   : {dict(verdicts)}")
    print(f"  report           : {outp}")


if __name__ == "__main__":
    main()
