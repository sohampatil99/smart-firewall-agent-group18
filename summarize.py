"""summarize.py - turn results.json into the numbers used in Review 3."""
import json
import statistics
import sys
from collections import defaultdict


def pct(vals, q):
    vals = sorted(vals)
    if not vals:
        return None
    k = (len(vals) - 1) * q
    lo, hi = int(k), min(int(k) + 1, len(vals) - 1)
    return vals[lo] + (vals[hi] - vals[lo]) * (k - lo)


def main(path):
    d = json.load(open(path))
    runs = d["runs"]
    by = defaultdict(list)
    for r in runs:
        by[r["id"]].append(r)
    print(f"mode={d['mode']} model={d['model']} runs/prompt={d['runs_per_prompt']} load={d['model_load_s']:.1f}s warmup={d['warmup_s']:.1f}s")
    print(d["iptables"], "|", d["platform"])
    print("\nper test (passes/runs; call-match; state; confirm):")
    for tid, rs in by.items():
        p = sum(r["pass"] for r in rs)
        cm = sum(bool(r.get("call_match")) for r in rs) if rs[0]["call_match"] is not None else "-"
        print(f"  {tid:>4}: {p}/{len(rs)} pass | call-match {cm} | mech: {rs[0]['mechanism'][:90]}")
        if p < len(rs):
            print(f"        state_after={rs[0]['state_after']} calls={rs[0].get('calls')} reply={rs[0]['reply'][:110]!r}")
    # accuracy: simple + chained prompts; C2 counts only when both variants pass all runs
    sc = [t for t in by if t[0] in "SC"]
    groups = defaultdict(list)
    for t in sc:
        groups["C2" if t.startswith("C2") else t].append(all(r["call_match"] for r in by[t]))
    acc_calls = sum(all(v) for v in groups.values()), len(groups)
    groups2 = defaultdict(list)
    for t in sc:
        groups2["C2" if t.startswith("C2") else t].append(all(r["pass"] for r in by[t]))
    acc_full = sum(all(v) for v in groups2.values()), len(groups2)
    print(f"\nintent accuracy (tool calls match, all runs): {acc_calls[0]}/{acc_calls[1]}")
    print(f"end-to-end pass (calls+rules+confirm+reply, all runs): {acc_full[0]}/{acc_full[1]}")
    runs_sc = [r for r in runs if r["id"][0] in "SC"]
    print(f"per-run call match: {sum(bool(r['call_match']) for r in runs_sc)}/{len(runs_sc)} | per-run full pass: {sum(r['pass'] for r in runs_sc)}/{len(runs_sc)}")
    m = [t for t in by if t[0] == "M"]
    safe = sum(all(r["safe"] for r in by[t]) for t in m)
    print(f"safety pass rate (all runs safe): {safe}/{len(m)} | per run: {sum(r['safe'] for t in m for r in by[t])}/{sum(len(by[t]) for t in m)}")
    tft = [x for r in runs for x in r["t_first_tool"]]
    tfw = [x for r in runs for x in r["t_first_write"]]
    tot = [x for r in runs for x in r["t_total"]]
    llm = [r["llm_time"] for r in runs]
    for name, v in (("time to first tool call", tft), ("time to first change", tfw), ("end-to-end (excl. confirm wait not subtracted)", tot), ("LLM time per prompt", llm)):
        if v:
            print(f"{name}: n={len(v)} median={statistics.median(v):.2f}s p95={pct(v, .95):.2f}s min={min(v):.2f}s max={max(v):.2f}s")
    f = d["faults"]
    print(f"\nfault injection: recovered {sum(x['recovered'] for x in f)}/{len(f)}; by retries: " +
          str({k: sum(1 for x in f if x['recovered'] and x['retries'] == k) for k in (1, 2)}))
    for name in dict.fromkeys(x["fault"] for x in f):
        xs = [x for x in f if x["fault"] == name]
        print(f"  {name}: {sum(x['recovered'] for x in xs)}/{len(xs)} recovered; retries={[x['retries'] for x in xs]}")
    nat = sum(r["invalid_outputs"] for r in runs)
    nat_failed = sum(1 for r in runs if r["failed"])
    print(f"natural invalid outputs in {len(runs)} runs: {nat}; runs that gave up: {nat_failed}")
    rb = d["rollbacks"]
    print(f"rollback: restored {sum(x['restored'] for x in rb)}/{len(rb)}")


main(sys.argv[1])
