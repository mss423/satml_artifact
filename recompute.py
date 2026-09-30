"""Recompute the success counts reported in the paper from outcomes/*.csv.

A run is *scored* unless it ended at the step limit without an answer
(truncated) or in a provider error; a scored run is a success when `success`
is True. Intervals are 95% Clopper-Pearson.  Run: python3 recompute.py
"""
import csv
from math import comb
from pathlib import Path

HERE = Path(__file__).parent / "outcomes"


def load(name):
    with open(HERE / f"{name}.csv") as fh:
        return list(csv.DictReader(fh))


def scored(r):
    if r["stop_reason"] == "max_steps" and r["has_answer"] == "False" and r["success"] != "True":
        return False
    if r["model_error"] == "True" and r["has_answer"] == "False" and r["stop_reason"] not in ("max_steps", "model_finished", "refused", "surrender"):
        return False
    return True


def cp_lower(k, n):
    if k == 0:
        return 0.0
    lo, hi = 0.0, 1.0
    for _ in range(100):
        p = (lo + hi) / 2
        if 1 - sum(comb(n, i) * p**i * (1 - p)**(n - i) for i in range(k)) < 0.025:
            lo = p
        else:
            hi = p
    return p


def cell(rows, model, k):
    rs = [r for r in rows if r["model"] == model and r["knowledge"] == k]
    sc = [r for r in rs if scored(r)]
    s = sum(r["success"] == "True" for r in sc)
    ref = sum(r["refused"] == "True" for r in rs)
    return s, len(sc), len(rs), ref


def show(label, rows, model, levels):
    for k in levels:
        s, n, a, ref = cell(rows, model, k)
        if a:
            print(f"  {label:26s} {k}: {s}/{n} scored ({a} attempted, {ref} refused), "
                  f"CP lower bound {100*cp_lower(s, n):.1f}%")


fam, gate = load("L1_gemini_family"), load("L1_gate_sanity")
print("Figure 3 / Table III (Heard, gemini flash line; join-only null 7.1%)")
for m in ["gemini-2.5-flash", "gemini-3-flash-preview", "gemini-3.5-flash",
          "gemini-3.6-flash", "gemini-3.7-flash"]:
    show(m, fam, m, ["K1", "K2"])
show("gemini-3.8-flash", gate, "gemini-3.8-flash", ["K1", "K2"])

print("\nFigure 5 (Gwinnett, gemini-3.8-flash; join-only null 3.4%)")
show("gemini-3.8-flash", load("L2_gwinnett"), "gemini-3.8-flash", ["K0", "K1", "K2", "K3"])

print("\nFigure 6 (pro line, dedicated run)")
pro = load("L1_pro_isolated")
for m in ["gemini-2.5-pro", "gemini-3.1-pro-preview"]:
    show(m, pro, m, ["K1", "K2"])

print("\nAppendix B-A (frontier models, main run and event-gate run)")
fr = load("L1_frontier")
for m in ["gpt-6-astra", "claude-opus-5"]:
    show(m + " (main)", fr, m, ["K0", "K1", "K2", "K3"])
show("gpt-6-astra (event gate)", gate, "gpt-6-astra", ["K1", "K2"])
