#!/usr/bin/env python3
"""Measure how often CVSS Temporal (v3.x) / Threat + Supplemental (v4.0) metrics are
actually populated in NVD records.

Serves assumption A5 of *Scored Once, Deployed Forever*: "the right factors exist but are
quarantined from the score". The plan asked for published population rates; none were
found in the literature, so this measures it directly against the authoritative source.

Usage:  python3 nvd_temporal_population.py [--start YYYY-MM-DD] [--end YYYY-MM-DD]

Method: pull pages of CVEs from the NVD REST API v2.0 for a publication window, parse
every CVSS vector string attached to each CVE, and count how many carry a NON-"X"
(i.e. actually assigned) value for each optional metric. Note that CVSS v4.0 vector
strings enumerate every metric including unset ones as ":X", so presence of the letter
in the vector is NOT evidence of population — the value must be checked.

No API key is required for modest use; NVD asks for <=5 requests per 30s without one.
"""
import json, re, sys, time, urllib.request, collections, argparse

API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def val(vec, m):
    g = re.search(r"/" + m + r":([^/]+)", vec)
    return g.group(1) if g else None

def fetch(start, end, idx, per=2000):
    url = (f"{API}?resultsPerPage={per}&startIndex={idx}"
           f"&pubStartDate={start}T00:00:00.000&pubEndDate={end}T23:59:59.999")
    with urllib.request.urlopen(url, timeout=180) as r:
        return json.load(r)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--start", default="2026-01-01")
    ap.add_argument("--end",   default="2026-03-31")
    ap.add_argument("--offsets", default="0,9000",
                    help="comma-separated startIndex values to sample")
    a = ap.parse_args()

    S = collections.Counter()
    Evals = collections.Counter()
    Esrc  = collections.Counter()
    cves  = 0

    for i, off in enumerate(int(x) for x in a.offsets.split(",")):
        if i: time.sleep(7)                       # be polite to NVD
        d = fetch(a.start, a.end, off)
        S["total_in_window"] = d.get("totalResults", 0)
        for v in d["vulnerabilities"]:
            cves += 1
            c = v["cve"]
            for _, arr in c.get("metrics", {}).items():
                for e in arr:
                    cd  = e.get("cvssData", {})
                    vec = cd.get("vectorString") or ""
                    ver = str(cd.get("version", "?"))
                    src = "NVD" if e.get("source") == "nvd@nist.gov" else "CNA"
                    if ver.startswith("3"):
                        S["v3_scores"] += 1
                        if any(val(vec, m) not in (None, "X") for m in ("E", "RL", "RC")):
                            S["v3_temporal_populated"] += 1
                    elif ver.startswith("4"):
                        S["v4_scores"] += 1
                        ev = val(vec, "E")
                        if ev not in (None, "X"):
                            S["v4_threat_E_populated"] += 1
                            Evals[ev] += 1; Esrc[src] += 1
                        if val(vec, "AU") not in (None, "X"): S["v4_automatable"] += 1
                        if val(vec, "RE") not in (None, "X"): S["v4_response_effort"] += 1

    def pct(x, n): return f"{100*x/n:.2f}%" if n else "n/a"
    print(f"Window {a.start}..{a.end}: {S['total_in_window']} CVEs in NVD; sampled {cves}\n")
    print(f"CVSS v3.x scores parsed:        {S['v3_scores']}")
    print(f"  Temporal (E/RL/RC) populated: {S['v3_temporal_populated']} "
          f"({pct(S['v3_temporal_populated'], S['v3_scores'])})")
    print(f"CVSS v4.0 scores parsed:        {S['v4_scores']}")
    print(f"  Threat  Exploit Maturity (E): {S['v4_threat_E_populated']} "
          f"({pct(S['v4_threat_E_populated'], S['v4_scores'])})")
    print(f"  Supplemental Automatable(AU): {S['v4_automatable']} "
          f"({pct(S['v4_automatable'], S['v4_scores'])})")
    print(f"  Supplemental Resp. Effort(RE):{S['v4_response_effort']} "
          f"({pct(S['v4_response_effort'], S['v4_scores'])})")
    print(f"\n  E values assigned: {dict(Evals)}")
    print(f"  E populated by:    {dict(Esrc)}")

if __name__ == "__main__":
    main()
