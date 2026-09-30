"""What DVSorder would score under CVSS 4.0, and why the version does not help.

CVE-2022-48506 was scored under CVSS 3.1 only (verified against the NVD record:
no ``cvssMetricV40`` entry exists). CVSS 4.0 is the obvious rejoinder to a paper
that criticises CVSS, so the question has to be answered directly: *would 4.0
have got this right?*

It would not, and the reasons are more interesting than the score. Three of
them, each attached to a number this module computes:

1. **The version is not the variable.** Translating the 2023 vector faithfully
   into 4.0 — same modelling choices, ``AV:P`` and a low confidentiality
   impact — returns **the same 2.4 Low**. Nothing in 4.0 disturbs it. The score
   never depended on the version; it depended on one judgment about what kind
   of thing this vulnerability is.

2. **CVSS models attacker-to-component interaction; this is
   attacker-to-artifact.** Attack Vector describes how an attacker reaches the
   *vulnerable component*. Here nobody reaches it: the scanner is untouched,
   and the attack consumes a file the scanner produced, published months later
   on a county website. ``AV:P`` is defensible under the specification and is
   still wrong by six points. That is a modelling gap, not a scoring mistake,
   and 4.0 did not close it. NVD's own record shows the strain — the prose says
   the flaw "allows anyone to determine the order in which ballots were cast
   from public ballot-level data" while the vector beside it says physical
   access.

3. **4.0 added exactly the right vocabulary and then declined to score it.**
   Safety, Automatable, Recovery, Value Density, Vulnerability Response Effort
   and Provider Urgency are *Supplemental* metrics: by specification they carry
   no numeric weight. For this vulnerability every one of them sits at its most
   severe setting, and the score does not move by a tenth of a point.
   ``R:I`` — Irrecoverable — is this paper's thesis expressed as a metric, and
   it is decorative.

A fourth failure is shared with EPSS and KEV and is worth stating separately:
the Threat metric ``E`` measures *observed* exploit maturity, so a vulnerability
whose exploitation emits no telemetry is scored **down**. ``E:U`` costs this
vulnerability 2.1 points. CISA's own SSVC assessment recorded exactly that
(``exploitation: none``), alongside ``automatable: no`` — a claim our own batch
runner refutes, having processed 112 counties from one script.
"""
import json

# The record as it stands, verified against the NVD API on 2026-09-10.
CVE = "CVE-2022-48506"
CVE_PUBLISHED = "2023-06-19"
CVE_LAST_MODIFIED = "2026-06-17"     # touched three years on; still 2.4
V31_VECTOR = "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
V31_SCORE = 2.4
HAS_V40_SCORE = False

# CISA SSVC v2.0.3, recorded 2025-01-02, role "CISA Coordinator".
SSVC = {
    "exploitation": "none",
    "automatable": "no",
    "technicalImpact": "partial",
}

_BASE_CORRECTED = ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/"
                   "VC:H/VI:N/VA:N/SC:N/SI:N/SA:N")

# Short labels for the figure axis; the long ones carry the prose.
SHORT = {
    "as scored, CVSS 3.1 (2023)": "3.1 · as scored, 2023",
    "the same reading, expressed in 4.0": "4.0 · same reading",
    "4.0, physical reading kept, impact corrected": "4.0 · impact corrected only",
    "4.0, corrected: reachable over the network": "4.0 · corrected (AV:N, VC:H)",
    "4.0, corrected + subsequent-system impact": "4.0 · + subsequent impact",
    "4.0, corrected + no observed exploitation (E:U)": "4.0 · + no observed exploit",
    "4.0, corrected + public exploit code (E:P)": "4.0 · + public exploit code",
    "4.0, corrected + every supplemental metric at its worst":
        "4.0 · + all supplemental maxed",
}

# Each entry: label, vector, and what the reader should take from it.
VARIANTS = [
    ("as scored, CVSS 3.1 (2023)", V31_VECTOR, "3.1",
     "the published score"),
    ("the same reading, expressed in 4.0",
     "CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N", "4.0",
     "upgrading the version changes nothing"),
    ("4.0, physical reading kept, impact corrected",
     _BASE_CORRECTED.replace("AV:N", "AV:P"), "4.0",
     "impact alone moves it 2.7 points"),
    ("4.0, corrected: reachable over the network",
     _BASE_CORRECTED, "4.0",
     "the files are downloaded, not touched in person"),
    ("4.0, corrected + subsequent-system impact",
     _BASE_CORRECTED.replace("SC:N", "SC:H"), "4.0",
     "the harmed party is not the scanner"),
    ("4.0, corrected + no observed exploitation (E:U)",
     _BASE_CORRECTED + "/E:U", "4.0",
     "invisibility is scored as safety"),
    ("4.0, corrected + public exploit code (E:P)",
     _BASE_CORRECTED + "/E:P", "4.0",
     "a PoC has existed since 2022"),
    ("4.0, corrected + every supplemental metric at its worst",
     _BASE_CORRECTED + "/S:P/AU:Y/R:I/V:C/RE:H/U:Red", "4.0",
     "six alarms, zero effect on the score"),
]

# The supplemental metrics, with the value this vulnerability earns.
SUPPLEMENTAL = [
    ("S", "Safety", "P — Present",
     "ballot secrecy protects against coercion and retaliation"),
    ("AU", "Automatable", "Y — Yes",
     "one script processed 112 counties; CISA recorded 'no'"),
    ("R", "Recovery", "I — Irrecoverable",
     "a disclosed ballot cannot be un-disclosed"),
    ("V", "Value Density", "C — Concentrated",
     "one download yields an entire county"),
    ("RE", "Response Effort", "H — High",
     "six institutional gates from vendor to polling place"),
    ("U", "Provider Urgency", "Red",
     "the highest urgency the metric can express"),
]


def score(vector):
    """Score a vector with the reference implementation."""
    if vector.startswith("CVSS:3"):
        from cvss import CVSS3
        c = CVSS3(vector)
        return float(c.scores()[0]), c.severities()[0]
    from cvss import CVSS4
    c = CVSS4(vector)
    return float(c.base_score), c.severity


def compute():
    rows = []
    for label, vector, version, takeaway in VARIANTS:
        s, sev = score(vector)
        rows.append({"label": label, "short": SHORT.get(label, label),
                     "vector": vector, "version": version,
                     "score": s, "severity": sev, "takeaway": takeaway})
    return {
        "cve": CVE,
        "published": CVE_PUBLISHED,
        "last_modified": CVE_LAST_MODIFIED,
        "scored_under_v40": HAS_V40_SCORE,
        "ssvc": SSVC,
        "variants": rows,
        "supplemental": [
            {"metric": m, "name": n, "value": v, "why": w}
            for m, n, v, w in SUPPLEMENTAL
        ],
        "supplemental_effect_on_score": 0.0,
    }


def render(d):
    L = []
    w = L.append
    w(f"{d['cve']} — published {d['published']}, last modified "
      f"{d['last_modified']}, never rescored.")
    w(f"Scored under CVSS 4.0: {'yes' if d['scored_under_v40'] else 'NO'}")
    w("")
    for r in d["variants"]:
        w(f"  {r['score']:5.1f}  {r['severity']:9s} {r['label']}")
        w(f"         {r['takeaway']}")
    w("")
    w("Supplemental metrics (CVSS 4.0) — none of these enters any score:")
    for s in d["supplemental"]:
        w(f"  {s['metric']:3s} {s['name']:30s} {s['value']:18s} {s['why']}")
    w(f"  → combined effect on the score: {d['supplemental_effect_on_score']:.1f}")
    w("")
    w("CISA SSVC v2.0.3 (2025-01-02):")
    for k, v in d["ssvc"].items():
        w(f"  {k:16s} {v}")
    w("  'automatable: no' is refuted by this project's own batch runner.")
    return "\n".join(L) + "\n"


if __name__ == "__main__":
    import argparse
    import os
    p = argparse.ArgumentParser()
    p.add_argument("--out", default="results/cvss4_analysis.json")
    a = p.parse_args()
    d = compute()
    os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
    with open(a.out, "w") as fh:
        json.dump(d, fh, indent=1)
    txt = os.path.splitext(a.out)[0] + ".txt"
    with open(txt, "w") as fh:
        fh.write(render(d))
    print(render(d))
    print(f"wrote {a.out} and {txt}")
