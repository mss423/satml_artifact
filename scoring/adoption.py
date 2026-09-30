"""Who actually scores under CVSS 4.0, and what changes when they do.

Two empirical questions sit behind "would CVSS 4.0 have caught DVSorder?", and
both are answerable from NVD rather than by argument.

**1. Has the authoritative scorer adopted 4.0?** The score anyone cites for a
CVE is the one NVD assigns. If NVD still assigns 3.1, then "the standard was
updated" and "deployed scores improved" are different claims, and only the
first is true. This module counts v4.0 entries by source.

**2. When a vulnerability is scored under both versions, which way does the
score move?** Thousands of CVEs now carry a CNA-assigned 4.0 vector alongside
NVD's 3.1. That is a natural experiment: for the same flaw, described the same
way, what does the version change buy? And in particular, what does it buy for
flaws shaped like DVSorder — confidentiality-only, no integrity or
availability impact?

This is stronger evidence than a hand-built counterfactual, because it does not
depend on our reading of any vector.
"""
import json
import os
import time
import urllib.request
from collections import Counter, defaultdict

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_SOURCE = "nvd@nist.gov"


def fetch_window(start, end, page_size=2000, max_pages=12, sleep=7.0):
    """Pull every CVE published in a date window."""
    out, index, pages = [], 0, 0
    while pages < max_pages:
        url = (f"{NVD_API}?pubStartDate={start}&pubEndDate={end}"
               f"&resultsPerPage={page_size}&startIndex={index}")
        with urllib.request.urlopen(url, timeout=120) as fh:
            data = json.load(fh)
        items = data.get("vulnerabilities", [])
        out.extend(items)
        total = data.get("totalResults", 0)
        index += page_size
        pages += 1
        if index >= total or not items:
            break
        time.sleep(sleep)
    return out


def _primary(entries, prefer_source=None):
    """Pick one scoring entry, preferring a named source."""
    if not entries:
        return None
    if prefer_source:
        for e in entries:
            if e.get("source") == prefer_source:
                return e
    return entries[0]


def analyse(items):
    """Adoption counts and the paired 3.1 <-> 4.0 comparison."""
    n = len(items)
    has31 = has40 = both = 0
    src40 = Counter()
    src31 = Counter()
    pairs = []

    for it in items:
        cve = it["cve"]
        m = cve.get("metrics", {})
        e31 = m.get("cvssMetricV31") or []
        e40 = m.get("cvssMetricV40") or []
        has31 += bool(e31)
        has40 += bool(e40)
        for e in e40:
            src40[e.get("source", "?")] += 1
        for e in e31:
            src31[e.get("source", "?")] += 1
        if not (e31 and e40):
            continue
        both += 1
        a = _primary(e31, NVD_SOURCE)
        b = _primary(e40)
        ad, bd = a.get("cvssData", {}), b.get("cvssData", {})
        if not (ad.get("baseScore") is not None
                and bd.get("baseScore") is not None):
            continue
        # Comparing NVD's 3.1 against a CNA's 4.0 confounds the version with
        # the scorer. Where one source published both, that pair isolates the
        # version change; those are flagged and analysed separately.
        same = None
        by_src31 = {e.get("source"): e for e in e31}
        for e in e40:
            twin = by_src31.get(e.get("source"))
            if twin:
                same = (twin, e)
                break
        rec = {
            "id": cve["id"],
            "v31_score": ad["baseScore"],
            "v31_vector": ad.get("vectorString", ""),
            "v31_source": a.get("source"),
            "v40_score": bd["baseScore"],
            "v40_vector": bd.get("vectorString", ""),
            "v40_source": b.get("source"),
            "same_source": False,
        }
        if same:
            t31, t40 = same[0]["cvssData"], same[1]["cvssData"]
            rec.update({
                "same_source": True,
                "same_source_name": same[0].get("source"),
                "ss_v31_score": t31.get("baseScore"),
                "ss_v31_vector": t31.get("vectorString", ""),
                "ss_v40_score": t40.get("baseScore"),
            })
        pairs.append(rec)

    return {
        "n_cves": n,
        "with_v31": has31,
        "with_v40": has40,
        "with_both": both,
        "v40_assigned_by_nvd": src40.get(NVD_SOURCE, 0),
        "v31_assigned_by_nvd": src31.get(NVD_SOURCE, 0),
        "v40_top_sources": src40.most_common(8),
        "pairs": pairs,
    }


def confidentiality_only(vector31):
    """Does the 3.1 vector look like DVSorder — confidentiality impact only?"""
    parts = dict(p.split(":", 1) for p in vector31.split("/")[1:]
                 if ":" in p)
    return (parts.get("C", "N") != "N"
            and parts.get("I", "N") == "N"
            and parts.get("A", "N") == "N")


def shift_summary(pairs):
    """How the score moves from 3.1 to 4.0, overall and for DVSorder-shaped flaws."""
    def stats(rows):
        if not rows:
            return None
        deltas = [r["v40_score"] - r["v31_score"] for r in rows]
        deltas.sort()
        n = len(deltas)
        return {
            "n": n,
            "mean_delta": round(sum(deltas) / n, 3),
            "median_delta": round(deltas[n // 2], 3),
            "pct_higher_under_40": round(
                100.0 * sum(1 for d in deltas if d > 0) / n, 1),
            "pct_lower_under_40": round(
                100.0 * sum(1 for d in deltas if d < 0) / n, 1),
            "pct_unchanged": round(
                100.0 * sum(1 for d in deltas if d == 0) / n, 1),
        }

    conf_only = [r for r in pairs if confidentiality_only(r["v31_vector"])]
    low31 = [r for r in pairs if r["v31_score"] < 4.0]

    # Same-source pairs isolate the version change from the scorer.
    ss = [dict(r, v31_score=r["ss_v31_score"], v40_score=r["ss_v40_score"],
               v31_vector=r["ss_v31_vector"])
          for r in pairs if r.get("same_source")
          and r.get("ss_v31_score") is not None
          and r.get("ss_v40_score") is not None]
    ss_conf = [r for r in ss if confidentiality_only(r["v31_vector"])]
    ss_low = [r for r in ss if r["v31_score"] < 4.0]

    return {
        "all": stats(pairs),
        "confidentiality_only": stats(conf_only),
        "scored_low_under_31": stats(low31),
        "low_and_confidentiality_only": stats(
            [r for r in conf_only if r["v31_score"] < 4.0]),
        "SAME-SOURCE all": stats(ss),
        "SAME-SOURCE confidentiality_only": stats(ss_conf),
        "SAME-SOURCE scored_low_under_31": stats(ss_low),
        "SAME-SOURCE low_and_conf_only": stats(
            [r for r in ss_conf if r["v31_score"] < 4.0]),
    }


def run(start="2026-03-01T00:00:00.000", end="2026-08-31T23:59:59.000",
        out_path="results/cvss_adoption.json"):
    # NVD caps a single date query at 120 days, so the window is walked in
    # month-sized chunks.
    import datetime as _dt
    s_dt = _dt.datetime.fromisoformat(start)
    e_dt = _dt.datetime.fromisoformat(end)
    items, cur = [], s_dt
    while cur < e_dt:
        nxt = min(e_dt, cur + _dt.timedelta(days=30))
        items.extend(fetch_window(cur.isoformat(timespec="milliseconds"),
                                  nxt.isoformat(timespec="milliseconds")))
        cur = nxt
        time.sleep(7.0)
    a = analyse(items)
    a["window"] = [start, end]
    a["shift"] = shift_summary(a["pairs"])
    if out_path:
        os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
        with open(out_path, "w") as fh:
            json.dump(a, fh, indent=1)
    return a


def render(a):
    L = []
    w = L.append
    w(f"CVEs published {a['window'][0][:10]} .. {a['window'][1][:10]}: "
      f"{a['n_cves']:,}")
    w("")
    w(f"  carry a CVSS 3.1 score : {a['with_v31']:,} "
      f"({100.0*a['with_v31']/a['n_cves']:.0f}%)")
    w(f"  carry a CVSS 4.0 score : {a['with_v40']:,} "
      f"({100.0*a['with_v40']/a['n_cves']:.0f}%)")
    w(f"  carry both             : {a['with_both']:,}")
    w("")
    w(f"  CVSS 3.1 assigned by NVD itself : {a['v31_assigned_by_nvd']:,}")
    w(f"  CVSS 4.0 assigned by NVD itself : {a['v40_assigned_by_nvd']:,}")
    w("")
    w("  who assigns 4.0:")
    for src, n in a["v40_top_sources"]:
        w(f"    {n:5,}  {src}")
    w("")
    w("When the same CVE carries both versions, the score moves:")
    for label, s in a["shift"].items():
        if not s:
            continue
        w(f"  {label:28s} n={s['n']:5,}  mean {s['mean_delta']:+.2f}  "
          f"median {s['median_delta']:+.2f}  "
          f"higher {s['pct_higher_under_40']:.0f}% / "
          f"lower {s['pct_lower_under_40']:.0f}% / "
          f"same {s['pct_unchanged']:.0f}%")
    return "\n".join(L) + "\n"


if __name__ == "__main__":
    a = run()
    print(render(a))
    txt = "results/cvss_adoption.txt"
    with open(txt, "w") as fh:
        fh.write(render(a))
    print(f"wrote results/cvss_adoption.json and {txt}")
