# Artifact: Governing Algorithmic Public Infrastructure (SaTML 2027)

Anonymous artifact for the position paper. It contains what is needed to check
the paper's empirical claims, and deliberately omits the attack pipeline (see
"Not included" and the paper's Open Science section).

## Layout

    prompts/     K0-K2 knowledge-level prompts (add before upload; see prompts/README.md)
    outcomes/    per-attempt outcome records for every reported run + aggregates
    scoring/     CVSS, NVD-population and CVSS-4.0-adoption scripts and their outputs
    figures/     figure sources (.tex/.dat/.pdf) for the paper's figures
    recompute.py recomputes the reported success counts from outcomes/*.csv

## outcomes/

CSV, one row per attempt. Columns: model, knowledge (K0-K3), level (L1/L2), rung,
system_variant, success, refused, engaged, stop_reason, status, model_error,
steps, token (task id), prompt_hash, tokens_in, tokens_out, usd, wall_s,
has_answer. A run is scored unless it hit the step limit or errored with no
answer; K* is the least level whose 95% Clopper-Pearson lower bound clears the
join-only null (join_null.txt). The model's free-text answers, the ballot
serials and the transcripts are not included.

  L1_gemini_family.csv   Fig. 3 / Table III: the flash line, K1/K2
  L1_gate_sanity.csv     Fig. 3: gemini-3.8-flash anchor; gpt-6-astra event-gate run
  L1_frontier.csv        App. B: gpt-6-astra and claude-opus-5, K0-K3 (20/level)
  L1_pro_isolated.csv    Fig. 6: the pro line
  L2_gwinnett.csv        Fig. 5: the harder audit-log join
  expA_pooled.json       ceiling run: 6,387/6,387 certain ballots, 0 wrong
  join_null.txt          the join-only nulls and the Gwinnett K* computation

Run `python3 recompute.py` (standard library only) to reproduce every count.

## scoring/

  cvss_scoring.py        recomputes each CVSS vector (needs the `cvss` PyPI package)
  cvss4_analysis.{json,txt}   its output: Fig. 4 and Table VI
  nvd_temporal_population.py   queries the NVD API; output nvd_population_full.txt
                               (0 of 18,596 v3.x scores carry a temporal metric)
  adoption.py            CVSS-4.0 adoption; output cvss_adoption.{json,txt}
                         The paper cites ONLY the NVD-assigned-4.0 count (zero).
                         The version-to-version "shift" rows are dominated by one
                         numbering authority and are not used as a finding.

## Not included

The reference recovery engine, the agent harness, the benchmark bundles, the K3
prompt, the agent transcripts, and the real voter rosters and cast-vote records.
The rosters and cast-vote records are public and obtainable from the county
sources the paper cites; the bundles preserve real ballot contents and order and
could be re-linked to them. The engine and the K3 prompt are available on request.
