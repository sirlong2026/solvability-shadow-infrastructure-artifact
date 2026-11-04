# Artifact — Solvability-Driven Inference of Shadow Infrastructure

Companion artifact for the manuscript submitted to **IEEE Transactions on Network
and Service Management**. Author: Wensheng Huang (Nanjing Open University).

## What this is

A self-contained, **redacted** reproduction bundle for the three empirical tiers
reported in the paper: a network-namespace testbed (S0-S7), a three-machine
external-validity run (X1), and public RIPE Atlas measurements. It contains the
verdict engine, pre-registered ground truths, sensor reports, grading CSVs,
figure audit readings, and a one-command number check.

## Quick start

```bash
python scripts/verify_numbers.py     # prints PASS for every headline number in the paper
python -m unittest discover -s tests # 29 semantics regression cases
```

`verify_numbers.py` uses the Python standard library only. The engine in
`engine/` likewise has no third-party dependency. Scripts under `scripts/` that
rebuild figures require matplotlib and are optional.

## Layout

| Path | Content |
|---|---|
| `engine/sensor_agent.py`, `sensor_compare.py` | Six-dimension observability gate, four-state verdict function, equivalence-class collapse |
| `scripts/evaluate.py` | Pre-registered `EXPECT` truths and grading of S0-S7 |
| `scripts/atlas_adapter.py` | RIPE Atlas result -> sensor bundle adapter; one-off vs recurring discipline |
| `scripts/baseline_compare.py`, `kappa_sweep.py` | Single-signal baselines; analytical kappa/lead sweep |
| `scripts/topo.sh`, `run.sh` | Testbed deployment and one-step grading |
| `tests/test_sensor_semantics.py` | 29 regression cases |
| `data/testbed/`, `data/x1/` | Redacted sensor JSON, compare JSON, grading CSV for all nine scenarios |
| `data/atlas/` | Judged summaries for four archival batches, k-root ping, and campaign 231739937 |
| `data/summary/` | Baseline comparison table and kappa sweep report |
| `data/figures/` | Reading-audit CSVs behind the three figures |
| `manifest.txt` | SHA-256 of every file |

## Redaction and compliance

- **Every public IPv4 literal is replaced with a semantic label** (`SENSOR_A`,
  `TARGET_B`, `PILOT_VIP`, `PUBLIC_ADDR_nn`). The campus landmark, the cloud
  pilot address, and all public RIPE Atlas destination addresses never appear.
- RFC1918 private addresses (`10.198.x.x`), loopback, and RFC5737 documentation
  addresses are **kept verbatim**: they are the internal numbering of the
  self-built network-namespace testbed, carry no asset information, and must
  stay literal for `topo.sh` / `run.sh` to execute. They are not real hosts.
- No credentials, API keys, host names, or personal data are included. Remote
  executors read addresses from environment variables only.
- No third-party product documentation is redistributed (the paper cites public
  product documentation for its replication target only).
- **No raw RIPE Atlas result files are included.** The archive exceeds 500 MB and
  is subject to RIPE NCC terms. Re-fetch the public measurements by their ids:

```bash
curl --compressed "https://atlas.ripe.net/api/v2/measurements/1002676/results/" -o google.json
curl --compressed "https://atlas.ripe.net/api/v2/measurements/1002725/results/" -o facebook.json
curl --compressed "https://atlas.ripe.net/api/v2/measurements/1006513/results/" -o tor.json
curl --compressed "https://atlas.ripe.net/api/v2/measurements/1007611/results/" -o ovh.json
curl --compressed "https://atlas.ripe.net/api/v2/measurements/1001/results/"     -o kroot.json
curl --compressed "https://atlas.ripe.net/api/v2/measurements/231739937/results/" -o campaign.json
```

`data/atlas/cam_231739937_index.json` keeps only non-address fields for the
257-result campaign; the full public result set is retrievable at the id above.

## Numbers reproduced

8/8 controlled scenarios; 9/9 matrix vs 6/9, 8/9, 8/9 single-signal baselines;
four archival certificate unions (1/1/2/3); 13,685 k-root vantages with
kappa = 1/6 refusal; campaign 231739937 with 257 results / 254 successful
handshakes, verdict `decidable c2`, certificate union = 2, kappa = 1/3, matching
all four pre-registered dimensions. Re-judging at 11, 244, and 254 samples gives
the identical verdict.

## License

Code: MIT. Data and documentation: CC BY 4.0. RIPE Atlas derived data remain
subject to the RIPE NCC terms of use; see the re-fetch commands above.

## Relationship to other work by the same author

This artifact belongs to a network-measurement study. It shares no data, code,
or results with the author's CTF-Oracle code-security benchmark or with the
84-cell educational-assessment matrix (cited in the paper as prior work).
