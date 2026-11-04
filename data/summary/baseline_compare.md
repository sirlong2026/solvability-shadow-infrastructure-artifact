# 基线对照（单信号规则 vs 可解性矩阵）

| scenario | truth | R_TTL | R_CERT | R_UNION | MATRIX |
|---|---|---|---|---|---|
| S0 | single | single (hit) | single (hit) | single (hit) | at_most_one (hit) |
| S1 | pool | single (miss) | pool (hit) | pool (hit) | pool (hit) |
| S2 | pool | single (miss) | pool (hit) | single (miss) | pool (hit) |
| S3 | single+shadow | single (hit) | single (hit) | single (hit) | at_most_one(+shadow) (hit) |
| S4 | pool | pool (hit) | single (miss) | pool (hit) | pool (hit) |
| S5 | at_most_one | single (hit) | single (hit) | single (hit) | at_most_one (hit) |
| S6 | single | single (hit) | single (hit) | single (hit) | single (hit) |
| S7 | single+shadow | pool (miss) | single (hit) | single (hit) | at_most_one(+shadow) (hit) |
| X1 | pool+shadow | pool (hit) | pool (hit) | pool (hit) | pool(+shadow) (hit) |

## 汇总

| method | structure hits (S0-S7+X1) | overclaims on blind spot | shadow axis |
|---|---|---|---|
| R_TTL | 6/9 | 1 | none (binary output) |
| R_CERT | 8/9 | 1 | none (binary output) |
| R_UNION | 8/9 | 1 | none (binary output) |
| MATRIX | 9/9 | 0 | yes (aux axes) |

- kroot: single host (hard over-claim from one TTL) vs unobservable (honest refusal)
- facebook2012: pool (hijack specimen swallowed as another back-end cert) vs fleet stats + cross-source check isolates resolver hijack