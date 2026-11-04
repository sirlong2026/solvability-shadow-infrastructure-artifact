# -*- coding: utf-8 -*-
"""verify_numbers.py — 一条命令核对论文全部头条数字（只读本包派生数据）。

用法：python scripts/verify_numbers.py
"""
import csv, io, json, os, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ok = True

def check(name, got, want):
    global ok
    good = got == want
    ok &= good
    print("%s  %-46s got=%-14s want=%s" % ("PASS" if good else "FAIL", name, got, want))

# 1) 基线对比 9 场景
p = ROOT / "data/summary/baseline_compare.csv"
rows = list(csv.DictReader(io.StringIO(p.read_text(encoding="utf-8-sig")), delimiter=";"))
check("baseline scenarios", len(rows), 9)
for col, want in [("R_TTL_hit", 6), ("R_CERT_hit", 8), ("R_UNION_hit", 8), ("MATRIX_hit", 9)]:
    check("baseline " + col, sum(r[col] == "hit" for r in rows), want)

# 2) 公开层档案批次
a = json.loads((ROOT / "data/atlas/atlas_judged.json").read_text(encoding="utf-8"))
by = {x["tag"]: x for x in a}
check("atlas batches", len(a), 5)
check("google2012 union", by["google2012"]["fleet"]["union_certs"], 1)
check("facebook2012 union", by["facebook2012"]["fleet"]["union_certs"], 3)
check("tor2013 union", by["torproject2013"]["fleet"]["union_certs"], 2)
check("ovh2013 union", by["ovh2013"]["fleet"]["union_certs"], 1)
check("kroot vantages", by["kroot-ping"]["probes_ok"], 13685)

# 3) campaign 结题四维
c = json.loads((ROOT / "data/atlas/cam_231739937_judged.json").read_text(encoding="utf-8"))
check("campaign msm", c["msm"], 231739937)
check("campaign results", c["samples"]["results"], 257)
check("campaign verdict", c["realized"]["V"], "决定可判")
check("campaign winner", c["realized"]["winner"], "c2")
check("campaign kappa", c["realized"]["kappa"], 0.333)
check("campaign cert union", c["fleet"]["union_certs"], 2)
check("campaign pre-registered match", all(c["match"].values()), True)

# 4) 回归用例数
t = (ROOT / "tests/test_sensor_semantics.py").read_text(encoding="utf-8")
import re
check("semantics regression cases", len(re.findall(r"def test\w+", t)), 29)

print("\nRESULT:", "ALL PASS" if ok else "FAILED")
sys.exit(0 if ok else 1)
