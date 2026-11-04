#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""baseline_compare.py —— 单信号基线 vs 可解性矩阵判定（S6 补强：§4.5 对照表）。

基线（"典型实践"：二值输出、无拒判、无诚实降级）：
  R_TTL   单信号 TTL 规则：合并两视角 ttl_set，>1 个不同 TTL ⇒ pool，否则 single。
  R_CERT  单信号证书规则：合并两视角 TLS 证书摘要集合，>1 ⇒ pool，否则 single。
  R_UNION 朴素跨视角：两视角各自按 (ttl∪cert) 多值判 pool/单值判 single，不一致 ⇒ pool。

对照：矩阵判定（s{i}_compare.json 的 four_state.V/winner，已对预注册 ground truth）。

评分维度（论文 §4.5 表）：
  A 后端结构命中   B 过度声明（S5 盲区：真值=至多一个后端，基线称 single host）
  C 影子轴漏检（S3 hidden hop / S7 chain / X1 隐身中间盒）
  D 拒判能力（kroot：κ=1/6 应拒；基线硬给 single = 过度声明）
  E Atlas 车队层分层正确性（含劫持标本处理）

纪律：基线只吃原始信号（ttl_set / cert hashes），不经矩阵的观测性闸；
     分数来自数据，不预设结论；判不中如实记录。
"""
import csv
import io
import json
import os
from collections import defaultdict

BASE = r"G:\ipsonar-verifier"
RUN_MAIN = os.path.join(BASE, "data", "lab20", "run_20261031_001555")   # S0-S6
RUN_S7 = os.path.join(BASE, "data", "lab20", "run_20261031_014938")     # S7
RUN_X1 = os.path.join(BASE, "data", "lab20", "x1")
OUT_CSV = os.path.join(BASE, "data", "lab20", "baseline_compare.csv")
OUT_MD = os.path.join(BASE, "data", "lab20", "baseline_compare.md")

# 预注册 ground truth（与论文 §4.2 tab:s0s7 一致；结构维度：single=单后端, pool=多后端）
TRUTH = {
    "S0": {"structure": "single", "blind_spot": False, "shadow": None,
           "note": "control"},
    "S1": {"structure": "pool", "blind_spot": False, "shadow": None,
           "note": "round-robin, two certs, shared kernel clock"},
    "S2": {"structure": "pool", "blind_spot": False, "shadow": None,
           "note": "source-sticky, two back ends"},
    "S3": {"structure": "single", "blind_spot": False, "shadow": "hidden_hop",
           "note": "hidden hop (iptables)"},
    "S4": {"structure": "pool", "blind_spot": False, "shadow": None,
           "note": "dual egress TTL 64/255"},
    "S5": {"structure": "at_most_one", "blind_spot": True, "shadow": None,
           "note": "principled blind spot: same cert, shared clock, sticky flows"},
    "S6": {"structure": "single", "blind_spot": False, "shadow": None,
           "note": "SNI front end, 3 certs, ONE back end box"},
    "S7": {"structure": "single", "blind_spot": False, "shadow": "chain",
           "note": "chained topology, sensor in path"},
    "X1": {"structure": "pool", "blind_spot": False, "shadow": "hidden_hop",
           "note": "RR two back ends + stealth middlebox on path"},
}


def load_scenario(run_dir, tag, sensor_files=None):
    """读 sens1/sens2 原始报告 + compare.json 的矩阵判定。
    只取场景主 target（compare.json targets[0].ip），避免把 landmark 探测混进信号。
    sensor_files: 覆盖默认 (sens1,sens2) 命名（X1 用 sLT/s34）。"""
    out = {"tag": tag}
    cp = os.path.join(run_dir, "%s_compare.json" % tag.lower())
    m = json.load(io.open(cp, encoding="utf-8"))
    fs = m["targets"][0]["four_state"]
    main_ip = m["targets"][0].get("ip")
    out["main_ip"] = main_ip
    ttls, certs = set(), set()
    view_calls = []
    for sen in (sensor_files or ("sens1", "sens2")):
        p = os.path.join(run_dir, "%s_%s.json" % (tag.lower(), sen) if sensor_files is None
                         else "%s.json" % sen)
        if not os.path.exists(p):
            raise FileNotFoundError("sensor report missing: %s" % p)  # 缺文件要炸，不许静默空转
        rep = json.load(io.open(p, encoding="utf-8"))
        calls = set()
        for t in rep.get("targets", []):
            if main_ip and t.get("ip") != main_ip:
                continue  # 只看本场景靶，landmark 等旁路目标不进基线信号
            tt = t.get("ttl") or {}
            ts_ = tt.get("ttl_set") or []
            ttls.update(ts_)
            calls.add("pool" if len(ts_) > 1 else "single")
            tls = t.get("tls") or {}
            # 注意：S1 双证书在 hashes 全列表里（unique_hashes 是计数），取 hashes 而非 unique；
            # per-view 判据必须用去重后的证书数（重复握手记录不是多证书）
            hs = tls.get("hashes") or []
            certs.update(hs)
            calls.add("pool" if len(set(hs)) > 1 else "single")
        view_calls.append(calls)
    out["ttl_set"] = sorted(ttls)
    out["cert_n"] = len(certs)
    if len(view_calls) == 2:
        a, b = view_calls
        merged = (a | b)
        if len(merged) == 1:
            out["union_call"] = next(iter(merged))
        else:
            out["union_call"] = "pool"  # 视角间不一致 ⇒ 朴素规则输出 pool
    else:
        out["union_call"] = "single"
    out["matrix_V"] = fs.get("V")
    out["matrix_winner"] = fs.get("winner")
    out["matrix_equiv"] = fs.get("equivalent") or []
    out["matrix_kappa"] = fs.get("kappa")
    out["matrix_aux"] = fs.get("aux") or {}
    return out


STRUCT_OF_WINNER = {
    "c2": "pool", "c3": "pool", "c4": "pool",   # 负载分担/粘性/多出口 ⇒ 多后端
    "c5": "single",                              # SNI 前端：一台盒子（判定更细，结构上单后端）
    "single": "single", "c1": "single", "c8": "at_most_one",
}


def matrix_structure(sc):
    """矩阵四态 → 后端结构维度（动作等价折算：single ≡ at_most_one）。"""
    eq = set(sc["matrix_equiv"] or [])
    if eq == {"c1", "c8"}:
        return "at_most_one"
    return STRUCT_OF_WINNER.get(sc["matrix_winner"], sc["matrix_winner"])


def baseline_calls(sc):
    """三条基线在原始信号上的输出（二值、永不拒判）。"""
    ttl_pool = len(sc["ttl_set"]) > 1
    cert_pool = sc["cert_n"] > 1
    return {
        "R_TTL": "pool" if ttl_pool else "single",
        "R_CERT": "pool" if cert_pool else "single",
        "R_UNION": sc["union_call"],
    }


def grade_structure(call, truth):
    """后端结构命中判定（S5 盲区按动作等价处理：single==at_most_one 视为命中但记过度声明）。"""
    if truth == "at_most_one":
        return ("hit" if call == "single" else "miss"), ("overclaim" if call == "single" else "")
    return ("hit" if call == truth else "miss"), ""


def main():
    rows = []
    scen = {}
    for tag in ("S0", "S1", "S2", "S3", "S4", "S5", "S6"):
        scen[tag] = load_scenario(RUN_MAIN, tag)
    scen["S7"] = load_scenario(RUN_S7, "S7")
    scen["X1"] = load_scenario(RUN_X1, "x1", sensor_files=("sLT", "s34"))

    tally = defaultdict(lambda: {"hit": 0, "miss": 0, "overclaim": 0, "shadow_miss": 0})
    for tag, sc in sorted(scen.items()):
        truth = TRUTH[tag]
        calls = baseline_calls(sc)
        m_struct = matrix_structure(sc)
        shadow_seen = bool(sc["matrix_aux"].get("hidden_router")) or bool(sc["matrix_aux"].get("chain"))
        row = {"scenario": tag, "truth_structure": truth["structure"],
               "truth_shadow": truth["shadow"] or "-",
               "matrix": m_struct + ("" if not shadow_seen else "(+shadow)"),
               "matrix_hit": ""}
        for name, call in calls.items():
            hit, over = grade_structure(call, truth["structure"])
            row[name] = call
            row[name + "_hit"] = hit
            tally[name]["hit" if hit == "hit" else "miss"] += 1
            if over:
                tally[name]["overclaim"] += 1
            row[name + "_note"] = over
        # 矩阵命中与影子轴（动作等价：single ≡ at_most_one 均为"至多一个后端"动作域）
        equiv_pair = {"single", "at_most_one"}
        m_hit = (m_struct == truth["structure"]) or (
            truth["structure"] in equiv_pair and m_struct in equiv_pair)
        row["matrix_hit"] = "hit" if m_hit else "miss"
        tally["MATRIX"]["hit" if m_hit else "miss"] += 1
        if truth["shadow"] and not shadow_seen:
            tally["MATRIX"]["shadow_miss"] += 1
            row["matrix_shadow_miss"] = 1
        else:
            row["matrix_shadow_miss"] = 0
        rows.append(row)

    # ---- 汇总表 ----
    methods = ["R_TTL", "R_CERT", "R_UNION", "MATRIX"]
    summary = []
    for mth in methods:
        t = tally[mth]
        summary.append({"method": mth,
                        "structure_hits": "%d/9" % t["hit"],
                        "overclaims_on_blind_spot": t["overclaim"],
                        "shadow_axis_capability": ("yes (aux axes)" if mth == "MATRIX"
                                                   else "none (binary output)")})
    # kroot 拒判维度（Atlas 层，结构化说明）
    kroot = {"method": "R_* vs MATRIX", "case": "k.root-servers.net (κ=1/6)",
             "baseline": "single host (hard over-claim from one TTL)",
             "matrix": "unobservable (honest refusal)"}
    atlas = {"method": "R_CERT vs MATRIX", "case": "facebook2012 fleet (3 certs)",
             "baseline": "pool (hijack specimen swallowed as another back-end cert)",
             "matrix": "fleet stats + cross-source check isolates resolver hijack"}

    # ---- 写 CSV/MD ----
    with io.open(OUT_CSV, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f, delimiter=";")
        w.writerow(["scenario", "truth_structure", "truth_shadow",
                    "R_TTL", "R_TTL_hit", "R_CERT", "R_CERT_hit",
                    "R_UNION", "R_UNION_hit", "MATRIX", "MATRIX_hit", "matrix_shadow_miss"])
        for r in rows:
            w.writerow([r["scenario"], r["truth_structure"], r["truth_shadow"],
                        r["R_TTL"], r["R_TTL_hit"], r["R_CERT"], r["R_CERT_hit"],
                        r["R_UNION"], r["R_UNION_hit"], r["matrix"], r["matrix_hit"],
                        r["matrix_shadow_miss"]])

    md = ["# 基线对照（单信号规则 vs 可解性矩阵）", ""]
    md.append("| scenario | truth | R_TTL | R_CERT | R_UNION | MATRIX |")
    md.append("|---|---|---|---|---|---|")
    for r in rows:
        md.append("| %s | %s%s | %s (%s) | %s (%s) | %s (%s) | %s (%s) |" % (
            r["scenario"], r["truth_structure"],
            "+shadow" if r["truth_shadow"] != "-" else "",
            r["R_TTL"], r["R_TTL_hit"], r["R_CERT"], r["R_CERT_hit"],
            r["R_UNION"], r["R_UNION_hit"], r["matrix"], r["matrix_hit"]))
    md.append("")
    md.append("## 汇总")
    md.append("")
    md.append("| method | structure hits (S0-S7+X1) | overclaims on blind spot | shadow axis |")
    md.append("|---|---|---|---|")
    for s in summary:
        md.append("| %s | %s | %s | %s |" % (s["method"], s["structure_hits"],
                                             s["overclaims_on_blind_spot"], s["shadow_axis_capability"]))
    md.append("")
    md.append("- kroot: %s vs %s" % (kroot["baseline"], kroot["matrix"]))
    md.append("- facebook2012: %s vs %s" % (atlas["baseline"], atlas["matrix"]))
    io.open(OUT_MD, "w", encoding="utf-8").write("\n".join(md))
    print("\n".join(md))
    print("\nCSV:", OUT_CSV)


if __name__ == "__main__":
    main()
