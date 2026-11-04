#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""atlas_adapter.py —— RIPE Atlas 公开测量数据 → sensor-report/v1 束 → 四态判卷。

定位（B 线论文 §4 外部效度的公开平台补强）：
  把 RIPE Atlas 公开测量结果适配进 sensor_compare.read_O/decide_formal，
  在真实互联网目标上运行同一套判定函数，并输出判卷 CSV + 车队级统计。

方法学纪律（与引擎诚实性规则同源）：
  1. **formal 批次**（recurring，逐探针 ≥3 轮成功握手）才允许进入四态判卷——
     one-off 快照每视角只有 1 次握手，撑不起 o₃ 观测性闸（len(hashes)>=3），
     只做车队级描述统计（跨视角证书并集/异样率），不出 V 判定；
  2. o₂（时钟偏移簇）在 Atlas 上**结构性不可观测**（平台无 ICMP Timestamp 探测），
     束中不设 o₂ 数据 → 诚实降级为 unobservable，绝不假装阴性；
  3. 长基线证书比较 ≠ 后端轮换（证书月级续期是生命周期事件）——适配器只在
     ≤48h 短窗内做轮换判定，跨月/跨年对比仅作生命周期对照，不入 o₃；
  4. 零 IP/凭据落盘纪律照旧：本脚本只读公开测量结果，不含任何私有地址。

用法：
    python atlas_adapter.py                 # 全批次处理
    python atlas_adapter.py --tag kroot     # 只跑指定批次

输出：
    G:\\ipsonar-verifier\\data\\atlas\\atlas_judged.json   # 全部判定与统计
    G:\\ipsonar-verifier\\data\\atlas\\atlas_judged.csv    # 判卷留痕（逐行）
"""

import argparse
import base64
import csv
import hashlib
import json
import os
import sys
from collections import defaultdict

BASE = r"G:\ipsonar-verifier"
RAW = os.path.join(BASE, "data", "atlas", "raw")
OUT_JSON = os.path.join(BASE, "data", "atlas", "atlas_judged.json")
OUT_CSV = os.path.join(BASE, "data", "atlas", "atlas_judged.csv")
sys.path.insert(0, os.path.join(BASE, "ipsonar-neo", "tools"))
import sensor_compare  # noqa: E402  (判定引擎，单源不复制)

# ---------------------------------------------------------------- 批次登记 ---- #
# kind: sslcert_recurring（走 formal 四态） / sslcert_snapshot（one-off，车队统计）
#       / ping_recurring（o₁ 正式判定）
BATCHES = [
    dict(tag="google2012", kind="sslcert_snapshot", msm=1002676,
         target="www.google.com", file="test_1002676.json",
         prior="超大规模多前端服务（公开事实）；2012 快照，Atlas 保留部分结果"),
    dict(tag="facebook2012", kind="sslcert_snapshot", msm=1002725,
         target="www.facebook.com", file="fb2012_gz.json",
         prior="超大规模多前端服务（公开事实）；2012 快照"),
    dict(tag="torproject2013", kind="sslcert_snapshot", msm=1006513,
         target="www.torproject.org", file="tor_gz.json",
         prior="镜像分发集群（公开事实）；2013 批次（_interval 累积 64k 结果）"),
    dict(tag="ovh2013", kind="sslcert_snapshot", msm=1007611,
         target="www.ovh.com", file="snap_1007611_ovh_2013.json",
         prior="主机商多前端（公开事实）；2013 快照"),
    dict(tag="kroot-ping", kind="ping_recurring", msm=1001,
         target="k.root-servers.net", file="kroot_gz.json",
         prior="根服务器 anycast（公开事实）；30min 固定窗，约 1.4 万视角×7.5 轮"),
    # 2026-11-01 检索结论：2015 年 th-mon-run2 之后无存活的公开大规模
    # recurring 证书战役（其 67/32 探针集 2025/2026 全 timeout）——
    # o₃ 时间轮换维度在公开平台复用数据上结构性缺失，进论文观察。
]

WINDOW_NOTE = ("Atlas 适配：o₂ 平台无 ICMP Timestamp → 结构性 unobservable；"
               "o₅ 无路径探测 → unobservable；o₃/o₆ 仅在短窗（≤48h）内判定")


# ---------------------------------------------------------------- 证书摘要 ---- #
def _leaf_hash(pem_or_der):
    """PEM 或裸 base64 DER → 叶证书 SHA-256 前 16 hex。与引擎“证书摘要”同义。"""
    s = pem_or_der.strip()
    if "-----BEGIN" in s:
        body = "".join(ln for ln in s.splitlines() if "-----" not in ln)
    else:
        body = s
    der = base64.b64decode(body)
    return hashlib.sha256(der).hexdigest()[:16]


def load_json_checked(path, tag):
    """带截断检测的加载：Atlas 大结果集可能传输中断（截断 JSON 明确报错拒用）。"""
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except json.JSONDecodeError as e:
        raise SystemExit(f"[拒用] {tag}：{os.path.basename(path)} JSON 截断（{e}）——"
                         f"请续传或重下后重跑")


def aggregate_certs(data):
    """{prb: {"hashes":[(ts,hash)], "dst_ips":set, "err":n}} 按探针聚合。"""
    per = defaultdict(lambda: {"hashes": [], "dst_ips": set(), "err": 0})
    for r in data:
        p = per[r["prb_id"]]
        if "cert" in r and r["cert"]:
            try:
                p["hashes"].append((r["timestamp"], _leaf_hash(r["cert"][0])))
                p["dst_ips"].add(r.get("dst_addr"))
            except Exception:
                p["err"] += 1
        else:
            p["err"] += 1
    return per


def build_cert_bundle(tag, entry, sni_map=None):
    """一个探针的证书观测 → sensor-report/v1 束（o₃/o₆ 部分）。"""
    hashes = [h for _, h in sorted(entry["hashes"])]
    gate_o3 = len(hashes) >= 3
    return {
        "schema": "sensor-report/v1",
        "probe": tag,
        "ttl": {"supported": False, "samples": 0, "ttl_set": []},
        "skew": {"supported": False, "points": []},
        "tls": {"supported": bool(hashes), "hashes": hashes,
                "sni_map": sni_map or {}},
        "path": {"hops": []},
        "gate": {
            "o1": {"observable": False, "reason": "无 ping 数据（cert 批次）"},
            "o2": {"observable": False, "reason": "Atlas 无 ICMP Timestamp 探测"},
            "o3": {"observable": gate_o3,
                   "reason": "" if gate_o3 else f"成功握手 {len(hashes)} < 3"},
            "o4": {"observable": bool(sni_map and len(sni_map) >= 2),
                   "reason": "" if sni_map else "无同 IP 双 SNI 观测"},
            "o5": {"observable": False, "reason": "无路径探测数据"},
        },
    }


def build_ping_bundle(tag, ttl_set, samples):
    """一个探针的 ping 观测 → 束（o₁ 部分）。"""
    ok = bool(ttl_set) and samples >= 4
    return {
        "schema": "sensor-report/v1",
        "probe": tag,
        "ttl": {"supported": ok, "samples": samples, "ttl_set": sorted(ttl_set)},
        "skew": {"supported": False, "points": []},
        "tls": {"supported": False, "hashes": [], "sni_map": {}},
        "path": {"hops": []},
        "gate": {
            "o1": {"observable": ok,
                   "reason": "" if ok else f"回包样本 {samples} < 4 或无回包"},
            "o2": {"observable": False, "reason": "Atlas 无 ICMP Timestamp 探测"},
            "o3": {"observable": False, "reason": "无 TLS 数据"},
            "o4": {"observable": False, "reason": "无 TLS 数据"},
            "o5": {"observable": False, "reason": "无路径探测数据"},
        },
    }


# ---------------------------------------------------------------- 批次处理 ---- #
def pick_pair(per):
    """选代表探针对：成功轮次 ≥3 的探针里按 (轮次降序, prb_id 升序) 取前二。"""
    ok = [(prb, len(e["hashes"])) for prb, e in per.items() if len(e["hashes"]) >= 3]
    ok.sort(key=lambda x: (-x[1], x[0]))
    return [prb for prb, _ in ok[:2]]


def run_sslcert_recurring(b):
    """recurring 证书批次：代表探针对 → 四态判卷 + 车队并集统计。"""
    path = os.path.join(RAW, b["file"])
    data = load_json_checked(path, b["tag"])
    per = aggregate_certs(data)
    pair = pick_pair(per)
    row = {"tag": b["tag"], "msm": b["msm"], "target": b["target"],
           "kind": b["kind"], "prior": b.get("prior", ""),
           "probes_ok": sum(1 for e in per.values() if e["hashes"]),
           "results_total": len(data), "pair": pair, "note": WINDOW_NOTE}
    if len(pair) == 2:
        a = build_cert_bundle(f"{b['tag']}#prb{pair[0]}", per[pair[0]])
        bb = build_cert_bundle(f"{b['tag']}#prb{pair[1]}", per[pair[1]])
        verdict = sensor_compare.decide_formal(a, bb)
        row["verdict"] = verdict
    union = set()
    for e in per.values():
        union |= {h for _, h in e["hashes"]}
    n_probes_multi = sum(1 for e in per.values() if len({h for _, h in e["hashes"]}) >= 2)
    n_probes_ok = sum(1 for e in per.values() if e["hashes"])
    row["fleet"] = {"union_certs": len(union), "probes_with_cert": n_probes_ok,
                    "probes_multi_cert_48h": n_probes_multi,
                    "o3_positive_rate": round(n_probes_multi / n_probes_ok, 3) if n_probes_ok else None,
                    "dst_ips": sorted({ip for e in per.values() for ip in e["dst_ips"]})[:10]}
    return row


def run_sslcert_snapshot(b):
    """one-off 快照：只做车队统计（跨视角并集/异样率），不出 V 判定。"""
    path = os.path.join(RAW, b["file"])
    data = load_json_checked(path, b["tag"])
    per = aggregate_certs(data)
    union, by_cert = set(), defaultdict(int)
    for e in per.values():
        for _, h in e["hashes"]:
            union.add(h)
            by_cert[h] += 1
    row = {"tag": b["tag"], "msm": b["msm"], "target": b["target"],
           "kind": b["kind"], "prior": b.get("prior", ""),
           "results_total": len(data),
           "probes_ok": sum(1 for e in per.values() if e["hashes"]),
           "note": "one-off 快照：每视角 1 次握手，不进四态判卷（o₃ 闸），仅车队统计"}
    # 证书身份 ⊗ 目的地址池 一致性（野外伪像检出：个别视角被中间盒/本地解析
    # 静默换标——其证书与主流证书不同且集中于单一地址）。取 top8 证书的池画像。
    ips_by_cert, prb_by_cert = defaultdict(set), defaultdict(set)
    for prb, e in per.items():
        for _, h in e["hashes"]:
            ips_by_cert[h] |= e["dst_ips"]
            prb_by_cert[h].add(prb)
    pool = [{"hash": h, "n_obs": by_cert[h], "n_probes": len(prb_by_cert[h]),
             "dst_ips": sorted(ips_by_cert[h])[:6]}
            for h, _ in sorted(by_cert.items(), key=lambda x: -x[1])[:8]]
    row["fleet"] = {"union_certs": len(union),
                    "cert_share": sorted(by_cert.values(), reverse=True)[:5],
                    "cert_pools": pool,
                    "dst_ips": sorted({ip for e in per.values() for ip in e["dst_ips"]})[:10]}
    return row


def run_ping_recurring(b):
    """recurring ping 批次：逐探针 TTL → o₁ 正式判定（预期 κ<1/3 诚实拒判）。

    TTL 取样规则（2026-11-02 真机数据修正）：**一律取结果对象顶层 ttl**
    （Atlas ping 顶层 ttl = 本轮最后一个回包的 IP TTL，跨固件语义一致）。
    回包级 ttl 字段仅作固件一致性观察：个别固件将其写成 1..59 奇数步进序列
    （非 IP TTL），若按回包级取样会让伪像探针样本数膨胀并污染视角选择——
    这本身构成 RQ4 主题（观测手段自身偏差）的公开平台例证。
    """
    path = os.path.join(RAW, b["file"])
    data = load_json_checked(path, b["tag"])
    per = defaultdict(lambda: {"ttl": [], "dst": set()})
    n_rep_field = 0
    for r in data:
        p = per[r["prb_id"]]
        p["dst"].add(r.get("dst_addr"))
        if any(isinstance(rep, dict) and rep.get("ttl")
               for rep in (r.get("result") or [])):
            n_rep_field += 1
        if r.get("ttl"):
            p["ttl"].append((r["timestamp"], r["ttl"]))
    ok = sorted(((prb, len(e["ttl"])) for prb, e in per.items() if len(e["ttl"]) >= 4),
                key=lambda x: (-x[1], x[0]))
    row = {"tag": b["tag"], "msm": b["msm"], "target": b["target"],
           "kind": b["kind"], "prior": b.get("prior", ""),
           "results_total": len(data),
           "probes_ok": len(ok), "pair": [prb for prb, _ in ok[:2]],
           "note": WINDOW_NOTE}
    if len(ok) >= 2:
        p1, p2 = per[ok[0][0]], per[ok[1][0]]
        a = build_ping_bundle(f"{b['tag']}#prb{ok[0][0]}", {t for _, t in p1["ttl"]}, len(p1["ttl"]))
        bb = build_ping_bundle(f"{b['tag']}#prb{ok[1][0]}", {t for _, t in p2["ttl"]}, len(p2["ttl"]))
        row["verdict"] = sensor_compare.decide_formal(a, bb)
        n_multi = sum(1 for e in per.values()
                      if len({t for _, t in e["ttl"]}) >= 2)
        n_dstchg = sum(1 for e in per.values() if len(e["dst"]) >= 2)
        row["fleet"] = {
            "ttl_set_prbA": sorted({t for _, t in p1["ttl"]}),
            "ttl_set_prbB": sorted({t for _, t in p2["ttl"]}),
            "dst_change_prbA": sorted(p1["dst"])[:4],
            "probes_ttl_multi": n_multi,
            "probes_dst_change": n_dstchg,
            "results_with_reply_ttl_field": n_rep_field,
            "ttl_source": "顶层 ttl（最后回包 IP TTL）",
        }
    return row


RUNNERS = {"sslcert_recurring": run_sslcert_recurring,
           "sslcert_snapshot": run_sslcert_snapshot,
           "ping_recurring": run_ping_recurring}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tag", help="只跑指定批次")
    args = ap.parse_args()
    rows = []
    for b in BATCHES:
        if args.tag and b["tag"] != args.tag:
            continue
        path = os.path.join(RAW, b["file"])
        if not os.path.exists(path):
            print(f"[跳过] {b['tag']}：raw 文件缺失 {b['file']}", file=sys.stderr)
            continue
        try:
            rows.append(RUNNERS[b["kind"]](b))
            print(f"[完成] {b['tag']}")
        except (SystemExit, json.JSONDecodeError) as e:
            print(f"[跳过] {b['tag']}：{e}", file=sys.stderr)
            rows.append(dict(tag=b["tag"], msm=b["msm"], target=b["target"],
                             kind=b["kind"], prior=b.get("prior", ""),
                             results_total=None, probes_ok=None,
                             note=f"数据不可用（截断/缺失），跳过判定"))
    with open(OUT_JSON, "w", encoding="utf-8") as fh:
        json.dump(rows, fh, ensure_ascii=False, indent=1)
    with open(OUT_CSV, "w", newline="", encoding="utf-8-sig") as fh:
        w = csv.writer(fh)
        w.writerow(["tag", "msm", "target", "kind", "V", "winner", "equivalent",
                    "kappa", "obs", "probes_ok", "union_certs", "prior", "note"])
        for r in rows:
            v = r.get("verdict") or {}
            w.writerow([r["tag"], r["msm"], r["target"], r["kind"],
                        v.get("V", "(车队统计)"), v.get("winner", ""),
                        ";".join(v.get("equivalent", [])),
                        v.get("kappa", ""), json.dumps(v.get("obs", {}), ensure_ascii=False),
                        r.get("probes_ok", ""),
                        (r.get("fleet") or {}).get("union_certs", ""),
                        r.get("prior", ""), r.get("note", "")])
    print("已写出", OUT_JSON)
    print("已写出", OUT_CSV)


if __name__ == "__main__":
    main()
