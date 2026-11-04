#!/usr/bin/env python3
"""evaluate.py —— 实验床真值核对：已知答案 vs 系统判定，输出命中率记录。

单主机拓扑的固有局限已写入 EXPECT 注释：时钟域信号要求真实异机时钟
（同一内核 = 同一钟），故 s3/s4 在单主机上本应"时钟静默"，
真正靠 TLS 并集/ TTL / ICMP 隐形跳检测三条腿走路。跨机阶段把 34 号
接成真第三观测点后，把 EXPECT 里 hidden 的判据一并复核。
"""
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

# 每场景：接受判定集合 + 是否必须出现影子路由告警
# four: §五 期望四态（formal V 值域）；family: single|multi|undecided；both 可选
EXPECT = {
    "s0": {"ok": {"consistent_single"}, "hidden": False, "desc": "单机控制",
           "four": {"决定可判", "条件可判"}, "family": {"single"}},
    "s1": {"ok": {"multiple_backends"}, "hidden": False, "desc": "RR 轮询 LB 双证书",
           "four": {"决定可判"}, "family": {"multi"}},
    "s2": {"ok": {"multiple_backends", "likely_pool", "undetermined"},  # 双 sticky 碰撞未定属可接受，看 evidence
           "hidden": False, "desc": "ip_hash 粘性 LB（跨源并集/单点漏报皆预期）",
           "note_evidence_must": "并集",
           "four": {"决定可判", "条件可判", "不可分辨"}, "family": {"multi", "undecided"}},
    "s3": {"ok": {"consistent_single", "undetermined", "multiple_backends", "likely_pool"},
           "hidden": True, "desc": "隐形路由器（必须报出影子跳）",
           "four": {"决定可判", "条件可判", "不可分辨", "不可观测"},   # 后端轴不受 infra 轴影响（§三 正交约束）
           "aux_hidden_must": True},
    "s4": {"ok": {"likely_pool", "multiple_backends"}, "hidden": False,
           "desc": "后端 TTL 分歧（ECMP/NAT 多出口信号）",
           "four": {"决定可判", "条件可判"}, "family": {"multi"}},    # s5 = 故意不可分辨下限：等价类 [c1,c8] 锚点生效即正确（坍缩 single 与不可分辨皆算对）
    "s5": {"ok": {"consistent_single", "undetermined"}, "hidden": False,
           "desc": "同证书+同内核时钟+粘性=原理盲区（期望如实 undetermined/single）", "limit": True,
           "four": {"决定可判", "条件可判", "不可分辨"}, "family": {"single", "undecided"},
           "equiv_must_contain": "c8"},
    "s6": {"ok": {"multiple_backends", "likely_pool"}, "hidden": False,
           "desc": "共享前端多站点：SNI 多证书 ⇒ 检出多虚拟主机（IP-only 视图不可见）",
           "note_evidence_must": "SNI",
           "four": {"决定可判"}, "winner_must": "c5"},
    # x1 = 跨机真实路径 LB（外部效度野考）：VIP DNAT 轮转 20 的 be1/be2 双证书双后端；
    # 观测点=LT（校园网出口真实多跳路径）与 s34（豁免固定 be1 = 单视角漏报负对照+
    # NAT 中间盒"隐身跳"在 34 观测上必现：MASQ 转发吞一跳 TTL 而 traceroute 不见）。
    # 34 后端三角不对称（LVS-NAT 经典病，FNAT+策略路由两法实测未通）存档为论文限制节。
    "x1": {"ok": {"multiple_backends", "likely_pool"}, "hidden": True,
           "desc": "X1 跨机真实路径 LB：双后端 RR+单视角对照+中间盒隐身跳野外检出（预期报影子）",
           "note_evidence_must": "并集",
           "four": {"决定可判", "条件可判"}, "family": {"multi"}, "winner_must": "c2"},
    # s7 = 链式拓扑负样本（观测性场景）：sensor 位居对方路径 → 必须检出 chain 并给降级
    # 警告；verdict 不预断（负样本考"知道自己不该自信"，如实登记）。
    "s7": {"ok": {"consistent_single", "likely_pool", "multiple_backends", "undetermined"},
           "hidden": False,
           "desc": "S7 链式负样本：sens2 植入 sens1 路径 —— 判卷只硬性要求 chain+降级警告",
           "note_evidence_must": "链式拓扑", "chain_must": True,
           "four": {"决定可判", "条件可判", "不可分辨", "不可观测"}},
}


def main():
    if len(sys.argv) < 3:
        print("用法: evaluate.py <s0..s5> <compare.json>", file=sys.stderr)
        return 2
    sc, path = sys.argv[1], Path(sys.argv[2])
    exp = EXPECT.get(sc)
    if exp is None:
        print(f"未知场景 {sc}", file=sys.stderr)
        return 2
    rep = json.loads(path.read_text(encoding="utf-8"))
    rows = rep.get("targets", [])
    if not rows:
        print(f"[{sc}] ✗ compare 结果为空（common targets=0）——传感器 JSON 缺 ip 段或目标无交集，"
              f"判卷失败而非通过", file=sys.stderr)
        return 1
    must = exp.get("note_evidence_must")
    print(f"[{sc}] {exp['desc']}"
          + ("  ※场景预期即'方法盲区演示'，判 undetermined/single 均算正确"
             if exp.get("limit") else ""))
    all_hit, records = True, []
    for r in rows:
        v, conf = r.get("verdict", "?"), r.get("confidence", "?")
        hidden, evs = bool(r.get("hidden_router")), " | ".join(r.get("evidence", []))
        ok = v in exp["ok"]
        hit = ok and (hidden if exp.get("hidden") else True) and (not must or must in evs)
        # —— 四态核对（compare v2 输出 four_state；旧 JSON 缺字段则跳过） —— #
        fs = r.get("four_state") or {}
        four_hit, four_v = None, fs.get("V", "")
        if fs:
            four_hit = four_v in exp.get("four", set() | {four_v})
            if exp.get("family"):
                four_hit = four_hit and fs.get("family") in exp["family"]
            if exp.get("winner_must"):
                four_hit = four_hit and fs.get("winner") == exp["winner_must"]
            if exp.get("equiv_must_contain"):
                if "c8" not in (fs.get("equivalent") or []) and fs.get("winner") != "single":
                    four_hit = False
            if exp.get("aux_hidden_must"):
                four_hit = four_hit and bool((fs.get("aux") or {}).get("hidden_router"))
            if exp.get("chain_must"):
                four_hit = four_hit and bool((fs.get("aux") or {}).get("chain"))
            if exp.get("hidden"):
                four_hit = four_hit and bool((fs.get("aux") or {}).get("hidden_router"))
            hit = hit and four_hit
        all_hit = all_hit and hit
        print(f"  {r['ip']}: 判定={v} conf={conf} hidden={hidden} "
              f"verdict∈预期={ok}"
              + ("" if four_hit is None else
                 f" | 形式态={four_v or '—'} winner={fs.get('winner') or fs.get('equivalent')}"
                 f" κ={fs.get('kappa')} four∈预期={four_hit}")
              + (f" 影子跳告警={hidden}{'✓' if hidden else '✗(场景必须报出)'}" if exp.get("hidden") else "")
              )
        for e in r.get("evidence", [])[:6]:
            print("     ·", e[:120])
        records.append((v, conf, hidden, hit, four_v, fs.get("winner") or "", fs.get("kappa", "")))
    csv_path = path.with_suffix(".eval.csv")
    new = not csv_path.exists()
    with csv_path.open("a", encoding="utf-8") as fh:
        if new:
            fh.write("scenario,target,verdict,confidence,hidden,hit,four_state,four_winner,kappa,ts\n")
        for (v, conf, hd, ht, fv, fw, kp), r in zip(records, rows):
            fh.write(f"{sc},{r['ip']},{v},{conf},{int(hd)},{int(ht)},{fv},{fw},{kp},"
                     f"{datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}\n")
    print(f"场景 {sc} 汇总: {'✓ 全部符合预期' if all_hit else '✗ 存在偏差（见上行）'}；已记录 {csv_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
