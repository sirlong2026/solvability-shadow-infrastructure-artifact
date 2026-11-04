#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""sensor_compare.py —— 双传感器观测比对（Phase 2 推理端）。

输入：sensor_agent.py 在两个网络位置各采一份 JSON；输出：逐目标的
多路径推理报告（中文证据链，可直接截图进教材/论文）。

核心分析（跨两台独立观测点）
----------------------------
1. **时钟域簇（skew levels）**：各传感器内部对 skew 序列聚类。
   单一传感器内出现 ≥2 个稳定簇 → 同一目标 IP 背后至少两台机器
   （绝对 skew 值跨传感器不可比——除非双方同步同一 NTP 源）；
2. **TLS 身份并集**：两传感器各收证书摘要，合并去重 →
   后端数下界的**与路径无关**的强证据（比 skew 更硬，不依赖 NTP）；
   同证书跨双传感器一致 → 单一后端强佐证（粘性 LB 见脚注局限）；
3. **TTL↔路径交叉验证（隐身跳检测）**：回包初始 TTL 反推真实跳数
   （假定出口 TTL 64/128/255），扣除 traceroute 显示跳数——
   若 TTL 暗示的跳数 > 路径跳数 → 路径里存在未被 trace 显形的路由
   （限速/不回 ICMP 的中间盒），即 IPsonar 意义上的"影子基础设施"候选；
4. **TTL 集合分歧**：两传感器到同一 IP 看到不同 TTL 集合 →
   目标侧 ECMP 或多出口 NAT 的转发面差异；
5. **路径分歧点**：到同一地标（landmark）从两传感器出发的 traceroute
   前缀重合长度 → **传感器独立性预检**（分歧越早越独立）。

运行：
    python3 sensor_compare.py sensorA.json sensorB.json [sensorC.json ...]
可选：--strict 使任何降级信号计入"证据不足"警告。
"""

import argparse
import json
import sys
from collections import Counter

INITIAL_TTL_GUESSES = (64, 128, 255)


def load(path):
    with open(path, encoding="utf-8") as fh:
        d = json.load(fh)
    if d.get("schema") not in ("sensor-report/v1", "sensor-report/v2"):
        print(f"警告：{path} schema={d.get('schema')}", file=sys.stderr)
    return d


# =========================================================================== #
# 《可解性诊断矩阵形式化定义》§三 实例矩阵 M  + §四 判定函数 V=decide(O,M)
# 语义（预测极性）：H(c,oᵢ)=+ 表示 c 成立时预测该信号为 positive；− 相反；
# O=○ 无涉不记分；观察 polarity 与预测一致 → support+1，矛盾 → refute+1 淘汰。
# c6 链式、c7 影子路由为正交辅助轴（不参与后端淘汰，单独输出）；
# c8=伪装集群锚：全负读数下与 c1 永久同权 → 等价类坍缩输出，S0/S5 双锚点。
# =========================================================================== #
HYP_BACKEND = ("c1", "c2", "c3", "c4", "c5", "c8")   # c6/c7 辅助轴
SIGNALS = ("o1", "o2", "o3", "o4", "o5", "o6")
PRED = {
    "c1": {"o1": "-", "o2": "-", "o3": "-", "o4": "-", "o5": "O", "o6": "-"},
    "c2": {"o1": "O", "o2": "+", "o3": "+", "o4": "O", "o5": "O", "o6": "+"},
    "c3": {"o1": "O", "o2": "+", "o3": "-", "o4": "O", "o5": "O", "o6": "+"},
    "c4": {"o1": "+", "o2": "O", "o3": "-", "o4": "O", "o5": "O", "o6": "O"},
    "c5": {"o1": "-", "o2": "-", "o3": "-", "o4": "+", "o5": "O", "o6": "-"},
    "c8": {"o1": "-", "o2": "-", "o3": "-", "o4": "-", "o5": "O", "o6": "-"},
}
# §三 判读约束的代码化：o₅（TTL-路径背离）属 infra 轴（c₆ 反证 / c₇ 正证），
# 与后端行正交——S3 影子路由不得证伪后端假设。文档 §六 注记的"正交共存"
# 即此编码（后端行 o5 一律 O；原 v0.1 c₁/c₅ 行 o5="−" 为编码笔误，已同步修订）。
SINGLE_LIKE = {"c1", "c8"}     # 后端拓扑行动结论一致（至多单后端）→ 等价类
KAPPA_FLOOR = 1 / 3


def _gate(t, k, default):
    """优先信任 agent 上报的观测性门；v1 旧报告无 gate 时按同规则本地重推。"""
    g = (t.get("gate") or {}).get(k)
    if isinstance(g, dict) and "observable" in g:
        return g["observable"], g.get("reason", "")
    return (bool(default) if isinstance(default, bool) else default[0],
            default[1] if isinstance(default, tuple) else "")


def read_O(a, b):
    """读 bundle 对 → 观测向量 obs{o:i→positive|negative|unobservable} + 说明 + κ。"""
    obs, note = {}, {}

    # o1 TTL 多样性 -------------------------------------------------------- #
    # 默认门与其余维同构：无 agent 门时按"有回包且样本足够"本地重推。
    # （旧版默认 False 且按元组真值判断 ⇒ 诚实规则实际失效，2026-10-31 修复。）
    if any(_gate(t, "o1",
                 bool((t.get("ttl") or {}).get("supported"))
                 and (t.get("ttl") or {}).get("samples", 0) >= 4)[0] for t in (a, b)):
        tl_a = (a.get("ttl") or {}).get("ttl_set") or []
        tl_b = (b.get("ttl") or {}).get("ttl_set") or []
        obs["o1"] = "positive" if (len(tl_a) > 1 or len(tl_b) > 1) else "negative"
    else:
        obs["o1"] = "unobservable"

    # o2 skew 稳定簇 ------------------------------------------------------- #
    lv_tot = []
    for t in (a, b):
        sk = t.get("skew", {})
        ok, _ = _gate(t, "o2", bool(sk.get("supported")) and len(sk.get("points") or []) >= 6)
        if ok and sk.get("supported"):
            lv_tot.append(len(skew_levels(sk.get("points", []))))
    if lv_tot:
        obs["o2"] = "positive" if (max(lv_tot) >= 2) else "negative"
    else:
        obs["o2"] = "unobservable"

    # o3 应用层证书轮换 ----------------------------------------------------- #
    rot = []
    for t in (a, b):
        tls = t.get("tls") or {}
        hs = tls.get("hashes") or []
        ok, _ = _gate(t, "o3", tls.get("supported") and len(hs) >= 3)
        if ok:
            rot.append(len(set(hs)))
    if rot:
        obs["o3"] = "positive" if max(rot) >= 2 else "negative"
    else:
        obs["o3"] = "unobservable"

    # o4 SNI 分发多证书 ----------------------------------------------------- #
    sni = {}
    sni_enough = False
    for t in (a, b):
        sm = {k: v for k, v in ((t.get("tls") or {}).get("sni_map") or {}).items() if v}
        sni.update(sm)
        ok, _ = _gate(t, "o4", len(sm) >= 2)
        sni_enough = sni_enough or ok
    if sni_enough and sni:
        uniq_v = len(set(sni.values()))
        obs["o4"] = "positive" if uniq_v >= 2 else "negative"
        note["sni_uniq"] = uniq_v
    else:
        obs["o4"] = "unobservable"

    # o5 TTL↔路径背离（影子跳）——TTL 多值已强制 unobservable（§二） ---------- #
    hidden_any = False
    for t, side in ((a, "A"), (b, "B")):
        ttl_set = (t.get("ttl") or {}).get("ttl_set") or []
        hops = (t.get("path") or {}).get("hops") or []
        ok, reason = _gate(t, "o5", bool(hops) and len(ttl_set) == 1)
        if not ok:
            if len(ttl_set) > 1 and hops:
                note.setdefault("o5_skip", []).append(f"[{side}] {reason}")
            continue
        ini = ttl_initial(ttl_set)
        if ini is None:
            continue
        inferred = max(ini)
        shown = max(len(hops) - 1, 0)
        hidden_any = hidden_any or inferred > shown
    # 汇总判据与逐侧循环同构（默认 False 曾与循环规则不一致，2026-10-31 统一）
    o5_ok = any(_gate(t, "o5",
                      bool((t.get("path") or {}).get("hops"))
                      and len((t.get("ttl") or {}).get("ttl_set") or []) == 1)[0]
                for t in (a, b))
    obs["o5"] = ("positive" if hidden_any else "negative") if o5_ok else "unobservable"
    note["hidden_router"] = hidden_any

    # o6 跨视角证书并集 ----------------------------------------------------- #
    g_ok = [bool(_gate(t, "o3", (t.get("tls") or {}).get("supported") and
                        len((t.get("tls") or {}).get("hashes") or []) >= 3)[0])
            for t in (a, b)]
    if all(g_ok):
        set_all = set((a.get("tls") or {}).get("hashes") or []) | set((b.get("tls") or {}).get("hashes") or [])
        obs["o6"] = "positive" if len(set_all) >= 2 and set((a.get("tls") or {}).get("hashes") or []) != set((b.get("tls") or {}).get("hashes") or []) or (
            len(set_all) >= 2) else "negative"
    else:
        obs["o6"] = "unobservable"

    kapp = sum(1 for o in SIGNALS if obs[o] != "unobservable") / len(SIGNALS)
    return obs, kapp, note  # 返回精确 κ；显示时再 round（闸比较不能用 round 值）


def decide_formal(a, b, chain=False):
    """§四 判定函数：κ 闸 → 淘汰 → 等价类坍缩 → 四态 + 辅助轴输出。

    与 infer_pair 的映射族一致性（回归测试锚定）：
      consistent_single ↔ 决定可判(class⊆{c1,c8}坍缩)   多后端 ↔ 决定/条件可判(cluster)
      likely_pool       ↔ 条件可判                      undetermined ↔ 不可分辨/不可观测
    """
    obs, kappa, note = read_O(a, b)
    out = {"kappa": round(kappa, 3), "obs": dict(obs), "aux": {}, "support": {}, "eliminated": {}}

    # 辅助轴（正交结论，不进后端淘汰） ------------------------------------- #
    out["aux"]["hidden_router"] = bool(note.get("hidden_router"))
    out["aux"]["chain"] = bool(chain)
    if note.get("o5_skip"):
        out["aux"]["o5_skip"] = note["o5_skip"]

    # κ 为精确分数（如 2/6=0.3333…）；闸值 1/3 严格小于才拒判，边界值 1/3 过闸。
    if kappa < KAPPA_FLOOR:
        out.update(V="不可观测", equivalent=["(κ不足)"], winner=None,
                   basis=[f"κ={round(kappa, 2)} < 1/3，可观测信号维不足（§四 优先闸）"],
                   family="undecided")
        out["missing"] = [o for o, v in obs.items() if v == "unobservable"]
        return out

    support = {c: 0 for c in HYP_BACKEND}
    eliminated = {}
    # §四.1 仲裁条款：TLS 簇（o₃/o₆）任一阳性时，o₂ 阴性视为"共钟共因"
    # （lab 单内核实验 be1/be2 共享时钟 ⇒ skew 必然单簇），对 c₂/c₃ 的
    # o₂ 矛盾降格记 O，不再单独击杀——否则 S1/S2 在单机上被系统性误否。
    pos_tls = obs.get("o3") == "positive" or obs.get("o6") == "positive"
    O2_CONFOUND = {("c2", "o2"), ("c3", "o2")}
    suppressed = []
    for c in HYP_BACKEND:
        for o, val in obs.items():
            if val == "unobservable":
                continue
            p = PRED[c][o]
            if p == "O":
                continue
            pred = "positive" if p == "+" else "negative"
            if val == pred:
                support[c] += 1
            elif (c, o) in O2_CONFOUND and val == "negative" and pos_tls:
                suppressed.append(f"{c}.o2（共钟共因，O₂ 记而不杀）")
            else:
                eliminated[c] = f"{o}={val} ⇌ 预测 {p}（证伪淘汰）"
    out["support"] = {c: support[c] for c in HYP_BACKEND}
    out["eliminated"] = eliminated
    out["aux"]["o2_confounded_suppressed"] = suppressed
    survivors = [c for c in HYP_BACKEND if c not in eliminated]
    if not survivors:                          # 理论不触发；兜底
        out.update(V="不可分辨", equivalent=list(HYP_BACKEND), winner=None,
                   basis=["全部假设被证伪——观测与矩阵矛盾，需人工复查"],
                   family="undecided")
        return out

    top = max(support[c] for c in survivors)
    best = [c for c in survivors if support[c] == top]
    best_set = set(best)

    if best_set <= SINGLE_LIKE:                # c1≡c8 等价类坍缩 → 行动结论 single
        v = "决定可判" if top >= 2 else "条件可判"
        out.update(V=v, equivalent=sorted(best_set), winner="single",
                   basis=[f"负向读数×{top} 支持单后端；等价类内含 c8 锚（完美伪装集群与单机在本组观测下不可分辨）"]
                   if "c8" in best_set else [f"负向读数×{top} 支持单后端"],
                   family="single")
        return out
    if len(best) == 1:
        cluster = best[0]
        v = "决定可判" if (top >= 2 and top - max([support[c] for c in survivors
                                                   if c != cluster] or [0]) >= 2) else "条件可判"
        out.update(V=v, equivalent=[cluster] + [c for c in survivors if c != cluster],
                   winner=cluster,
                   basis=[f"{cluster} 支持度 {top}，其余存活假设持平度不足"],
                   family="multi")
        return out
    # 多个 cluster 假设同权且行动结论不同 → 真不可分辨
    out.update(V="不可分辨", equivalent=sorted(best_set), winner=None,
               basis=[f"等价类 {sorted(best_set)} 同权同分（支持度 {top}），现有观测无法分离"],
               family="undecided")
    return out


def skew_levels(points, gap=8.0, min_n=3):
    """把 skew 采样值聚类成时钟域；返回 [(代表值, 计数)]；单点或全簇不足 → []。"""
    vals = sorted(p[1] for p in points)
    if len(vals) < 2:
        return []
    clusters = [[vals[0]]]
    for v in vals[1:]:
        if v - clusters[-1][-1] <= gap:
            clusters[-1].append(v)
        else:
            clusters.append([v])
    big = [(round(sum(c) / len(c), 2), len(c)) for c in clusters if len(c) >= min_n]
    return big


def target_map(report):
    return {t.get("ip"): t for t in report.get("targets", []) if "ip" in t}


def landmark_map(report):
    return {t.get("ip"): t.get("path", {}) for t in report.get("landmarks", [])}


def ttl_initial(ttl_set):
    """对观测到的（衰减后）TTL 集合，反推最可信的初始 TTL 估计。"""
    best = None
    for init in INITIAL_TTL_GUESSES:
        hops = [init - t for t in ttl_set]
        if any(h < 0 for h in hops):
            continue
        if best is None or max(hops) < max(best):
            best = hops
    return best  # None=全不合法


def infer_pair(ip, a, b, chain=False):
    """单个目标的双传感器推理。返回 (verdict, zh, conf, hidden_router, evidence, caveats)。
    chain=传感器IP命中对方路径（由 main 依据 source_ips 计算；v1 报告无源IP时为 False）。

    两个独立结论，语义不可混（影子路由器 ≠ 多后端）：
    - verdict：后端拓扑（单一 / 池 / 不定）
    - hidden_router：路径中是否存在不回 ICMP 的隐形跳（基础设施发现）
    """
    ev, fl = [], []
    pos_strong = pos_med = neg = 0
    hidden_sites: dict = {}          # {side: hidden_hops} → 影子路由发现，独立于后端判定

    # --- 1) 时钟域簇 -------------------------------------------------- #
    for side, s in (("A", a), ("B", b)):
        sk = s.get("skew", {})
        if sk.get("supported"):
            lv = skew_levels(sk.get("points", []))
            if len(lv) >= 2:
                pos_strong += 1
                ev.append(f"[{side}] skew 分成 {len(lv)} 个时钟域簇（{lv}）→ 同一 IP 后 ≥2 台机器")
            elif len(lv) == 1:
                neg += 1
                ev.append(f"[{side}] skew 单簇（{lv[0]}）→ 单一时钟域")
            if sk.get("backend_jumps"):
                pos_med += 1
                ev.append(f"[{side}] {sk['backend_jumps']} 处 5-20ms 跳变与簇分析一致")
        else:
            fl.append(f"skew 在 [{side}] 不可观测（{sk.get('error', '?')}）")

    # --- 2) TLS 证书并集 ---------------------------------------------- #
    tls_a, tls_b = (a.get("tls") or {}), (b.get("tls") or {})
    set_a = set(tls_a.get("hashes") or [])
    set_b = set(tls_b.get("hashes") or [])
    # S6：SNI 虚拟主机视图——同 IP 按域名分发不同证书 = 共享反代多站点
    sni_a = {k: v for k, v in (tls_a.get("sni_map") or {}).items() if v}
    sni_b = {k: v for k, v in (tls_b.get("sni_map") or {}).items() if v}
    sni_all = dict(sni_a)
    sni_all.update(sni_b)
    sni_uniq = len(set(sni_all.values()))
    if sni_uniq >= 2:
        pos_strong += 1
        by_sid = {}
        for h, hh in sni_all.items():
            by_sid.setdefault(hh, []).append(h)
        ev.append(f"★共享前端多站点（S6）：同一 IP 按 SNI 分发 {sni_uniq} 种证书 → "
                  f"≥{sni_uniq} 个虚拟主机共享一个网络入口：" +
                  "; ".join(f"{h}→{ss}" for h, ss in sorted(by_sid.items())[:6]))
        if not set_a and not set_b:
            ev.append("（IP-only 视图无 SNI ⇒ 只见默认证书，此现象本身即共享反代的指纹）")
    if tls_a.get("supported") and tls_b.get("supported"):
        union = set_a | set_b
        if len(union) >= 2:
            pos_strong += 1
            ev.append(f"TLS 证书摘要两侧并集 {len(union)} 种（A:{sorted(set_a)} B:{sorted(set_b)}）→ 后端 ≥{len(union)}")
        else:
            neg += 1
            ev.append(f"TLS 证书摘要两侧一致（{union}）→ 后端同一（若 LB 对两源均粘性则此论断减弱，见脚注）")
    elif tls_a.get("supported") or tls_b.get("supported"):
        fl.append("TLS 仅单侧可观测")
    else:
        fl.append("TLS 两侧均不可观测（目标未开 TLS 端口）")

    # --- 3) TTL↔路径（隐身跳） ---------------------------------------- #
    ttl_a = (a.get("ttl") or {}).get("ttl_set") or []
    ttl_b = (b.get("ttl") or {}).get("ttl_set") or []
    if len(ttl_a) > 1 or len(ttl_b) > 1:
        pos_med += 1
        ev.append(f"TTL 集合分歧（A:{ttl_a} B:{ttl_b}）→ ECMP/NAT 多出口候选")
    if len(ttl_a) == 1 and len(ttl_b) == 1:
        neg += 1
    path_a = a.get("path", {}).get("hops") or []
    path_b = b.get("path", {}).get("hops") or []
    for side, hops_, ttl_ in (("A", path_a, ttl_a), ("B", path_b, ttl_b)):
        if not hops_ or len(ttl_) != 1:
            # 无 trace 或多值 TTL（存在 ECMP/TTL 分歧，初始 TTL 不可唯一反推）
            # ⇒ 跳过影子跳推断，避免假告警；TTL 分歧本身已在上方计分
            if ttl_ and len(ttl_) > 1:
                fl.append(f"[{side}] TTL 多值 {ttl_} → 初始 TTL 不唯一，隐形跳推断跳过")
            continue
        init_hops = ttl_initial(ttl_)
        if init_hops is None:
            fl.append(f"[{side}] TTL={ttl_} 无法匹配 64/128/255 初始 TTL")
            continue
        inferred = max(init_hops)                    # 回包衰减推断出的"途经路由器数"
        routers_shown = max(len(hops_) - 1, 0)      # traceroute 显形路由器数（末跳=目标本身）
        hidden = inferred - routers_shown
        if hidden >= 1:
            hidden_sites[side] = hidden
            ev.append(f"[{side}] ★影子路由线索：TTL 推断途经 {inferred} 台路由，trace 仅显 {routers_shown} 台"
                      f" → 约 {hidden} 跳不回 ICMP（隐身路由器/中间盒，独立于'后端数'结论）")
        else:
            neg += 1
            ev.append(f"[{side}] TTL 推断路由数({inferred})与 trace 显形({routers_shown})一致 → 无隐藏跳")

    # --- 4) 路径一致性（同一目标的 A/B 路径） -------------------------- #
    if path_a and path_b:
        la_set = set(path_a)
        shared = la_set & set(path_b)
        if chain:
            ev.append("一个传感器 IP 出现在另一传感器通往目标的路径上 → 链式拓扑（非对等双观测，"
                      "独立性降级看预检；o₆『两源不同桶』前提减弱，c₃ 判定需人工复核）")
        ev.append(f"双传感器到目标路径共享段长度={len(shared)}，A独有={sorted(la_set - set(path_b))[:4]}，B独有={sorted(set(path_b) - la_set)[:4]}")

    # --- 判定 ---------------------------------------------------------- #
    score = pos_strong * 2 + pos_med
    if score >= 3:
        v, zh, conf = "multiple_backends", "多后端/多出口（跨信号吻合）", "high"
    elif score >= 1:
        v, zh, conf = "likely_pool", "疑似多后端（单信号）", "medium"
    elif neg >= 2:
        v, zh, conf = "consistent_single", "双传感器一致：单一后端", "high"
    else:
        v, zh, conf = "undetermined", "证据不足以判定", "none"
    hidden_txt = ("影子路由嫌疑：" + "; ".join(f"[{k}]≈{x}跳不回ICMP" for k, x in hidden_sites.items())
                  if hidden_sites else None)
    return v, zh, conf, hidden_txt, ev, fl


def independence(reports):
    """传感器独立性预检：对共同地标比 traceroute 前缀重合。"""
    lmaps = [landmark_map(r) for r in reports]
    ids = [r.get("sensor_id") for r in reports]
    out = []
    lands = sorted(set(lmaps[0]) & set.intersection(*[set(l) for l in lmaps])) if all(lmaps) else []
    for ip in lands:
        paths = [lmaps[i].get(ip, {}).get("hops") or [] for i in range(len(reports))]
        pref = 0
        if paths[0] and paths[1:]:
            for j in range(min(len(x) for x in paths)):
                if len({p[j] for p in paths}) == 1:
                    pref = j + 1
                else:
                    break
        out.append({"landmark": ip, "common_prefix_hops": pref,
                    "paths": {ids[i]: paths[i][:8] for i in range(len(reports))}})
    return out


def main():
    ap = argparse.ArgumentParser(description="双（多）传感器观测比对")
    ap.add_argument("reports", nargs="+", help="sensor_agent.py 产出的 JSON（≥2 份按 A、B… 比对）")
    ap.add_argument("--out", default="-", help="结果 JSON 输出（- = stdout）")
    args = ap.parse_args()
    reports = [load(p) for p in args.reports]
    if len(reports) < 2:
        print("需要至少两个传感器的 JSON", file=sys.stderr)
        return 2
    a, b = reports[0], reports[1]
    ta, tb = target_map(a), target_map(b)
    common = sorted(set(ta) & set(tb))

    print("=" * 72)
    print(f"多路径比对  传感器 A={a['sensor_id']}({a['os']})  B={b['sensor_id']}({b['os']})")
    print(f"共同目标 {len(common)} 个")
    print("=" * 72)
    res = []
    ips_a = a.get("source_ips") or []
    ips_b = b.get("source_ips") or []
    for ip in common:
        bundle_a, bundle_b = ta[ip], tb[ip]
        pa = (bundle_a.get("path") or {}).get("hops") or []
        pb = (bundle_b.get("path") or {}).get("hops") or []
        chain = bool(ips_a and set(ips_a) & set(pb)) or bool(ips_b and set(ips_b) & set(pa))
        v, zh, conf, hidden, ev, fl = infer_pair(ip, bundle_a, bundle_b, chain=chain)
        formal = decide_formal(bundle_a, bundle_b, chain=chain)
        tag = f" ⚑{hidden}" if hidden else ""
        fs = (f"  【形式判定 {formal['V']}"
              f"{'·' + str(formal.get('winner')) if formal.get('winner') else ''}"
              f" κ={formal['kappa']}】")
        print(f"\n── 目标 {ip} ──  判定: {v} | {zh}  [置信 {conf}]{tag}{fs}")
        for e in ev:
            print("   ·", e)
        for w in fl:
            print("   ⚠", w)
        res.append({"ip": ip, "verdict": v, "verdict_zh": zh, "confidence": conf,
                    "hidden_router": hidden, "evidence": ev, "caveats": fl,
                    "four_state": formal})
    extra = sorted((set(ta) | set(tb)) - set(common))
    if extra:
        print("\n（单侧观测到的目标，未做比对：", ", ".join(extra), "）")

    ind = independence(reports)
    print("\n── 传感器独立性预检（共同地标 traceroute）──")
    for row in ind:
        print(f"  {row['landmark']}: 前缀重合 {row['common_prefix_hops']} 跳"
              f"（{'充分独立' if row['common_prefix_hops'] <= 1 else '共享路径较多，独立性打折'}）")

    result_json = {"pair": [a["sensor_id"], b["sensor_id"]],
                   "targets": res, "independence": ind}
    if args.out == "-":
        print("\n── 脚注与方法局限 ──")
        print("· 粘性会话 LB 可能对两源固定同一后端：TLS 并集会缩小（本工具已如实降级）")
        print("· 跨传感器绝对 skew 不可直比（各自本地墙钟+路径不对称）；簇判在传感器内部做")
        print("· TTL 反推跳数假设初始 64/128/255；设备自定义 TTL 会引入偏差——以两传感器交叉为准")
    else:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(result_json, fh, ensure_ascii=False, indent=1)


if __name__ == "__main__":
    main()
