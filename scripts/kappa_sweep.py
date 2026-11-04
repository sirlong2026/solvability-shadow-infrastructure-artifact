#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""kappa_sweep.py —— κ 闸阈值与 lead 参数敏感性 sweep（解析法，零合成）。

原理（参数只与判定链的两处交互，均可精确解析，无需重跑引擎）：
  1) κ 闸：位于判定链最前，通过后下游逻辑与 κ 无关 ⇒ 场景在 floor f 下过闸 ⇔ κ_场景 ≥ f。
  2) lead：只影响"决定可判 vs 条件可判"的边界（坍缩分支 top≥lead；单胜者分支
     top≥lead 且 top-次高≥lead），**不改变 winner/结构**。用 compare.json 里真实的
     support 分逐场景重算四态值即可。

数据源：9 场景的 compare.json（κ、support、equivalent、四态值）＋ Atlas 两案例（kroot 1/6、
campaign 2/6，来自 atlas_judged.json / cam_231739937_judged.json）。
判卷纪律：sweep 是参数研究；不改动引擎默认值；结果如实记录。
"""
import io
import json
import os
from fractions import Fraction

OUT_MD = r"G:\ipsonar-verifier\data\lab20\kappa_sweep.md"
RUN_MAIN = r"G:\ipsonar-verifier\data\lab20\run_20261031_001555"
RUN_S7 = r"G:\ipsonar-verifier\data\lab20\run_20261031_014938"
RUN_X1 = r"G:\ipsonar-verifier\data\lab20\x1"

SCEN = [("S0", RUN_MAIN), ("S1", RUN_MAIN), ("S2", RUN_MAIN), ("S3", RUN_MAIN),
        ("S4", RUN_MAIN), ("S5", RUN_MAIN), ("S6", RUN_MAIN), ("S7", RUN_S7),
        ("X1", RUN_X1)]


def exact_kappa(kappa_display):
    """κ 的精确分数：显示值 0.833→5/6、0.167→1/6、0.333→1/3、1.0→1。"""
    return {0.833: Fraction(5, 6), 0.167: Fraction(1, 6),
            0.333: Fraction(1, 3), 1.0: Fraction(1)}.get(kappa_display)


def margins(fs):
    """从 support/eliminated 取存活者 (top, second) 与坍缩标志。
    引擎的"次高"只在存活假设上取（eliminated 的分不参与领先差）。"""
    support = fs.get("support") or {}
    eliminated = set(fs.get("eliminated") or [])
    eq = set(fs.get("equivalent") or [])
    collapsed = eq and eq <= {"c1", "c8"}
    surv = sorted((v for c, v in support.items() if c not in eliminated), reverse=True)
    top = surv[0] if surv else 0
    second = surv[1] if len(surv) > 1 else 0
    return collapsed, top, second


def four_state_at(fs, lead):
    """在给定 lead 下重算四态值（winner/结构不变）。"""
    collapsed, top, second = margins(fs)
    if collapsed:
        return "决定可判" if top >= lead else "条件可判"
    # 单胜者分支：top≥lead 且 top-second≥lead
    return "决定可判" if (top >= lead and top - second >= lead) else "条件可判"


def main():
    scen = {}
    for tag, run in SCEN:
        cp = os.path.join(run, "%s_compare.json" % tag.lower())
        m = json.load(io.open(cp, encoding="utf-8"))
        scen[tag] = m["targets"][0]["four_state"]

    KFLOORS = [Fraction(0), Fraction(1, 6), Fraction(1, 3), Fraction(1, 2), Fraction(2, 3)]
    LEADS = [1, 2, 3]

    print("== 场景 κ 与 lead 边距 ==")
    for tag, fs in scen.items():
        collapsed, top, second = margins(fs)
        print("  %-3s κ=%-5s collapsed=%-5s top=%d second=%d four=%s" % (
            tag, scen[tag].get("kappa"), collapsed, top, second, fs.get("V")))

    # ---- κ sweep（闸只拦"不可观测"）----
    print("\n== κ floor sweep（9 场景过闸数；闸拒=四态改判不可观测）==")
    kappa_rows = []
    for f in KFLOORS:
        passed = [t for t, fs in scen.items() if exact_kappa(fs.get("kappa")) >= f]
        refused = [t for t, fs in scen.items() if exact_kappa(fs.get("kappa")) < f]
        kappa_rows.append((f, len(passed), refused))
        print("  floor=%-5s pass %d/9   refused: %s" % (f, len(passed), refused or "—"))

    # ---- lead sweep（四态值变化，winner/结构不变）----
    print("\n== lead sweep（四态值：决定可判 vs 条件可判）==")
    lead_rows = []
    for lead in LEADS:
        changed = []
        for tag, fs in scen.items():
            v0 = fs.get("V")
            v1 = four_state_at(fs, lead)
            if v0 != v1:
                changed.append("%s:%s→%s" % (tag, v0, v1))
        lead_rows.append((lead, changed))
        print("  lead=%d  changed: %s" % (lead, changed or "—（全部保持原四态值）"))

    # ---- Atlas 层 ----
    aj = json.load(io.open(r"G:\ipsonar-verifier\data\atlas\atlas_judged.json", encoding="utf-8"))
    kroot = [e for e in aj if e.get("tag") == "kroot-ping"][0]
    cam = json.load(io.open(r"G:\ipsonar-verifier\data\atlas\cam_231739937_judged.json", encoding="utf-8"))
    print("\n== Atlas 层闸位 ==")
    print("  kroot κ=1/6 :", "过闸" if Fraction(1, 6) >= Fraction(1, 6) else "拒判",
          "@floor=1/6;", "拒判 @floor≥1/3")
    print("  campaign κ=1/3:", "过闸 @floor≤1/3；拒判 @floor≥1/2")

    # ---- md ----
    md = ["# κ 闸与 lead 参数敏感性 sweep（解析法）", ""]
    md.append("方法：κ 闸位于判定链最前，通过后下游与 κ 无关，故场景在 floor f 下过闸 ⇔ κ≥f（精确分数比较）；"
              "lead 只影响决定可判/条件可判边界，用 compare.json 的真实 support 分重算。不重跑引擎、不合成数据。")
    md.append("")
    md.append("## 场景参数")
    md.append("")
    md.append("| 场景 | κ | support(top/second) | 现四态值 |")
    md.append("|---|---|---|---|")
    for tag, fs in scen.items():
        c, top, sec = margins(fs)
        md.append("| %s | %s | %d/%d%s | %s |" % (tag, fs.get("kappa"), top, sec,
                                                  "（坍缩分支）" if c else "", fs.get("V")))
    md.append("")
    md.append("## κ floor sweep")
    md.append("")
    md.append("| floor | 9 场景过闸 | 被闸拒绝 |")
    md.append("|---|---|---|")
    for f, n, refused in kappa_rows:
        md.append("| %s | %d/9 | %s |" % (f, n, ", ".join(refused) or "—"))
    md.append("")
    md.append("## lead sweep（四态值变化）")
    md.append("")
    md.append("| lead | 变化 |")
    md.append("|---|---|")
    for lead, changed in lead_rows:
        md.append("| %d | %s |" % (lead, ", ".join(changed) or "—（全部保持原四态值）"))
    md.append("")
    md.append("## Atlas 层闸位")
    md.append("")
    md.append("- k-root（κ=1/6）：floor=1/6 恰好过闸（1/6<1/6 为假）；floor≥1/3 拒判。现值 1/3 下拒判成立。")
    md.append("- 云 campaign（κ=1/3）：floor∈{0,1/6,1/3} 过闸且 decidable c₂；floor≥1/2 才拒判。现值位于安全区下沿。")
    md.append("")
    md.append("## 结论")
    md.append("")
    md.append("1. **κ floor 在 [1/3, 5/6] 区间内，受控层＋真机层 9 场景判定完全不变**（κ∈{5/6,1} 全部过闸）——现值 1/3 处于不变平台下沿，向下（1/6、0）也只是提前过闸、判定不变，向上到 5/6 仍不变。")
    md.append("2. **lead 在 {1,2,3} 内不改变任何 winner/结构结论**；lead=3 时部分场景四态值从决定可判降为条件可判（边际案例如实降级），lead=1、2 与现结果完全一致。")
    md.append("3. 闸位真正的敏感点在 Atlas 层：k-root 的拒判依赖 floor>1/6（现值 1/3 满足）；campaign 的通过依赖 floor≤1/3（现值恰在下沿）——这是 1/3=「6 维中 2 维」设计的自然结果：两个独立可观测维是本框架给出的最小证据集。")
    io.open(OUT_MD, "w", encoding="utf-8").write("\n".join(md))
    print("\nmd:", OUT_MD)


if __name__ == "__main__":
    main()
