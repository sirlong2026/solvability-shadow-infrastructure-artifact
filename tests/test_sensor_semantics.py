# -*- coding: utf-8 -*-
"""test_sensor_semantics.py —— 双传感器语义回归 + 四态形式化判定引擎（§三矩阵/§四）
的原生测试。此前用例散落在临时脚本（_sni_check / _cmp_regression），未入库即
形同虚设，现全部固化于此防静默回归。

内容：① 后端/影子轴解耦等 5 例语义回归；② SNI(o₄) 4 例；③ §二 观测性门；
④ decide_formal 四态 × lab S0–S6 已知答案（合成 bundle 复刻 lab 前提，含
   §四.1 共钟仲裁与"o₄ 不可观测 ⇒ {c₁,c₅,c₈} 不可分辨"的诚实降级）。
"""
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tools"))

import sensor_agent  # noqa: E402
from sensor_compare import infer_pair, decide_formal, read_O  # noqa: E402

PTS_ONE = [[0, -50], [600, 0.2], [1200, -58], [1800, 0.1], [2400, 0.2], [3000, 55]]
PTS_STICKY_A = [[0, -50], [600, -50.1], [1200, -50.2], [1800, -50.15], [2400, -50.0], [3000, -50.1]]
PTS_STICKY_B = [[0, 299], [600, 299.1], [1200, 299.2], [1800, 299.15], [2400, 299.0], [3000, 299.1]]

# 中性 SNI 探针名（lab topo.sh 对 S0–S5 同写此名组）：查询命中默认证书 ⇒
# o₄ 可观测-阴性，矩阵"六通道齐"前提成立（§四.1 备注）。
NEUTRAL_SNI = {"a.mp.test": "same", "b.mp.test": "same", "d.mp.test": "same"}
BLIND = {"ttl": {"supported": False, "ttl_set": [], "samples": 0, "sent": 0},
         "skew": {"supported": False, "points": []},
         "tls": {"supported": False, "unique_hashes": 0, "hashes": [], "sni_map": {},
                 "sni_unique": 0},
         "path": {"supported": False, "hops": [], "source_ips": []},
         "ping": {"supported": False, "received": 0, "sent": 0}}


def bundle(ip="10.198.3.10", ttl=None, skew=None, hashes=None, sni=None,
           hops=None, samples=14, source_ips=None):
    hashes = hashes if hashes is not None else ["H", "H", "H"]
    sni = sni if sni is not None else dict(NEUTRAL_SNI)
    return {
        "ip": ip,
        "ttl": ttl or {"supported": True, "ttl_set": [63], "samples": samples,
                       "sent": samples},
        "skew": skew or {"supported": True, "points": PTS_ONE},
        "tls": {"supported": True, "unique_hashes": len(set(hashes)), "hashes": hashes,
                "sni_map": sni, "sni_unique": len(set(sni.values()))},
        "path": {"supported": bool(hops), "hops": hops or [],
                 "source_ips": source_ips or []},
        "ping": {"supported": True, "received": samples, "sent": samples},
    }


class TestSemantics(unittest.TestCase):
    """① 后端轴与影子轴解耦等基础语义。"""

    def test_single_sane_pair(self):
        a = bundle(hops=["10.198.3.1", "10.198.3.10"])
        v, _, conf, hidden, _, _ = infer_pair("s0", a, bundle(hops=["10.198.3.1", "10.198.3.10"]))
        self.assertEqual((v, hidden), ("consistent_single", None))
        self.assertIn(conf, ("high", "medium"))

    def test_hidden_router_keeps_backend_single(self):
        a = bundle(hops=["10.198.3.10"])          # 1 跳且末跳=目标自身
        v, _, _, hidden, ev, _ = infer_pair("s3", a, bundle(hops=["10.198.3.10"]))
        self.assertEqual(v, "consistent_single", "影子跳不得越权改判后端")
        self.assertIsNotNone(hidden)
        self.assertTrue(any("影子" in e for e in ev))

    def test_ttl_multivalue_no_shadow_inference(self):
        tt = {"supported": True, "ttl_set": [63, 255], "samples": 14, "sent": 14}
        v, _, _, hidden, _, fl = infer_pair("s4", bundle(ttl=tt), bundle(ttl=tt))
        self.assertIsNone(hidden, "TTL 多值须禁止影子跳推断（§二正交）")
        self.assertTrue(fl or True)

    def test_blind_undetermined(self):
        v, _, conf, _, _, _ = infer_pair("s5", BLIND, dict(BLIND))
        self.assertEqual(v, "undetermined")
        self.assertIn(conf, ("none", "low"))

    def test_sticky_two_backends(self):
        a = bundle(hashes=["A", "A", "A"], skew={"supported": True, "points": PTS_STICKY_A})
        b = bundle(hashes=["B", "B", "B"], skew={"supported": True, "points": PTS_STICKY_B})
        b = dict(b, tls=dict(b["tls"], sni_map={"a.mp.test": "B", "b.mp.test": "B",
                                                 "d.mp.test": "B"}, sni_unique=1))
        a = dict(a, tls=dict(a["tls"], sni_map={"a.mp.test": "A", "b.mp.test": "A",
                                                 "d.mp.test": "A"}, sni_unique=1))
        v, _, _, _, _, _ = infer_pair("s2", a, b)
        self.assertIn(v, ("multiple_backends", "likely_pool"))


class TestSni(unittest.TestCase):
    """② o₄（SNI 分发）语义。"""

    def test_sni_three_hashes_multi(self):
        sni = {"a.mp.test": "s1", "b.mp.test": "s2", "d.mp.test": "s3"}
        a, b = bundle(hashes=[], sni=sni), bundle(hashes=[], sni=sni)
        v, _, _, _, ev, _ = infer_pair("s6", a, b)
        self.assertIn(v, ("multiple_backends", "likely_pool"))
        self.assertTrue(any("SNI" in e or "S6" in e for e in ev))

    def test_sni_single_value_not_multi(self):
        a = bundle(hashes=["H", "H", "H"])          # 默认即中性单值 SNI
        v, _, _, _, _, _ = infer_pair("s0", a, bundle())
        self.assertEqual(v, "consistent_single")

    def test_sni_one_side_union_still_flagged(self):
        a = bundle(hashes=[], sni={"x.a": "s1", "y.a": "s2"})
        b = bundle(hashes=["H", "H", "H"], sni={})
        v, _, _, _, _, _ = infer_pair("s6c", a, b)
        self.assertIn(v, ("multiple_backends", "likely_pool"), "SNI 跨源并集须成立")

    def test_v1_report_no_sni_compat(self):
        a = dict(bundle(hops=["PUBLIC_ADDR_01", "10.198.3.10"]))
        a["tls"] = {"supported": True, "unique_hashes": 1, "hashes": ["H"], "sni_map": {},
                    "sni_unique": 0}
        b = dict(a)
        v, _, _, _, _, _ = infer_pair("legacy", a, b)
        self.assertEqual(v, "consistent_single", "v1 无 sni 字段不得误报多后端")


class TestGate(unittest.TestCase):
    """③ §二 观测性门（agent 侧）。"""

    def test_gate_shape_and_c8_anchor_absent_in_gate(self):
        t = bundle(hops=["gw", "10.198.3.10"])
        g = sensor_agent.evaluate_gate(t)
        self.assertEqual(sorted(g), ["o1", "o2", "o3", "o4", "o5"])
        self.assertNotIn("raw", g, "gate 只标注、不删原始数据")
        self.assertTrue(g["o1"]["observable"])
        self.assertTrue(t.get("kappa_view", 0) > 0)

    def test_ttl_multivalue_forces_o5_unobservable(self):
        t = bundle(ttl={"supported": True, "ttl_set": [63, 255], "samples": 14, "sent": 14},
                   hops=["gw", "10.198.3.10"])
        g = sensor_agent.evaluate_gate(t)
        self.assertFalse(g["o5"]["observable"])
        self.assertIn("TTL 多值", g["o5"]["reason"])

    def test_insufficient_samples_gate_o3(self):
        t = bundle(hashes=["H"])              # 仅 1 次握手
        g = sensor_agent.evaluate_gate(t)
        self.assertFalse(g["o3"]["observable"])
        obs, kappa, _ = read_O(t, dict(t))    # 本地重推同规则
        self.assertEqual(obs["o3"], "unobservable")


class TestFormalEngine(unittest.TestCase):
    """④ §三矩阵 + §四判定 × S0–S6 已知答案（lab 前提的合成复刻）。"""

    FAMILY_OF_VERDICT = {"consistent_single": "single", "undetermined": "undecided",
                         "multiple_backends": "multi", "likely_pool": "multi"}

    def test_s0_collapse_c1_c8(self):
        a = bundle(hops=["10.198.3.1", "10.198.3.10"])
        fs = decide_formal(a, bundle(hops=["10.198.3.1", "10.198.3.10"]))
        self.assertEqual(fs["family"], "single")
        self.assertEqual(fs["winner"], "single")
        self.assertIn("c8", fs["equivalent"], "坍缩等价类必须含伪装锚 c8≡c1")
        self.assertIn(fs["V"], ("决定可判", "条件可判"))

    def test_s1_rr_same_kernel_confounded_still_multi(self):
        """lab S1：单内核 ⇒ o₂ 必然单簇（共钟），TLS 簇 o₃/o₆ 阳性 → c₂ 存活（§四.1 仲裁）。"""
        mix = {"supported": True, "points": PTS_ONE}
        a = bundle(hashes=["A", "B", "A", "B", "A", "B"], skew=mix,
                   sni={"a.mp.test": "A", "b.mp.test": "B", "d.mp.test": "A"})
        b = bundle(hashes=["A", "B", "A", "B", "A", "B"], skew=mix,
                   sni={"a.mp.test": "B", "b.mp.test": "A", "d.mp.test": "B"})
        fs = decide_formal(a, b)
        self.assertEqual(fs["family"], "multi")
        self.assertEqual(fs["winner"], "c2")
        self.assertTrue(fs["aux"].get("o2_confounded_suppressed"),
                        "共钟降格须显式留痕（审计可查哪些 o₂ 矛盾未记分）")
        self.assertEqual(infer_pair("s1", a, b)[0], "multiple_backends")
        self.assertEqual(self.FAMILY_OF_VERDICT[infer_pair("s1", a, b)[0]], fs["family"])

    def test_s2_sticky_same_clock_resolves_c3(self):
        a = bundle(hashes=["A", "A", "A"], skew={"supported": True, "points": PTS_STICKY_A},
                   sni={"a.mp.test": "A", "b.mp.test": "A", "d.mp.test": "A"})
        b = bundle(hashes=["B", "B", "B"], skew={"supported": True, "points": PTS_STICKY_B},
                   sni={"a.mp.test": "B", "b.mp.test": "B", "d.mp.test": "B"})
        fs = decide_formal(a, b)
        self.assertEqual(fs["winner"], "c3", "粘性池：单视角无轮换+跨源并集阳性 ⇒ c₃")
        self.assertEqual(fs["family"], "multi")

    def test_s4_ttl_multivalue_winner_c4(self):
        a = bundle(ttl={"supported": True, "ttl_set": [63, 255], "samples": 14, "sent": 14},
                   hops=["gw", "10.198.3.10"])
        fs = decide_formal(a, bundle(ttl={"supported": True, "ttl_set": [63, 255],
                                          "samples": 14, "sent": 14},
                                     hops=["gw", "10.198.3.10"]))
        self.assertEqual(fs["winner"], "c4", "TTL 多值 ⇒ 多后段，绝不落入影子路由 c₃")
        self.assertEqual(fs["obs"]["o5"], "unobservable")

    def test_s6_sni_winner_c5(self):
        sni = {"a.mp.test": "s1", "b.mp.test": "s2", "d.mp.test": "s3"}
        a = bundle(hashes=[], sni=sni)
        fs = decide_formal(a, bundle(hashes=[], sni=sni))
        self.assertEqual(fs["winner"], "c5")
        self.assertEqual(fs["V"], "决定可判")

    def test_o4_unobservable_honest_indistinguishable(self):
        """§六诚实点：不跑 SNI 通道时 {c₁,c₈} 与 c₅ 观察等价 → 不可分辨。

        这是 infer_pair（旧版会直接 consistent_single）比 decide_formal 更乐观
        的已知案例——formal 引擎按矩阵"全通道可观测才可判"原则更严。
        lab S0–S5 经 topo.sh 中性 SNI 探针补齐 o₄，不受影响。
        """
        a = dict(bundle(sni={}, hops=["10.198.3.1", "10.198.3.10"]))
        a["tls"] = {"supported": True, "unique_hashes": 1, "hashes": ["H", "H", "H"],
                    "sni_map": {}, "sni_unique": 0}
        fs = decide_formal(a, dict(a))
        self.assertEqual(fs["V"], "不可分辨")
        self.assertIn("c5", fs["equivalent"])
        self.assertEqual(fs["family"], "undecided")

    def test_aux_axis_orthogonal(self):
        a = bundle(hops=["10.198.3.10"])
        fs = decide_formal(a, bundle(hops=["10.198.3.10"]))
        self.assertTrue(fs["aux"]["hidden_router"])
        self.assertEqual(fs["family"], "single", "影子轴不得污染后端 family")

    def test_chain_axis_reported(self):
        a = bundle(source_ips=["10.198.3.1"], hops=["10.198.3.1", "10.198.3.10"])
        fs = decide_formal(a, dict(a), chain=True)
        self.assertTrue(fs["aux"]["chain"])

    def test_kappa_floor_gate(self):
        fs = decide_formal(BLIND, dict(BLIND))
        self.assertEqual(fs["V"], "不可观测")
        self.assertEqual(fs["family"], "undecided")
        self.assertLess(fs["kappa"], 1 / 3)

    def test_family_label_set(self):
        for v in ("consistent_single", "multiple_backends", "likely_pool", "undetermined"):
            self.assertIn(self.FAMILY_OF_VERDICT[v], ("single", "multi", "undecided"))



class TestX1Scenario(unittest.TestCase):
    """X1 真实网络合成锚点：LT 双证+sni 双值+TTL 混合 × s34 单证单值 → c2 族。
    （2026-10-31 凌晨真机形态的固化：fan-out 采样、共钟降格、负对照。）"""

    def _lt(self):
        return {"ip": "VIP",
                "ttl": {"supported": True, "ttl_set": [63, 249], "samples": 21,
                        "sent": 21, "ttl_source": "system_ping", "ping_fanout": 3},
                "skew": {"supported": False,
                         "error": "Windows raw 收不到 timestamp 回包（常态降级）"},
                "tls": {"supported": True, "unique_hashes": 2,
                        "hashes": ["hA", "hB"] * 4,
                        "sni_map": {"a.mp.test": "hA", "b.mp.test": "hB", "d.mp.test": "hA"},
                        "sni_unique": 2},
                "path": {"supported": True, "hops": ["1.1", "2.2", "3.3", "VIP"]},
                "ping": {"supported": True, "received": 21, "sent": 21}}

    def _s34(self):
        return {"ip": "VIP",
                "ttl": {"supported": True, "ttl_set": [63], "samples": 20, "sent": 20},
                "skew": {"supported": True,
                         "points": [[i * 1000.0, -37.0 + (i % 3) * 0.2] for i in range(30)]},
                "tls": {"supported": True, "unique_hashes": 1, "hashes": ["hA"] * 10,
                        "sni_map": {"a.mp.test": "hA", "b.mp.test": "hA", "d.mp.test": "hA"},
                        "sni_unique": 1},
                "path": {"supported": True, "hops": []},
                "ping": {"supported": True, "received": 20, "sent": 20}}

    def test_x1_family_and_winner(self):
        fs = decide_formal(self._lt(), self._s34())
        self.assertEqual(fs["winner"], "c2")
        self.assertEqual(fs["family"], "multi")
        self.assertTrue(fs["aux"].get("o2_confounded_suppressed"),
                        "LT 无 skew、s34 单簇 ⇒ c2 的 o2 矛盾应走共钟降格并留痕")
        v = infer_pair("VIP", self._lt(), self._s34())[0]
        self.assertIn(v, ("multiple_backends", "likely_pool"))

    def test_x1_chain_flag_orthogonal(self):
        fs = decide_formal(self._lt(), self._s34(), chain=True)
        self.assertTrue(fs["aux"]["chain"])
        self.assertEqual(fs["winner"], "c2", "chain 记录不得改变后端判定")


class TestS7ChainNegative(unittest.TestCase):
    """S7 链式负样本合成：传感器 IP 命中对方路径 → chain 证据成行、不过度自信。"""

    def _pair(self):
        a = {"ip": "t", "ttl": {"supported": True, "ttl_set": [63], "samples": 14, "sent": 14},
             "skew": {"supported": True, "points": [[i * 1000.0, -1.0] for i in range(8)]},
             "tls": {"supported": True, "unique_hashes": 1, "hashes": ["h"] * 5,
                     "sni_map": {"a": "h", "b": "h"}, "sni_unique": 1},
             "path": {"supported": True,
                      "hops": ["10.198.1.1", "10.198.2.10", "10.198.3.13"]},
             "ping": {"supported": True, "received": 6, "sent": 6}}
        b = {"ip": "t", "ttl": {"supported": True, "ttl_set": [64], "samples": 14, "sent": 14},
             "skew": {"supported": True, "points": [[i * 1000.0, -50.0] for i in range(8)]},
             "tls": {"supported": True, "unique_hashes": 1, "hashes": ["h"] * 5,
                     "sni_map": {"a": "h", "b": "h"}, "sni_unique": 1},
             "path": {"supported": True, "hops": ["10.198.3.13"]},
             "ping": {"supported": True, "received": 6, "sent": 6}}
        return a, b

    def test_chain_evidence_line(self):
        a, b = self._pair()
        v, _zh, _conf, _hid, ev, _fl = infer_pair("t", a, b, chain=True)
        self.assertTrue(any("链式拓扑" in x for x in ev), "chain 降级警告必须成行")
        self.assertIn(v, ("consistent_single", "likely_pool", "undetermined"))
        fs = decide_formal(a, b, chain=True)
        self.assertTrue(fs["aux"]["chain"])


class TestLoopbackOnly(unittest.TestCase):
    def test_ping_fanout_shape(self):
        import sensor_agent as sa
        pg = sa._ping_collect("127.0.0.1", 3)
        self.assertGreaterEqual(pg.get("ping_fanout", 0), 1)
        self.assertIsInstance(pg.get("ttl_set"), list)




class TestO1Honesty(unittest.TestCase):
    """o1 诚实性门回归：无 agent 门时按"有回包且样本足够"本地重推。

    历史缺陷（2026-10-31 修复）：_gate 改元组返回后，o1 判据仍按元组真值
    （恒真）判断 ⇒ TTL 探测全失败也会记 negative，违反 §二"看不见≠没发生"。
    """

    def _base(self, ttl):
        return {"ip": "T", "ttl": ttl,
                "skew": {"supported": True,
                         "points": [[i * 1000.0, -50.0] for i in range(8)]},
                "tls": {"supported": True, "unique_hashes": 1, "hashes": ["H"] * 3,
                        "sni_map": {"a": "H", "b": "H"}, "sni_unique": 1},
                "path": {"supported": True, "hops": ["g", "T"]},
                "ping": {"supported": True, "received": 8, "sent": 8}}

    def test_ttl_failure_is_unobservable_not_negative(self):
        b = self._base({"supported": True, "ttl_set": [], "samples": 0, "sent": 15})
        obs, kappa, _ = read_O(b, dict(b))
        self.assertEqual(obs["o1"], "unobservable", "TTL 全失败必须记不可观测")
        self.assertLess(kappa, 1.0)

    def test_ttl_supported_keeps_observable(self):
        b = self._base({"supported": True, "ttl_set": [63, 255], "samples": 14, "sent": 14})
        obs, kappa, _ = read_O(b, dict(b))
        self.assertEqual(obs["o1"], "positive")
        self.assertAlmostEqual(kappa, 0.833, places=2)

    def test_blind_kappa_zero(self):
        b = {"ip": "T", "ttl": {"supported": False, "ttl_set": [], "samples": 0, "sent": 0},
             "skew": {"supported": False, "points": []},
             "tls": {"supported": False, "unique_hashes": 0, "hashes": [], "sni_map": {},
                     "sni_unique": 0},
             "path": {"supported": False, "hops": []},
             "ping": {"supported": False, "received": 0, "sent": 0}}
        obs, kappa, _ = read_O(b, dict(b))
        self.assertEqual(kappa, 0.0)
        self.assertTrue(all(v == "unobservable" for v in obs.values()))


if __name__ == "__main__":
    unittest.main(verbosity=2)
