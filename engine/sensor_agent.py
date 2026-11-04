#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""sensor_agent.py —— 零依赖网络测量传感器（多路径推理 Phase 2 采集端）。

单文件、纯标准库，放到任意 Linux/Windows 机器即可运行：
    python3 sensor_agent.py --id A --targets 10.198.0.10 \\
        --allow-cidr 10.198.0.0/24 --json sensorA.json

每个目标的测量束（与 ipsonar_neo/pathtools.py 同源实现，可独立离线跑）：
    ttl    raw ICMP echo 连续采样的回包 TTL 集合
    skew   ICMP Timestamp 序列 → 每对样本斜率/跳变（单机=平，多后端=5-20ms 跳）
    tls    重复握手收集的证书 DER 摘要集合（摘要轮换=应用层多后端，强证据）
    rtt    TCP 连接 RTT 分布 + 双峰检测
    path   traceroute 逐 hops（经子进程 tracepath/traceroute/tracert 兜底）
    ping   系统 ping 回包数与 TTL（raw 不可用时的降级校验通道；Linux/Windows 通用）

授权护栏
--------
默认仅允许 私网 / 回环 / 链路本地目标；其余一律拒绝。
公网/校内自管专属段（如 <YOUR_MGMT_CIDR> 自管实验目标）必须显式
`--allow-cidr CIDR[,CIDR...]` 传入——对应"书面/管理授权"的机器可读形式。
landmarks 只做 traceroute（被动路径测量，不触发包内容）。

安全声明：本工具仅用于自管网络与实验床。请勿扫描其他机构站点。
"""

import argparse
import hashlib
import json
import os
import platform
import re
import socket
import ssl
import struct
import subprocess
import sys
import time
from ipaddress import ip_address, ip_network

VERSION = "sensor-report/v2"
_RE_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IS_WIN = (os.name == "nt")


# --------------------------------------------------------------------------- #
# §二 诚实性规则：观测性门（gate）—— 实现与《可解性诊断矩阵形式化定义》对齐
#   任一信号 oᵢ 前提不满足时必须显式记 unobservable（"看不见"），
#   绝不允许被下游误读为 negative（"没发生"）。gate 只标注、不删除
#   原始读数（raw 永远保留——判定可追溯的前提）。
# --------------------------------------------------------------------------- #
GATE_MIN = {           # (o1..o5 按视角；o6 在 compare 端)：最小证据量阈值
    "o1": 4,           # TTL 多样性需 ≥4 个回包样本
    "o2": 6,           # skew 簇判需 ≥6 个 timestamp 点
    "o3": 3,           # 证书轮换需 ≥3 次握手才能区分有/无轮换
    "o4": 2,           # SNI 多证需至少 2 个非空命中
    "o5": 4,           # TTL-路径背离需 o1 同级的回包样本量
}
KAPPA_FLOOR = 1 / 3    # §四 不可观测阈值：κ(O) < 1/3 时优先输出 unobservable


def local_ipv4s() -> list:
    """尽力枚举本机 IPv4（供 compare 做链式拓扑判定 o/c₆）。纯本地解析，不发流。"""
    ips = set()
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ips.add(info[4][0])
    except OSError:
        pass
    try:  # UDP connect 不发包，只查路由表选中的本机源地址（对任何不可达目标均安全）
        for probe_ip in ("10.255.255.255", "192.0.2.1"):   # 192.0.2.1 = TEST-NET-1 文档段
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s.connect((probe_ip, 9))
                ips.add(s.getsockname()[0])
            except OSError:
                pass
            finally:
                s.close()
    except OSError:
        pass
    return sorted(i for i in ips if not i.startswith("127.")) or ["127.0.0.1"]


def evaluate_gate(target: dict) -> dict:
    """为单个目标 bundle 计算 o1–o5 观测性门与 κ。返回 gate dict（同时就地写入）。"""
    g = {}
    ttl, sk, tls = target.get("ttl", {}), target.get("skew", {}), target.get("tls", {})
    path, ping = target.get("path", {}), target.get("ping", {})

    ns = ttl.get("samples", 0)
    if not ttl.get("supported"):
        g["o1"] = {"observable": False, "reason": ttl.get("error") or "无 echo 回包"}
    elif ns < GATE_MIN["o1"]:
        g["o1"] = {"observable": False, "reason": f"回包 {ns}<{GATE_MIN['o1']} 样本不足"}
    else:
        g["o1"] = {"observable": True, "reason": ""}

    pts = sk.get("points") or []
    if not sk.get("supported"):
        g["o2"] = {"observable": False, "reason": sk.get("error") or "无 timestamp 应答"}
    elif len(pts) < GATE_MIN["o2"]:
        g["o2"] = {"observable": False, "reason": f"skew 点 {len(pts)}<{GATE_MIN['o2']}"}
    else:
        g["o2"] = {"observable": True, "reason": ""}

    hs = tls.get("hashes") or []
    if not tls.get("supported"):
        g["o3"] = {"observable": False, "reason": "TLS 端口未开/握手全失败"}
    elif len(hs) < GATE_MIN["o3"]:
        g["o3"] = {"observable": False, "reason": f"握手 {len(hs)}<{GATE_MIN['o3']} 无法区分有无轮换"}
    else:
        g["o3"] = {"observable": True, "reason": ""}

    sni_hits = sum(1 for v in (tls.get("sni_map") or {}).values() if v)
    if sni_hits >= GATE_MIN["o4"]:
        g["o4"] = {"observable": True, "reason": ""}
    else:
        g["o4"] = {"observable": False,
                   "reason": "未配置 sni-hosts 或命中不足" if sni_hits == 0
                   else f"SNI 命中 {sni_hits}<{GATE_MIN['o4']}"}

    ttls = ttl.get("ttl_set") or []
    if not path.get("hops"):
        g["o5"] = {"observable": False, "reason": path.get("error") or "trace 不可用"}
    elif len(ttls) != 1:
        g["o5"] = {"observable": False,
                   "reason": f"TTL 多值 {ttls} → 初始 TTL 不唯一（§二 强制降级，防 ECMP 污染影子跳）"}
    elif ns < GATE_MIN["o5"]:
        g["o5"] = {"observable": False, "reason": f"回包样本 {ns} 不足"}
    elif ttl.get("supported") is False and ping.get("supported") and ping.get("received", 0) >= 2:
        g["o5"] = {"observable": True, "reason": "raw 不可用，取自系统 ping 的 TTL（降级通道）"}
    else:
        g["o5"] = {"observable": True, "reason": ""}

    target["gate"] = g
    obs = sum(1 for x in g.values() if x["observable"])
    target["kappa_view"] = round(obs / 5, 3)   # 本视角 o1–o5；o6 在 compare 端并入后算总 κ
    return g


def _private_or_allowed(ip: str, allow: list) -> bool:
    try:
        addr = ip_address(ip)
    except ValueError:
        return False
    if addr.is_private or addr.is_loopback or addr.is_link_local:
        return True
    return any(addr in ip_network(c) for c in allow)


# --------------------------------------------------------------------------- #
# ICMP 原语（与 pathtools 同源；Windows 与 root 权限 Linux 均可用）
# --------------------------------------------------------------------------- #
def _icmp_cksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) + data[i + 1]
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return (~s) & 0xFFFF


def _icmp_packet(ty, ident, seq, ts=None):
    if ts is None:
        body = struct.pack("!BBHHH", ty, 0, 0, ident, seq) + b"pathtools000"
    else:
        body = struct.pack("!BBHHHIII", ty, 0, 0, ident, seq,
                           ts & 0xFFFFFFFF, 0, 0)
    if _IS_WIN:
        ck_body = body[2:]          # 伪头约定：checksum 覆盖除 cksum 字段外的 ICMP
    else:
        ck_body = body
    ck = _icmp_cksum(ck_body)
    head = struct.pack("!BBHHH", ty, 0, ck, ident, seq)
    return head + body[8:] if ts is not None else head + body[8:]


def _icmp_parse(buf):
    """返回 (ttl, icmp_type, icmp_payload)；短包返回 (-1,-1,b"")。"""
    if len(buf) < 28:
        return -1, -1, b""
    ihl = (buf[0] & 0x0F) * 4
    if ihl < 20 or len(buf) < ihl + 8:
        return -1, -1, b""
    return buf[8], buf[ihl], buf[ihl:]


def _probe_raw_icmp(ip, samples, interval, timeout, msg_type, ident, fresh_ident=False):
    """连续发一种 ICMP 请求，返回 [(rtt_ms, ttl, payload), ...] 有效样本；异常返回 (None, err)。

    fresh_ident=True：每次探测换 ident、seq 恒 0 —— 在内核/中间盒（ECMP、DNAT、
    LB）眼中是 N 条独立流。固定 id 会被 conntrack 合并成同一 flow，多出口轮换
    类拓扑会被"骗"成全走一条路径（lab S4 真机判卷暴露）。
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except OSError as exc:
        return None, f"raw socket 不可用：{exc}"
    sock.settimeout(timeout)
    got = []
    try:
        for seq in range(samples):
            my_id = ((ident + seq * 613) & 0x7FFF) or 1 if fresh_ident else ident
            use_seq = 0 if fresh_ident else (seq & 0xFFFF)
            ts = int(time.time() * 1000) & 0xFFFFFFFF if msg_type == 13 else None
            pkt = _icmp_packet(msg_type, my_id, use_seq, ts)
            t0 = time.monotonic()
            try:
                sock.sendto(pkt, (ip, 0))
                data, _ = sock.recvfrom(512)
            except (socket.timeout, OSError):
                continue
            t1 = time.monotonic()
            ttl, mtype, payload = _icmp_parse(data)
            if ttl < 0 or len(payload) < 8:
                continue
            rid = struct.unpack("!HH", payload[4:8])
            if rid[0] != my_id:
                continue
            if msg_type == 8 and mtype != 0:
                continue
            if msg_type == 13 and mtype != 14:
                continue
            got.append(((t1 - t0) * 1000.0, ttl, payload))
            if seq < samples - 1:
                time.sleep(interval)
    finally:
        sock.close()
    return got, ""


# --------------------------------------------------------------------------- #
# 子信号
# --------------------------------------------------------------------------- #
def probe_ttl(ip, samples, timeout):
    ident = (int(time.time() * 1000) & 0x7FFF) or 1
    got, err = _probe_raw_icmp(ip, samples, 0.12, timeout, 8, ident, fresh_ident=True)
    if got is None or (not got and _IS_WIN):  # raw 不可用/Windows raw 收不到回包 → 系统 ping 降级通道
        pg = _ping_collect(ip, samples)
        if pg["ttl_set"]:
            return {"supported": True, "ttl_set": pg["ttl_set"], "samples": pg["received"],
                    "sent": pg.get("sent", samples), "rtt_ms": pg["rtt_ms"],
                    "ttl_source": "system_ping", "ping_fanout": pg.get("ping_fanout")}
        return {"supported": False, "error": err, "ttl_set": [],
                "samples": 0, "sent": samples, "rtt_ms": [], "ttl_source": "none"}
    if not got:
        return {"supported": False, "error": "无 echo 回包", "ttl_set": [],
                "samples": 0, "sent": samples, "rtt_ms": []}
    ttls = sorted({t for _, t, _ in got})
    return {"supported": True, "ttl_set": ttls, "samples": len(got),
            "sent": samples, "rtt_ms": [round(rt, 2) for rt, _, _ in got]}


def _ping_collect(ip, samples, fanout=3):
    """系统 ping 采集（raw 不可用时的降级通道）。

    并发多进程短采样：Windows/Linux 的 ping 进程以 pid 作 ICMP id——单进程连发
    N 包 = 同一 conntrack 流 = 被 LB/轮询拓扑粘死在一个后端，"每流后端分歧"会被
    采样手段本身抹掉（X1 真机 LT 实测暴露）。拆 fanout 个并发进程，pid.id 各异
    即真·每流采样；各进程输出 TTL/rtt 归并。速率仍保守（≤3×0.2s 间隔档）。
    """
    per = max(2, (samples + fanout - 1) // fanout)

    def build():
        if _IS_WIN:
            return ["ping", "-n", str(per), "-w", "1000", ip]
        return ["ping", "-c", str(per), "-i", "0.2", "-W", "2", ip]

    procs = []
    for _ in range(fanout):
        try:
            # Popen 并行起跑，稍后统一收
            procs.append(subprocess.Popen(build(), stdout=subprocess.PIPE,
                                          stderr=subprocess.STDOUT,
                                          text=True, encoding="utf-8", errors="replace"))
        except OSError:
            pass
    outs = []
    for p in procs:
        try:
            o, _ = p.communicate(timeout=per * 2 + 25)
            outs.append(o or "")
        except (subprocess.TimeoutExpired, OSError):
            try:
                p.kill()
            except OSError:
                pass
    out = "".join(outs)
    ttl_hits = re.findall(r"[Tt][Tt][Ll]=(\d+)", out)
    rtt_vals = re.findall(r"[Tt]ime[=<]\s*([\d.]+)\s*ms", out)
    return {"ttl_set": sorted({int(t) for t in ttl_hits}),
            "received": len(ttl_hits) if ttl_hits else len(rtt_vals),
            "sent": per * max(1, len(procs)),
            "rtt_ms": [round(float(x), 2) for x in rtt_vals],
            "ping_fanout": len(procs)}


def probe_skew(ip, samples, interval, timeout):
    # fresh_ident：X1 类"多后端按新流轮询"拓扑下，固定 ident 的全部 timestamp
    # 探测会被 conntrack 归并为同一 flow → 全落一台机器 → 时钟双簇假阴。
    got, err = _probe_raw_icmp(ip, samples, interval, timeout, 13,
                               (int(time.time() * 1000) & 0x7FFF) or 2,
                               fresh_ident=True)
    if not got:
        return {"supported": False, "error": err or "主机未实现 ICMP Timestamp（常态）"}
    pts = []
    t_first = None
    for rtt_ms, _ttl, payload in got:
        # Windows/Linux 均按 RFC 语义：transmit 偏移 16:20 在 icmp payload
        trans = struct.unpack("!III", payload[8:20])[2]
        t_now = time.time()
        if t_first is None:
            t_first = t_now
        local = t_now * 1000.0 - rtt_ms / 2.0
        skew = (trans - (int(local) & 0xFFFFFFFF) + 0x80000000) % 0x100000000 - 0x80000000
        pts.append((((t_now - t_first) * 1000.0), skew))
    if not pts:
        return {"supported": False, "error": "无有效 timestamp 样本"}
    out = {"supported": True, "points": [[round(x, 1), round(y, 2)] for x, y in pts]}
    if len(pts) >= 3:
        diffs = [abs(pts[i][1] - pts[i - 1][1]) for i in range(1, len(pts))]
        if max(diffs) > 1e8:
            return {"supported": False,
                    "error": "Timestamp 字段环绕伪像（栈未正确实现，判不可观测）"}
        xs = [p[0] for p in pts]
        ys = [p[1] for p in pts]
        n = len(xs)
        mx, my = sum(xs) / n, sum(ys) / n
        sxx = sum((x - mx) ** 2 for x in xs)
        slope = (sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / sxx) if sxx else 0.0
        out["slope_ms_per_ms"] = round(slope, 6)
        # 多机跳变：5-20ms 档；>100ms 算 NTP；1-5ms 算噪声
        out["ntp_jumps"] = sum(1 for d in diffs if d > 100.0)
        out["backend_jumps"] = sum(1 for d in diffs if 5.0 < d <= 20.0)
        out["noise_jumps"] = sum(1 for d in diffs if 1.0 < d <= 5.0)
        out["max_step"] = round(max(diffs), 2)
    return out


def _tls_client_ctx() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_ciphers("DEFAULT@SECLEVEL=1")
    except ssl.SSLError:
        pass
    return ctx


def _tls_one(ip, port, server_hostname):
    with socket.create_connection((ip, port), timeout=3.0) as raw:
        with _tls_client_ctx().wrap_socket(raw, server_hostname=server_hostname) as tls:
            der = tls.getpeercert(True)
            ciph = (tls.cipher() or ("?",))[0]
    return hashlib.sha1(der or b"").hexdigest()[:12], ciph


def probe_tls(ip, port, samples, interval, sni_hosts=()):
    """按 samples 次无 SNI 握手续集轮换；sni_hosts 非空时另为每域名一次握手建 sni_map。
    sni_map 是 S6 的关键：同一 IP 不同 SNI 返回不同证书 ⇒ 共享反代多站点，
    只按 IP 观测完全不可见（IP-only 永远只见默认证书）。"""
    hashes, ciphers, errs, sni_map = [], [], [], {}
    for i in range(samples or (1 if sni_hosts else 0)):
        try:
            h, c = _tls_one(ip, port, None)
            hashes.append(h)
            ciphers.append(c)
        except Exception as exc:  # noqa: BLE001
            errs.append(str(exc)[:100])
        time.sleep(interval)
    for host in sni_hosts:
        try:
            h, c = _tls_one(ip, port, host)
            sni_map[host] = h
            ciphers.append(c)
        except Exception as exc:  # noqa: BLE001
            sni_map[host] = ""
            errs.append(f"{host}: {str(exc)[:80]}")
        time.sleep(0.1)
    sup = bool(hashes) or any(sni_map.values())
    return {"supported": sup,
            "port": port,
            "unique_hashes": len(set(hashes)),
            "hashes": hashes, "ciphers": ciphers,
            "sni_map": sni_map,
            "sni_unique": len({h for h in sni_map.values() if h}),
            "error": (errs[:2] if not sup else [])}


def probe_rtt(ip, port, samples):
    rtts = []
    for _ in range(samples):
        try:
            t0 = time.monotonic()
            sock = socket.create_connection((ip, port), timeout=2.0)
            rtts.append(round((time.monotonic() - t0) * 1000.0, 2))
            sock.close()
        except OSError:
            pass
    return {"supported": len(rtts) >= 6, "samples": rtts}


def probe_path(ip, max_hops=24):
    """子进程 traceroute → 归一 hops 列表；多候选命令兼容 GNU/busybox/Windows。"""
    cands = []
    if _IS_WIN:
        cands.append(["tracert", "-d", "-h", str(max_hops), "-w", "1000", ip])
    else:
        cands += [
            ["traceroute", "-n", "-m", str(max_hops), "-w", "1", ip],
            ["traceroute", "-n", "-m", str(max_hops), ip],
            ["traceroute", "-n", ip],                      # busybox 最小参数
            ["tracepath", "-n", "-m", str(max_hops), ip],
        ]
    last_err = ""
    for cmd in cands:
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=45,
                               encoding="utf-8", errors="replace")
        except (subprocess.TimeoutExpired, OSError) as exc:
            last_err = str(exc)[:120]
            continue
        hops: list = []
        seen = set()
        reached = False
        for line in (r.stdout or "").splitlines():
            ips = _RE_IPV4.findall(line)
            if not ips:
                continue
            hop = ips[-1] if _IS_WIN else ips[0]
            if hop in seen:
                continue
            seen.add(hop)
            if hop == ip:
                reached = True
            hops.append(hop)
        if hops:
            return {"supported": True, "hops": hops[:max_hops], "reached": reached,
                    "tool": cmd[0]}
        last_err = f"{cmd[0]} rc={r.returncode} 无解析结果"
    return {"supported": False, "error": last_err or "无可用 traceroute"}


def probe_ping_cmd(ip, samples=4):
    """系统 ping 兜底（不依赖 raw 权限）。"""
    if _IS_WIN:
        cmd = ["ping", "-n", str(samples), "-w", "1000", ip]
    else:
        cmd = ["ping", "-c", str(samples), "-i", "0.2", "-W", "2", ip]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=samples + 15,
                           encoding="utf-8", errors="replace")
    except (subprocess.TimeoutExpired, OSError):
        return {"supported": False}
    out = (r.stdout or "") + (r.stderr or "")
    got = len(re.findall(r"[Tt][Tt][Ll]=\s*(\d+)", out)) or \
        len(re.findall(r"(\d+)\s+bytes from", out))
    return {"supported": True, "received": got, "sent": samples}


def _which(exe):
    """无 shutil.which 老版本兜底。"""
    try:
        import shutil
        return shutil.which(exe)
    except Exception:  # noqa: BLE001
        return None


# --------------------------------------------------------------------------- #
def probe_target(ip, args):
    t = {"ip": ip}
    t["ttl"] = probe_ttl(ip, args.ttl_samples, 1.0)
    t["skew"] = probe_skew(ip, args.skew_samples, args.skew_interval, 1.0)
    tls_port = None
    for p in args.tls_ports:
        fp = probe_tls(ip, p, args.tls_samples, args.tls_interval, args.sni_hosts)
        if fp["supported"]:
            tls_port = p
            t["tls"] = fp
            break
    else:
        t["tls"] = {"supported": False, "unique_hashes": 0, "sni_unique": 0,
                    "sni_map": {}, "hashes": []}
        t["tls"]["port_tried"] = args.tls_ports[:1] and args.tls_ports[0]
    port = (tls_port or 80)
    t["rtt"] = probe_rtt(ip, port, max(args.ttl_samples // 2, 6))
    t["path"] = probe_path(ip)
    t["ping"] = probe_ping_cmd(ip)
    return t


def main():
    ap = argparse.ArgumentParser(description="零依赖网络测量传感器 agent")
    ap.add_argument("--id", default=socket.gethostname(), help="传感器标识（如 20/34）")
    ap.add_argument("--targets", required=True, help="逗号分隔 IP 白名单（须已授权）")
    ap.add_argument("--allow-cidr", default="", help="额外授权 CIDR 列表（逗号分隔）")
    ap.add_argument("--landmarks", default="", help="额外 traceroute 地标 IP（仅测路径）")
    ap.add_argument("--ttl-samples", type=int, default=15)
    ap.add_argument("--skew-samples", type=int, default=20)
    ap.add_argument("--skew-interval", type=float, default=1.0)
    ap.add_argument("--tls-samples", type=int, default=6)
    ap.add_argument("--tls-ports", default="443,8443,993")
    ap.add_argument("--tls-interval", type=float, default=0.35,
                    help="TLS 相邻握手间隔；LB 轮询探测建议 ≥0.3s")
    ap.add_argument("--sni-hosts", default="",
                    help="S6 场景：逗号分隔虚拟主机名，逐个带 SNI 握手看证书分发（如 a.mp.test,b.mp.test）")
    ap.add_argument("--json", default="-", help="输出文件（- = stdout）")
    args = ap.parse_args()
    for name, attr in (("tls_ports", "tls_ports"),):
        setattr(args, name, [int(p) for p in getattr(args, name).split(",") if p.strip()])
    args.sni_hosts = [s.strip() for s in args.sni_hosts.split(",") if s.strip()]
    allow = [c.strip() for c in args.allow_cidr.split(",") if c.strip()]
    targets = [t.strip() for t in args.targets.split(",") if t.strip()]

    report = {
        "schema": VERSION,
        "sensor_id": args.id,
        "host": socket.gethostname(),
        "os": platform.system().lower(),
        "python": platform.python_version(),
        "t_start": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "allow_cidr": allow,
        "source_ips": local_ipv4s(),   # 供 compare 做链式拓扑判定（c₆/o5 反证）
        "targets": [], "landmarks": [],
    }
    for ip in targets:
        if not _private_or_allowed(ip, allow):
            report["targets"].append({"ip": ip, "blocked":
                                      "目标不在私网/回环，且不在 --allow-cidr 授权内"})
            continue
        t = probe_target(ip, args)
        evaluate_gate(t)                    # 就地写入 gate/kappa_view
        report["targets"].append(t)
    for ip in [x.strip() for x in args.landmarks.split(",") if x.strip()]:
        report["landmarks"].append({"ip": ip, "path": probe_path(ip)})
    report["t_end"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    text = json.dumps(report, ensure_ascii=False, indent=1)
    if args.json == "-":
        print(text)
    else:
        with open(args.json, "w", encoding="utf-8") as fh:
            fh.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
