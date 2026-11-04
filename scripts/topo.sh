#!/usr/bin/env bash
# topo.sh —— 多路径推理实验床（纯 netns，root；不依赖 docker）
# 拓扑（全部在本机，零外部目标，绝对合规）：
#   网段 br1 10.198.1.0/24           网段 br2 10.198.2.0/24
#        sens1(.10) [观测点A]            sens2(.10) [观测点B]
#              \                          /
#                       gw (10.198.1.1, 10.198.2.1, 10.198.3.1)  ★S3 可隐身
#                        |
#               网段 br3 10.198.3.0/24  [目标段]
#        lb(.10)   be1(.11)   be2(.12)   s0(.13)
# sens1/sens2 访问目标段的一切流量必经 gw ⇒ "隐形路由器"由 gw 的 ICMP 应答开关
# 直接决定；后端初始 TTL 可按 ns 设定（触发 TTL 集合分歧），Timestamp 可关
# （触发时钟信号静默）——这些精细旋钮正是选 netns 而非 docker 的原因。
#
# 时钟信号局限说明：同一台主机的全部 ns 共享内核时钟 ⇒ 单主机实验里 skew 恒为单簇。
# 这本身是要记录的方法结论（时钟域法需真实异机），跨机阶段把 34 号接成真第三传感器。
set -euo pipefail
LAB_DIR="$(cd "$(dirname "$0")" && pwd)"

ns_add(){ ip netns list | grep -qw "$1" || ip netns add "$1"; }
br(){  ip link show "$1" >/dev/null 2>&1 || ip link add name "$1" type bridge
      ip link set "$1" up; }
link_ns(){ # link_ns <peer名在host上> <目标ns> <ns内改名>
  ip link set "$1" netns "$2" 2>/dev/null || true
  ip -n "$2" link set "$1" name "$3" 2>/dev/null || true
  ip -n "$2" link set "$3" up; }
attach(){ # attach <ns> <ns内if名> <IP/len> <bridge>  —— 建 veth 并把 host 侧并入网桥
  # 命名须全局唯一且防半程残留：固定 peer 名 "t" 会在部分执行后与下次 add 冲突。
  local ns="$1" ifname="$2" addr="$3" bridge="$4" h p added=""
  for k in 1 2 3 4 5 6 7 8; do
    h="lh$(( (RANDOM + k*97 + ${BASHPID:-$$}) % 60000 ))"
    p="lp$h"
    ip link del "$h" >/dev/null 2>&1 || true
    ip link del "$p"  >/dev/null 2>&1 || true
    if ip link add "$h" type veth peer name "$p" 2>/dev/null; then added=1; break; fi
  done
  [ -n "$added" ] || { echo "attach($ns): veth 创建失败（名字空间冲突）" >&2; return 1; }
  ip link set "$h" master "$bridge" && ip link set "$h" up
  ip link set "$p" netns "$ns"
  ip -n "$ns" link set "$p" name "$ifname"
  ip -n "$ns" addr add "$addr" dev "$ifname" 2>/dev/null || true
  ip -n "$ns" link set "$ifname" up; }
ns_sys(){ ip netns exec "$1" sysctl -qw "$2=$3" >/dev/null; }
ns_no_ts(){ ip netns exec "$1" sh -c "iptables -C INPUT -p icmp --icmp-type timestamp-request -j DROP 2>/dev/null || iptables -I INPUT -p icmp --icmp-type timestamp-request -j DROP"; }
srv(){ local ns="$1"; shift
  ip netns exec "$ns" setsid "$@" >>"$LAB_DIR/.$ns.log" 2>&1 & echo $! > "$LAB_DIR/.$ns.pid"; }

apply_base(){
  echo "[base] namespace + bridge + 路由"
  for n in gw sens1 sens2 be1 be2 s0 lb sni; do ns_add "$n"; done
  for b in br1 br2 br3; do br "$b"; done
  ns_sys gw net.ipv4.ip_forward 1; ns_sys gw net.ipv4.conf.all.rp_filter 0
  attach sens1 eth0 10.198.1.10/24 br1; ip -n sens1 route replace default via 10.198.1.1 2>/dev/null
  attach sens2 eth0 10.198.2.10/24 br2; ip -n sens2 route replace default via 10.198.2.1 2>/dev/null
  attach gw    e1   10.198.1.1/24  br1
  attach gw    e2   10.198.2.1/24  br2
  attach gw    e3   10.198.3.1/24  br3
  for t in "be1 10.198.3.11" "be2 10.198.3.12" "s0 10.198.3.13" "lb 10.198.3.10" "sni 10.198.3.14"; do
    set -- $t; attach "$1" eth0 "$2/24" br3; ip -n "$1" route replace default via 10.198.3.1 2>/dev/null
  done
  cp -f "$LAB_DIR/../tools/sensor_agent.py" "$LAB_DIR/sensor_agent.py"
  sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
  echo "[base] 就绪（自检：ip netns exec sens1 ping -c1 -W1 10.198.3.13）"
}

stop_scenario(){
  for ns in be1 be2 s0 lb sni; do
    [ -f "$LAB_DIR/.$ns.pid" ] && { pkill -g "$(ps -o pgid= "$(cat "$LAB_DIR/.$ns.pid")" | tr -d ' ')" 2>/dev/null || true
                                      kill "$(cat "$LAB_DIR/.$ns.pid")" 2>/dev/null || true; rm -f "$LAB_DIR/.$ns.pid"; }
    ip netns exec gw iptables -F 2>/dev/null || true
 ip netns exec gw iptables -t nat -F 2>/dev/null || true
 # S7 链式路由与第二 NIC 回收（ns 不删，防跨场景污染）
 ip -n gw route del 10.198.3.13/32 2>/dev/null || true
 ip -n sens2 route del 10.198.3.13/32 2>/dev/null || true
 ip -n sens2 link del e3 2>/dev/null || true
  done
}

scenario(){
  local id="$1"; stop_scenario; local CERTS="$LAB_DIR/certs"
  [ -f "$CERTS/be1.crt" ] || { echo "先跑 gen_certs.sh"; exit 3; }
  echo "[$id] 部署…"
  case "$id" in
    s0) ns_sys s0 net.ipv4.ip_default_ttl 64
        srv s0 python3 "$LAB_DIR/tlsd.py" --cert "$CERTS/be1.crt" --key "$CERTS/be1.key" --name s0
        echo 10.198.3.13 >"$LAB_DIR/.scenario.target" ;;
    s1) ns_sys be1 net.ipv4.ip_default_ttl 64; ns_sys be2 net.ipv4.ip_default_ttl 64
        srv be1 python3 "$LAB_DIR/tlsd.py" --cert "$CERTS/be1.crt" --key "$CERTS/be1.key" --name be1
        srv be2 python3 "$LAB_DIR/tlsd.py" --cert "$CERTS/be2.crt" --key "$CERTS/be2.key" --name be2
        srv lb  python3 "$LAB_DIR/lbd.py" --backends 10.198.3.11:443,10.198.3.12:443 --mode rr
        echo 10.198.3.10 >"$LAB_DIR/.scenario.target" ;;
    s2) ns_sys be1 net.ipv4.ip_default_ttl 64; ns_sys be2 net.ipv4.ip_default_ttl 64
        srv be1 python3 "$LAB_DIR/tlsd.py" --cert "$CERTS/be1.crt" --key "$CERTS/be1.key" --name be1
        srv be2 python3 "$LAB_DIR/tlsd.py" --cert "$CERTS/be2.crt" --key "$CERTS/be2.key" --name be2
        srv lb  python3 "$LAB_DIR/lbd.py" --backends 10.198.3.11:443,10.198.3.12:443 --mode hash
        echo 10.198.3.10 >"$LAB_DIR/.scenario.target" ;;
    s3) ns_sys s0 net.ipv4.ip_default_ttl 64
        srv s0 python3 "$LAB_DIR/tlsd.py" --cert "$CERTS/be1.crt" --key "$CERTS/be1.key" --name s0
        ip netns exec gw sh -c "iptables -C INPUT -p icmp -j DROP || iptables -A INPUT -p icmp -j DROP; iptables -C OUTPUT -p icmp -j DROP || iptables -A OUTPUT -p icmp -j DROP"
        echo 10.198.3.13 >"$LAB_DIR/.scenario.target" ;;
    s4) ns_sys be1 net.ipv4.ip_default_ttl 64; ns_sys be2 net.ipv4.ip_default_ttl 255
        # 多出口 TTL 分歧（S4，DSR 版）：旧写法经 lb 应答，响应 TTL 被 lb 网元的
        # ip_default_ttl=64 掩蔽，两后端真实 TTL 差不可见（真机判卷暴露）。现法：
        # gw 对 echo-request 按包轮转 DNAT 至两后端，后端把 VIP 挂 lo 直接应答
        # ——响应包源自各自 netns ⇒ 同一目标 ttl_set={64,255}；证书两边相同 ⇒
        # "应用层一致、仅 TTL 单信号"只匹配 c₄ 多后段/出口，而非 c₂。
        srv be1 python3 "$LAB_DIR/tlsd.py" --cert "$CERTS/be1.crt" --key "$CERTS/be1.key" --name be1
        srv be2 python3 "$LAB_DIR/tlsd.py" --cert "$CERTS/be1.crt" --key "$CERTS/be1.key" --name be2
        ip -n be1 addr add 10.198.3.20/32 dev lo 2>/dev/null || true
        ip -n be2 addr add 10.198.3.20/32 dev lo 2>/dev/null || true
        ip netns exec gw sh -c '
          iptables -t nat -C PREROUTING -d 10.198.3.20 -p icmp --icmp-type echo-request -m statistic --mode nth --every 2 --packet 0 -j DNAT --to-destination 10.198.3.11 2>/dev/null || {
            iptables -t nat -A PREROUTING -d 10.198.3.20 -p icmp --icmp-type echo-request -m statistic --mode nth --every 2 --packet 0 -j DNAT --to-destination 10.198.3.11
            iptables -t nat -A PREROUTING -d 10.198.3.20 -p icmp --icmp-type echo-request -j DNAT --to-destination 10.198.3.12
            iptables -t nat -A PREROUTING -d 10.198.3.20 -p tcp --dport 443 -j DNAT --to-destination 10.198.3.11:443
          }'
        echo 10.198.3.20 >"$LAB_DIR/.scenario.target" ;;
    s5) ns_sys be1 net.ipv4.ip_default_ttl 64; ns_sys be2 net.ipv4.ip_default_ttl 64
        # 同证书、且两 ns 同宿主内核时钟 ⇒ TLS/TTL/时钟全同 = 本机拓扑的原理性盲区：
        # 只有"跨真实主机时钟域 + 跨真实源哈希 LB"场景才能被区分——这是 S5 的教学要点。
        srv be1 python3 "$LAB_DIR/tlsd.py" --cert "$CERTS/shared.crt" --key "$CERTS/shared.key" --name be1
        srv be2 python3 "$LAB_DIR/tlsd.py" --cert "$CERTS/shared.crt" --key "$CERTS/shared.key" --name be2
        srv lb  python3 "$LAB_DIR/lbd.py" --backends 10.198.3.11:443,10.198.3.12:443 --mode hash
        echo 10.198.3.10 >"$LAB_DIR/.scenario.target" ;;
    s6) ns_sys sni net.ipv4.ip_default_ttl 64
        # S6 共享前端多站点（SNI 分发）：单 IP 按域名回不同证书，映射真实云上
        # "769 IP 挂 5529 域名"形态的自管复现（证书全用本机 gen_certs，与演练零血缘）。
        srv sni python3 "$LAB_DIR/tlsd.py" --name sni-front \
          --default "$CERTS/shared.crt" "$CERTS/shared.key" \
          --sni "a.mp.test=$CERTS/be1.crt|$CERTS/be1.key,b.mp.test=$CERTS/be2.crt|$CERTS/be2.key,d.mp.test=$CERTS/shared.crt|$CERTS/shared.key"
        echo 10.198.3.14 >"$LAB_DIR/.scenario.target"
        echo 10.198.3.14 >"$LAB_DIR/.scenario.sni"; echo "a.mp.test,b.mp.test,d.mp.test" >"$LAB_DIR/.scenario.snihosts" ;;
    x1) ns_sys be1 net.ipv4.ip_default_ttl 64; ns_sys be2 net.ipv4.ip_default_ttl 255
        # X1 跨机双钟域 RR（外部效度野考）：不启 lb——VIP:2443 的真实 DNAT 轮询
        # 在 host 层 x1_front.sh：本 be1(64/be1.crt) ↔ 34 号(255/be2.crt)。
        # 两颗真晶振 + 两条真路由 + 两故障域：o₂ 时钟簇与独立性预检的首次实战。
        srv be1 python3 "$LAB_DIR/tlsd.py" --cert "$CERTS/be1.crt" --key "$CERTS/be1.key" --name be1
        srv be2 python3 "$LAB_DIR/tlsd.py" --cert "$CERTS/be2.crt" --key "$CERTS/be2.key" --name be2
        echo "${X1_VIP:?X1_VIP 环境变量未设（VIP 不落文件）}" >"$LAB_DIR/.scenario.target" ;;
    s7) ns_sys s0 net.ipv4.ip_default_ttl 64
        # S7 链式拓扑负样本（形式化§待补③）：把 sens2 塞进 sens1→目标的转发路径中间——
        # gw 路由目标改经 sens2(.2.10)，sens2 挂 e3 并以 /32 主机路由直连目标断环。
        # 判卷口径：chain=true（一方源 IP 命中对方路径）+ 链式降级警告成行；
        # 观测性场景：verdict 只如实登记不断言（负样本考的是"知道自己不该自信"）。
        srv s0 python3 "$LAB_DIR/tlsd.py" --cert "$CERTS/be1.crt" --key "$CERTS/be1.key" --name s0
        attach sens2 e3 10.198.3.16/24 br3
        ns_sys sens2 net.ipv4.ip_forward 1
        ip -n sens2 route replace 10.198.3.13/32 dev e3
        ip -n gw route replace 10.198.3.13/32 via 10.198.2.10 dev e2
        echo 10.198.3.13 >"$LAB_DIR/.scenario.target" ;;
    *) echo "未知场景 $id（s0-s6）"; exit 2 ;;
  esac
  sleep 2
  # 矩阵§四前提：六通道全可观测才可"决定可判"。非 S6 场景 TLS 仍可达但无
  # 特殊 SNI 映射 ⇒ 写中性探测名，使 o₄ 记"可观测-阴性"（区分 c₁ 与 c₅）；
  # 若删掉该通道，S0 与 S6 观察等价、只能落"不可分辨"（README §六注）。
  [ "$id" != s6 ] && { rm -f "$LAB_DIR/.scenario.sni"
    echo "a.mp.test,b.mp.test,d.mp.test" >"$LAB_DIR/.scenario.snihosts"; }
  echo "[$id] 目标=$(cat "$LAB_DIR/.scenario.target")  已就绪"
}

teardown(){ echo "[teardown]"; stop_scenario
  for n in sens1 sens2 gw be1 be2 s0 lb sni; do ip netns delete "$n" 2>/dev/null || true; done
  for b in br1 br2 br3; do ip link delete "$b" 2>/dev/null || true; done
  # 清崩溃可能遗留的 host 侧 attach veth（peer 端随 netns 删除自动消失）
  ip -o link show | awk -F': ' '{print $2}' | grep -E '^lh[0-9]+$' | xargs -r -n1 ip link del 2>/dev/null || true
  rm -f "$LAB_DIR"/.scenario.target "$LAB_DIR"/.scenario.sni "$LAB_DIR"/.scenario.snihosts \
        "$LAB_DIR"/.be*.log "$LAB_DIR"/.lb*.log "$LAB_DIR"/.s0*.log "$LAB_DIR"/.sni*.log; }

case "${1:-}" in
  base) apply_base ;;
  s0|s1|s2|s3|s4|s5|s6|s7|x1) scenario "$1" ;;
  teardown) teardown ;;
  *) cat <<'EOF'
用法: sudo ./topo.sh base           # 一次性建拓扑
      sudo ./topo.sh s0..s6         # 部署某场景（随后跑 run.sh collect <场景>）
      sudo ./topo.sh teardown       # 全部拆除
EOF
  ;;
esac
