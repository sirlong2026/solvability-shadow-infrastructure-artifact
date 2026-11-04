#!/usr/bin/env bash
# run.sh —— 采集→比对→真值核对（在 20 号 root；先 topo base + 某场景）
set -euo pipefail
LAB="$(cd "$(dirname "$0")" && pwd)"; REPO="$LAB/.."
DATASET="$LAB/dataset"; mkdir -p "$DATASET"

if [ "${1:-}" = "collect" ]; then
  sc="${2:?用法: run.sh collect <s0..s5|all>}"; 
  one(){
    t="$(cat "$LAB/.scenario.target")"
    sni=""; [ -f "$LAB/.scenario.snihosts" ] && sni="--sni-hosts $(cat "$LAB/.scenario.snihosts")"
    echo "== 场景 $1 目标 $t ${sni:+（SNI: $sni）} =="
    for s in sens1 sens2; do
      ip netns exec "$s" python3 "$REPO/tools/sensor_agent.py" --id "$s" \
        --targets "$t" --allow-cidr 10.198.0.0/16 \
        --ttl-samples 15 --skew-samples 20 --skew-interval 1.0 \
        --tls-samples 10 --tls-interval 0.4 ${sni:+$sni} \
        --json "$DATASET/${1}_${s}.json"
      echo "   ${s} 采集完"
    done
    python3 "$REPO/tools/sensor_compare.py" "$DATASET/${1}_sens1.json" "$DATASET/${1}_sens2.json" \
      --out "$DATASET/${1}_compare.json"
    python3 "$LAB/evaluate.py" "$1" "$DATASET/${1}_compare.json"
  }
  if [ "$sc" = "all" ]; then for s in s0 s1 s2 s3 s4 s5 s6; do "$LAB/topo.sh" "$s"; one "$s"; done
  else one "$sc"; fi
  exit 0
fi

cat <<'EOF'
run.sh collect <s0..s5|all>   —— 对已部署场景采集双传感器并比对判卷
推荐全流程：
  sudo ./gen_certs.sh
  sudo ./topo.sh base && sudo ./topo.sh s0 && ./run.sh collect s0
  … 或 sudo ./topo.sh base && ./run.sh collect all（逐场景自检自部署）
EOF
