#!/usr/bin/env bash
# RoboDR one-command demo (T28).
#
#   demo/run.sh            replay demo: commission, attack, detect, SOC, Kafka
#   demo/run.sh --live     + live robot and attacker (time to detect / to SOC)
#   demo/run.sh --compare  after a run: RoboDR vs Pulsar-only table (T65)
#   demo/run.sh --down     stop and remove the containers (keeps demo/state)
#   demo/run.sh --clean    --down and delete demo/state (all demo keys)
#
# Binaries: $ROBODR_BIN if set (a directory with the release binaries, e.g.
# an unpacked release tarball), else target/release of this checkout, built
# with cargo if missing. Needs docker with compose v2.24+.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/.." && pwd)
cd "$here"

need=(robodr-agentd robodr-commission robodr-blackbox robodr-uplink robodr-kafka-publish
      robodr-attack-sim robodr-demo-soc)
profile=()
case "${1:-}" in
  --down) ROBODR_BIN=${ROBODR_BIN:-$root/target/release} docker compose --profile live down; exit 0 ;;
  --clean)
    export ROBODR_BIN=${ROBODR_BIN:-$root/target/release}
    docker compose --profile live down -v
    # The containers write demo/state as root: delete it from a container.
    [[ -d "$here/state" ]] && docker compose run --rm -T --no-deps robot find /demo/state -mindepth 1 -delete
    docker compose --profile live down
    rmdir "$here/state" 2>/dev/null || true
    exit 0 ;;
  --live) profile=(--profile live) ;;
  --compare)
    export ROBODR_BIN=${ROBODR_BIN:-$root/target/release}
    docker compose run --rm -T robot /demo/scripts/compare.sh
    python3 "$root/tools/e2e/compare_pulsar_only.py" "$here/state/compare"
    exit 0 ;;
  "") ;;
  *) sed -n '2,13p' "$0"; exit 2 ;;
esac

bin=${ROBODR_BIN:-$root/target/release}
missing=()
for b in "${need[@]}"; do [[ -x "$bin/$b" ]] || missing+=("$b"); done
if ((${#missing[@]})); then
  if [[ -n "${ROBODR_BIN:-}" ]]; then
    echo "missing in ROBODR_BIN=$bin: ${missing[*]}" >&2
    exit 1
  fi
  echo "building release binaries: ${missing[*]}"
  (cd "$root" && cargo build --release --locked -p robodr-agentd -p robodr-commission \
    -p robodr-blackbox -p robodr-export -p robodr-attack-sim -p robodr-demo-soc)
fi
export ROBODR_BIN=$bin
mkdir -p "$here/state"
start=$(date +%s)
docker compose "${profile[@]}" up -d
echo "waiting for the first finding at the SOC..."
port=${DEMO_SOC_PORT:-8080}
for _ in $(seq 1 600); do
  n=$(curl -fsS "http://127.0.0.1:$port/api/metrics" 2>/dev/null \
      | sed -n 's/.*"findings":\([0-9]*\).*/\1/p' || true)
  if [[ -n "${n:-}" && "$n" -gt 0 ]]; then
    echo "first findings at the SOC after $(( $(date +%s) - start )) s: $n so far"
    echo "viewer: http://127.0.0.1:$port/   robot score: demo/state/score.json"
    echo "Kafka:  docker compose -f demo/docker-compose.yml exec kafka /opt/kafka/bin/kafka-console-consumer.sh \\"
    echo "          --bootstrap-server kafka:9092 --topic robodr.findings --from-beginning --property print.headers=true"
    exit 0
  fi
  sleep 1
done
echo "no finding reached the SOC within 10 minutes; docker compose -f demo/docker-compose.yml logs" >&2
exit 1
