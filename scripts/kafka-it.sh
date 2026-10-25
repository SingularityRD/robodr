#!/usr/bin/env bash
# Real-broker integration test of the std-only Kafka producer and
# robodr-kafka-publish (crates/robodr-export/tests/kafka_real_broker.rs).
#
#   scripts/kafka-it.sh
#
# Starts a single-node KRaft Apache Kafka broker in docker, prepares it,
# runs the #[ignore]d real-broker tests against it and removes the
# container again (also on failure or Ctrl-C).
#
# Broker listeners (published on the docker host):
#   PLAINTEXT  $KAFKA_IT_PORT       (default 19092)  the tests' broker
#   SASL       $KAFKA_IT_SASL_PORT  (default 19094)  SASL_PLAINTEXT/PLAIN: must fail cleanly
#   TLS        $KAFKA_IT_TLS_PORT   (default 19095)  SSL, self-signed: must fail cleanly
#   INTERNAL   29092 inside the container (broker tooling only)
# Broker settings: no topic auto-creation, StandardAuthorizer with
# allow.everyone.if.no.acl.found=true, connections.max.idle.ms=10000.
# Prepared state:
#   robodr.findings  12 partitions
#   robodr-it-small     1 partition, max.message.bytes=4096
#   robodr-it-denied    1 partition, ACL DENY User:ANONYMOUS WRITE
#   robodr-it-murmur    12 partitions, 200+ records keyed by robot id written
#                       by kafka-console-producer (the Java partitioner)
#   quota               producer_byte_rate=65536 for client id robodr-it-throttled
#
# Environment:
#   KAFKA_IT_DOCKER=cmd     docker CLI (default: docker; e.g. docker.exe from
#                           WSL without Docker Desktop's WSL integration)
#   KAFKA_IT_IMAGE=image    broker image (default: apache/kafka:3.9.1; also
#                           verified with apache/kafka:4.1.0)
#   KAFKA_IT_NAME=name      container name (default: robodr-kafka-it)
#   KAFKA_IT_HOST=host      address the tests use to reach the published ports,
#                           also advertised by the broker (default: localhost)
#   KAFKA_IT_PORT / KAFKA_IT_SASL_PORT / KAFKA_IT_TLS_PORT   host ports
#   KAFKA_IT_KEEP=1         leave the broker running afterwards
#   CARGO_FLAGS="..."       extra cargo flags, e.g. "--locked --offline"
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/.." && pwd)"

docker_cmd="${KAFKA_IT_DOCKER:-docker}"
image="${KAFKA_IT_IMAGE:-apache/kafka:3.9.1}"
name="${KAFKA_IT_NAME:-robodr-kafka-it}"
host="${KAFKA_IT_HOST:-localhost}"
port="${KAFKA_IT_PORT:-19092}"
sasl_port="${KAFKA_IT_SASL_PORT:-19094}"
tls_port="${KAFKA_IT_TLS_PORT:-19095}"
idle_ms=10000
read -r -a cargo_flags <<<"${CARGO_FLAGS:-}"

docker() { MSYS_NO_PATHCONV=1 "$docker_cmd" "$@"; }
kexec() { docker exec -i "$name" "$@"; }
kbin() {
  local tool="$1"
  shift
  kexec "/opt/kafka/bin/$tool" --bootstrap-server localhost:29092 "$@"
}

cleanup() {
  if [[ "${KAFKA_IT_KEEP:-0}" == 1 ]]; then
    echo "kafka-it: leaving $name running ($host:$port)"
  else
    docker rm -f "$name" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT
trap 'exit 130' INT TERM

docker rm -f "$name" >/dev/null 2>&1 || true
echo "kafka-it: starting $image as $name"
# The listener names avoid "SSL://" on purpose: the image's configure
# script then demands its own secrets layout; TLS:SSL maps the protocol.
docker run -d --name "$name" \
  -p "$port:9092" -p "$sasl_port:9094" -p "$tls_port:9095" \
  -e KAFKA_NODE_ID=1 \
  -e KAFKA_PROCESS_ROLES=broker,controller \
  -e KAFKA_CONTROLLER_QUORUM_VOTERS=1@localhost:9093 \
  -e KAFKA_LISTENERS=PLAINTEXT://:9092,INTERNAL://:29092,SASL://:9094,TLS://:9095,CONTROLLER://:9093 \
  -e "KAFKA_ADVERTISED_LISTENERS=PLAINTEXT://$host:$port,INTERNAL://localhost:29092,SASL://$host:$sasl_port,TLS://$host:$tls_port" \
  -e KAFKA_LISTENER_SECURITY_PROTOCOL_MAP=CONTROLLER:PLAINTEXT,PLAINTEXT:PLAINTEXT,INTERNAL:PLAINTEXT,SASL:SASL_PLAINTEXT,TLS:SSL \
  -e KAFKA_CONTROLLER_LISTENER_NAMES=CONTROLLER \
  -e KAFKA_INTER_BROKER_LISTENER_NAME=INTERNAL \
  -e KAFKA_SASL_ENABLED_MECHANISMS=PLAIN \
  -e 'KAFKA_LISTENER_NAME_SASL_PLAIN_SASL_JAAS_CONFIG=org.apache.kafka.common.security.plain.PlainLoginModule required user_robodr="robodr-it";' \
  -e KAFKA_SSL_KEYSTORE_LOCATION=/tmp/robodr-it.p12 \
  -e KAFKA_SSL_KEYSTORE_TYPE=PKCS12 \
  -e KAFKA_SSL_KEYSTORE_PASSWORD=robodr-it \
  -e KAFKA_SSL_KEY_PASSWORD=robodr-it \
  -e KAFKA_AUTHORIZER_CLASS_NAME=org.apache.kafka.metadata.authorizer.StandardAuthorizer \
  -e KAFKA_ALLOW_EVERYONE_IF_NO_ACL_FOUND=true \
  -e KAFKA_AUTO_CREATE_TOPICS_ENABLE=false \
  -e "KAFKA_CONNECTIONS_MAX_IDLE_MS=$idle_ms" \
  -e KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR=1 \
  -e KAFKA_TRANSACTION_STATE_LOG_REPLICATION_FACTOR=1 \
  -e KAFKA_TRANSACTION_STATE_LOG_MIN_ISR=1 \
  -e KAFKA_GROUP_INITIAL_REBALANCE_DELAY_MS=0 \
  "$image" sh -c '[ -f /tmp/robodr-it.p12 ] || keytool -genkeypair -alias broker \
      -keyalg RSA -keysize 2048 -keystore /tmp/robodr-it.p12 -storetype PKCS12 \
      -storepass robodr-it -keypass robodr-it -dname CN=localhost -validity 2 \
      >/dev/null 2>&1 || exit 1
    exec /etc/kafka/docker/run' >/dev/null

echo "kafka-it: waiting for the broker"
for i in $(seq 1 90); do
  if kbin kafka-topics.sh --list >/dev/null 2>&1; then
    break
  fi
  if [[ "$i" == 90 ]]; then
    docker logs "$name" 2>&1 | tail -30
    echo "kafka-it: broker did not come up" >&2
    exit 1
  fi
  sleep 1
done

echo "kafka-it: creating topics, ACL, quota"
kbin kafka-topics.sh --create --topic robodr.findings --partitions 12 --replication-factor 1 >/dev/null
kbin kafka-topics.sh --create --topic robodr-it-small --partitions 1 --replication-factor 1 \
  --config max.message.bytes=4096 >/dev/null
kbin kafka-topics.sh --create --topic robodr-it-denied --partitions 1 --replication-factor 1 >/dev/null
kbin kafka-topics.sh --create --topic robodr-it-murmur --partitions 12 --replication-factor 1 >/dev/null
kbin kafka-acls.sh --add --deny-principal User:ANONYMOUS --operation Write \
  --topic robodr-it-denied >/dev/null
kbin kafka-configs.sh --alter --entity-type clients --entity-name robodr-it-throttled \
  --add-config producer_byte_rate=65536 >/dev/null
{
  for i in $(seq 0 199); do
    printf 'ugv-%03d\tx\n' "$i"
  done
  printf '%s\tx\n' uav-101 agv-9999 "robot-ü-42" "R" "a-very-long-robot-identifier-0123456789"
} | kexec /opt/kafka/bin/kafka-console-producer.sh --bootstrap-server localhost:29092 \
  --topic robodr-it-murmur --property parse.key=true --property key.separator="$(printf '\t')" \
  >/dev/null

export ROBODR_KAFKA_BROKER="$host:$port"
export ROBODR_KAFKA_SASL_BROKER="$host:$sasl_port"
export ROBODR_KAFKA_TLS_BROKER="$host:$tls_port"
export ROBODR_KAFKA_IDLE_MS="$idle_ms"
export ROBODR_KAFKA_QUOTA=1
export ROBODR_KAFKA_RESTART_CMD="MSYS_NO_PATHCONV=1 $docker_cmd restart $name"

cd "$root"
echo "kafka-it: running the real-broker tests against $image"
cargo test "${cargo_flags[@]}" -p robodr-export --test kafka_real_broker -- \
  --ignored --test-threads=1 --nocapture --skip real_broker_restart_mid_stream
# Last: restarts the broker.
cargo test "${cargo_flags[@]}" -p robodr-export --test kafka_real_broker -- \
  --ignored --test-threads=1 --nocapture --exact real_broker_restart_mid_stream

echo "kafka-it: cross-check with the broker's own tooling"
# kafka-dump-log re-reads every stored batch and recomputes its CRC-32C.
bad=0
# shellcheck disable=SC2016 # expanded by the container's shell
dump="$(kexec sh -c 'for d in $(find / -maxdepth 4 -type d -name "robodr.findings-*" 2>/dev/null); do
    for f in "$d"/*.log; do /opt/kafka/bin/kafka-dump-log.sh --deep-iteration --files "$f"; done
  done' 2>/dev/null || true)"
valid="$(grep -c "isvalid: true" <<<"$dump" || true)"
if [[ "$valid" == 0 ]] || grep -q "isvalid: false" <<<"$dump"; then
  echo "kafka-it: kafka-dump-log found no batches or an invalid CRC" >&2
  bad=1
else
  echo "kafka-it: kafka-dump-log: $valid batches, all CRCs valid"
fi
kexec /opt/kafka/bin/kafka-console-consumer.sh --bootstrap-server localhost:29092 \
  --topic robodr.findings --from-beginning --max-messages 1 --timeout-ms 20000 \
  --property print.headers=true --property print.key=true --property print.partition=true \
  2>/dev/null | cut -c1-400 || true
if [[ "$bad" != 0 ]]; then
  exit 1
fi
echo "kafka-it: OK ($image)"
