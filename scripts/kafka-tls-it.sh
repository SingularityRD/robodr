#!/usr/bin/env bash
# Real-broker integration test of the Kafka producer's TLS, mutual TLS and
# SASL/SCRAM (crates/robodr-export/tests/kafka_real_broker.rs, the
# `real_tls_*` / `real_mtls_*` / `real_scram_*` tests), and of the rest of
# that file, against a single-node KRaft Apache Kafka started from a local
# distribution (no docker):
#
#   KAFKA_HOME=/path/to/kafka_2.13-3.9.1 scripts/kafka-tls-it.sh
#
# Needs java (17+), openssl and keytool. The broker's certificate is the
# test PKI of fixtures/tls/ (server.pem: SAN DNS:localhost, IP:127.0.0.1),
# so the producer verifies the advertised host name `localhost` against
# fixtures/tls/ca.pem.
#
# Listeners (all on localhost):
#   PLAINTEXT  $KAFKA_IT_PORT       (19092)  the plain tests
#   SASL       $KAFKA_IT_SASL_PORT  (19094)  SASL_PLAINTEXT/PLAIN: must fail cleanly
#   TLS        $KAFKA_IT_TLS_PORT   (19095)  SSL, server-authenticated
#   MTLS       $KAFKA_IT_MTLS_PORT  (19096)  SSL, ssl.client.auth=required (CA: ca.pem)
#   SCRAM      $KAFKA_IT_SCRAM_PORT (19097)  SASL_SSL, SCRAM-SHA-256/512,
#                                            connections.max.reauth.ms=8000
#   INTERNAL   29092 (tooling), CONTROLLER 29093
#
# Environment: KAFKA_IT_KEEP=1 leaves the broker running; CARGO_FLAGS.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/.." && pwd)"
pki="$root/fixtures/tls"
: "${KAFKA_HOME:?set KAFKA_HOME to an extracted Apache Kafka distribution}"
port="${KAFKA_IT_PORT:-19092}"
sasl_port="${KAFKA_IT_SASL_PORT:-19094}"
tls_port="${KAFKA_IT_TLS_PORT:-19095}"
mtls_port="${KAFKA_IT_MTLS_PORT:-19096}"
scram_port="${KAFKA_IT_SCRAM_PORT:-19097}"
idle_ms=10000
scram_user=robodr-it
scram_pw='robodr-it-scram-pw'
read -r -a cargo_flags <<<"${CARGO_FLAGS:-}"

work="$(mktemp -d)"
pid=""
cleanup() {
  if [[ -n "$pid" && "${KAFKA_IT_KEEP:-0}" != 1 ]]; then
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  fi
  if [[ "${KAFKA_IT_KEEP:-0}" != 1 ]]; then
    rm -rf "$work"
  else
    echo "kafka-tls-it: leaving the broker running (pid $pid, $work)"
  fi
}
trap cleanup EXIT
trap 'exit 130' INT TERM

echo "kafka-tls-it: key and trust stores from fixtures/tls"
openssl pkcs12 -export -in "$pki/server.pem" -inkey "$pki/server.key" -certfile "$pki/ca.pem" \
  -name broker -passout pass:robodr-it -out "$work/broker.p12"
keytool -importcert -noprompt -alias ca -file "$pki/ca.pem" -keystore "$work/trust.p12" \
  -storetype PKCS12 -storepass robodr-it >/dev/null 2>&1

cat >"$work/server.properties" <<EOF
process.roles=broker,controller
node.id=1
controller.quorum.voters=1@localhost:29093
listeners=PLAINTEXT://localhost:$port,SASL://localhost:$sasl_port,TLS://localhost:$tls_port,MTLS://localhost:$mtls_port,SCRAM://localhost:$scram_port,INTERNAL://localhost:29092,CONTROLLER://localhost:29093
advertised.listeners=PLAINTEXT://localhost:$port,SASL://localhost:$sasl_port,TLS://localhost:$tls_port,MTLS://localhost:$mtls_port,SCRAM://localhost:$scram_port,INTERNAL://localhost:29092
listener.security.protocol.map=CONTROLLER:PLAINTEXT,PLAINTEXT:PLAINTEXT,INTERNAL:PLAINTEXT,SASL:SASL_PLAINTEXT,TLS:SSL,MTLS:SSL,SCRAM:SASL_SSL
controller.listener.names=CONTROLLER
inter.broker.listener.name=INTERNAL
log.dirs=$work/data
num.partitions=1
offsets.topic.replication.factor=1
transaction.state.log.replication.factor=1
transaction.state.log.min.isr=1
group.initial.rebalance.delay.ms=0
auto.create.topics.enable=false
connections.max.idle.ms=$idle_ms
authorizer.class.name=org.apache.kafka.metadata.authorizer.StandardAuthorizer
allow.everyone.if.no.acl.found=true
ssl.keystore.location=$work/broker.p12
ssl.keystore.type=PKCS12
ssl.keystore.password=robodr-it
ssl.key.password=robodr-it
ssl.truststore.location=$work/trust.p12
ssl.truststore.type=PKCS12
ssl.truststore.password=robodr-it
listener.name.mtls.ssl.client.auth=required
listener.name.sasl.sasl.enabled.mechanisms=PLAIN
listener.name.sasl.plain.sasl.jaas.config=org.apache.kafka.common.security.plain.PlainLoginModule required user_robodr="robodr-it";
listener.name.scram.sasl.enabled.mechanisms=SCRAM-SHA-256,SCRAM-SHA-512
listener.name.scram.scram-sha-256.sasl.jaas.config=org.apache.kafka.common.security.scram.ScramLoginModule required;
listener.name.scram.scram-sha-512.sasl.jaas.config=org.apache.kafka.common.security.scram.ScramLoginModule required;
listener.name.scram.connections.max.reauth.ms=8000
EOF

export KAFKA_HEAP_OPTS="-Xmx512m -Xms256m"
export LOG_DIR="$work/logs"
cluster_id="$("$KAFKA_HOME/bin/kafka-storage.sh" random-uuid)"
"$KAFKA_HOME/bin/kafka-storage.sh" format -t "$cluster_id" -c "$work/server.properties" \
  --add-scram "SCRAM-SHA-256=[name=$scram_user,password=$scram_pw]" \
  --add-scram "SCRAM-SHA-512=[name=$scram_user,password=$scram_pw]" >/dev/null
echo "kafka-tls-it: starting the broker ($KAFKA_HOME)"
"$KAFKA_HOME/bin/kafka-server-start.sh" "$work/server.properties" >"$work/broker.log" 2>&1 &
pid=$!

kbin() {
  local tool="$1"
  shift
  "$KAFKA_HOME/bin/$tool" --bootstrap-server localhost:29092 "$@"
}
for i in $(seq 1 90); do
  if kbin kafka-topics.sh --list >/dev/null 2>&1; then
    break
  fi
  if [[ "$i" == 90 ]] || ! kill -0 "$pid" 2>/dev/null; then
    tail -40 "$work/broker.log"
    echo "kafka-tls-it: broker did not come up" >&2
    exit 1
  fi
  sleep 1
done

echo "kafka-tls-it: creating topics, ACL, quota"
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
} | "$KAFKA_HOME/bin/kafka-console-producer.sh" --bootstrap-server localhost:29092 \
  --topic robodr-it-murmur --property parse.key=true --property key.separator="$(printf '\t')" \
  >/dev/null

export ROBODR_KAFKA_BROKER="localhost:$port"
export ROBODR_KAFKA_SASL_BROKER="localhost:$sasl_port"
export ROBODR_KAFKA_TLS_BROKER="localhost:$tls_port"
export ROBODR_KAFKA_MTLS_BROKER="localhost:$mtls_port"
export ROBODR_KAFKA_SCRAM_BROKER="localhost:$scram_port"
export ROBODR_KAFKA_SCRAM_USER="$scram_user"
export ROBODR_KAFKA_SCRAM_PASSWORD="$scram_pw"
export ROBODR_KAFKA_SCRAM_REAUTH_MS=8000
export ROBODR_KAFKA_TLS_PKI="$pki"
export ROBODR_KAFKA_IDLE_MS="$idle_ms"
export ROBODR_KAFKA_QUOTA=1

cd "$root"
echo "kafka-tls-it: running the real-broker tests (no restart test: see kafka-it.sh)"
cargo test "${cargo_flags[@]}" -p robodr-export --test kafka_real_broker -- \
  --ignored --test-threads=1 --skip real_broker_restart_mid_stream
echo "kafka-tls-it: OK ($("$KAFKA_HOME/bin/kafka-topics.sh" --version 2>/dev/null | head -1))"
