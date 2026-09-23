#!/usr/bin/env bash
# Usage: ./services.sh [start|stop|restart|status|build|certs|menu]
# No argument: interactive menu on a TTY, otherwise start.
# certs: generate dev certs if missing (certs --force to regenerate; wipes certs/*.pem incl. gateway-public.pem)
# Order: sso-server (uv) -> oauth2-server -> sso-gateway-mvc -> sso-client1 -> sso-client2
# Extra JVM/Spring args for all Java apps: JAVA_OPTS="-Dspring.profiles.active=ping-preauth" ./services.sh
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUN_DIR="$ROOT/.run"
LOG_DIR="$RUN_DIR/logs"
WAIT_SECS="${WAIT_SECS:-90}"
mkdir -p "$LOG_DIR"

# name:port:kind (kind = uv | jar:<module>)
SERVICES=(
  "sso-server:5000:uv"
  "oauth2-server:8077:jar:oauth2-server"
  "sso-gateway-mvc:8078:jar:sso-gateway-mvc"
  "sso-client1:8081:jar:sso-client1"
  "sso-client2:8082:jar:sso-client2"
)

pidfile() { echo "$RUN_DIR/$1.pid"; }
is_running() { [[ -f "$(pidfile "$1")" ]] && kill -0 "$(cat "$(pidfile "$1")")" 2>/dev/null; }
port_open() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }

build() {
  (cd "$ROOT" && mvn -q -DskipTests package -pl auth-common-jdbc,oauth2-server,sso-gateway-mvc,sso-client-common,sso-client1,sso-client2 -am)
}

start_one() {
  local name port kind module
  IFS=: read -r name port kind module <<<"$1"
  if is_running "$name"; then echo "$name already running (pid $(cat "$(pidfile "$name")"))"; return 0; fi

  echo "Starting $name on :$port ..."
  if [[ "$kind" == "uv" ]]; then
    ( cd "$ROOT/$name" && exec setsid nohup uv run src/app.py >"$LOG_DIR/$name.log" 2>&1 ) &
    echo $! >"$(pidfile "$name")"
  else
    local jar="$ROOT/$module/target/$module-0.1.jar"
    [[ -f "$jar" ]] || { echo "  $jar missing; run: $0 build"; return 1; }
    # shellcheck disable=SC2086
    ( cd "$ROOT/$module" && exec setsid nohup java ${JAVA_OPTS:-} -jar "$jar" >"$LOG_DIR/$name.log" 2>&1 ) &
    echo $! >"$(pidfile "$name")"
  fi

  local i=0
  until port_open "$port"; do
    is_running "$name" || { echo "  $name died; see $LOG_DIR/$name.log"; return 1; }
    (( ++i > WAIT_SECS )) && { echo "  $name not listening on :$port after ${WAIT_SECS}s; see $LOG_DIR/$name.log"; return 1; }
    sleep 1
  done
  echo "  $name up (pid $(cat "$(pidfile "$name")"))"
}

stop_one() {
  local name="${1%%:*}" pid
  is_running "$name" || { rm -f "$(pidfile "$name")"; return 0; }
  pid="$(cat "$(pidfile "$name")")"
  echo "Stopping $name (pid $pid) ..."
  kill -- "-$pid" 2>/dev/null || kill "$pid" 2>/dev/null
  for _ in $(seq 1 20); do kill -0 "$pid" 2>/dev/null || break; sleep 0.5; done
  kill -0 "$pid" 2>/dev/null && kill -9 -- "-$pid" 2>/dev/null
  rm -f "$(pidfile "$name")"
}

certs() {
  if [[ "${1:-}" != "--force" && -f "$ROOT/certs/services.p12" && -f "$ROOT/certs/truststore.jks" ]]; then
    echo "Certs present (use 'certs --force' to regenerate)."; return 0
  fi
  echo "Generating certs ..."
  (cd "$ROOT/certs" && bash generate-certs.sh)
}

menu() {
  local PS3="Choice: "
  select opt in start stop restart status build certs "certs --force" quit; do
    case "$opt" in
      start) certs; start_all ;;
      stop) stop_all ;;
      restart) stop_all; certs; start_all ;;
      status) status_all ;;
      build) build ;;
      certs) certs ;;
      "certs --force") certs --force ;;
      quit) break ;;
    esac
  done
}

start_all() {
  for s in "${SERVICES[@]}"; do
    start_one "$s" || { echo "Aborting; stopping started services."; stop_all; exit 1; }
  done
  echo "All services up. Logs: $LOG_DIR"
}

stop_all() {
  for (( i=${#SERVICES[@]}-1; i>=0; i-- )); do stop_one "${SERVICES[i]}"; done
}

status_all() {
  for s in "${SERVICES[@]}"; do
    IFS=: read -r name port _ <<<"$s"
    if is_running "$name"; then echo "$name  running  pid $(cat "$(pidfile "$name")")  :$port"; else echo "$name  stopped"; fi
  done
}

if [[ $# -eq 0 ]]; then
  if [[ -t 0 && -t 1 ]]; then set -- menu; else set -- start; fi
fi

case "$1" in
  start)   certs; start_all ;;
  stop)    stop_all ;;
  restart) stop_all; certs; start_all ;;
  status)  status_all ;;
  build)   build ;;
  certs)   certs "${2:-}" ;;
  menu)    menu ;;
  *) echo "Usage: $0 [start|stop|restart|status|build|certs|menu]"; exit 2 ;;
esac
