#!/bin/sh

set -eu

image=${1:?usage: container-contract.sh IMAGE}

fail() {
    printf 'container contract: %s\n' "$*" >&2
    exit 1
}

configured_user=$(docker image inspect --format '{{.Config.User}}' "$image")
case "$configured_user" in
    ''|0|root) fail "image must configure a non-root runtime user" ;;
esac

configured_entrypoint=$(docker image inspect --format '{{json .Config.Entrypoint}}' "$image")
[ "$configured_entrypoint" = '["venom"]' ] || \
    fail "unexpected entrypoint: $configured_entrypoint"

configured_command=$(docker image inspect --format '{{json .Config.Cmd}}' "$image")
[ "$configured_command" = '["--help"]' ] || \
    fail "unexpected default command: $configured_command"

exposed_ports=$(docker image inspect --format '{{json .Config.ExposedPorts}}' "$image")
case "$exposed_ports" in
    null|'{}') ;;
    *) fail "image exposes unsupported ports: $exposed_ports" ;;
esac

healthcheck=$(docker image inspect --format '{{json .Config.Healthcheck}}' "$image")
[ "$healthcheck" = 'null' ] || \
    fail "image contains an unsupported healthcheck: $healthcheck"

runtime_uid=$(docker run --rm --entrypoint /usr/bin/id "$image" -u)
case "$runtime_uid" in
    ''|*[!0-9]*) fail "runtime UID is not numeric: $runtime_uid" ;;
    0) fail "container process runs as root" ;;
esac

docker run --rm "$image" >/dev/null
docker run --rm "$image" --help >/dev/null

printf '%s\n' 'container distribution contract passed'
