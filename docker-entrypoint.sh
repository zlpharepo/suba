#!/bin/sh
set -eu

umask 077

case "${PUID:-}" in
  ''|*[!0-9]*) echo 'PUID: expected a numeric UID' >&2; exit 1 ;;
esac
case "${PGID:-}" in
  ''|*[!0-9]*) echo 'PGID: expected a numeric GID' >&2; exit 1 ;;
esac

if [ "$(id -u)" -eq 0 ]; then
  # Docker may create bind-mount directories as root before this script runs.
  for dir in "${CONFIG:-/app/config}" "${DATA:-/app/data}"; do
    mkdir -p "$dir"
    if [ "$PUID" -ne 0 ]; then
      chown -R "$PUID:$PGID" "$dir"
    fi
    chmod 0700 "$dir"
  done
  exec gosu "$PUID:$PGID" /usr/local/bin/suba "$@"
fi

if [ "$(id -u)" -ne "$PUID" ] || [ "$(id -g)" -ne "$PGID" ]; then
  echo 'PUID/PGID: must match the container user when started without root' >&2
  exit 1
fi
exec /usr/local/bin/suba "$@"
