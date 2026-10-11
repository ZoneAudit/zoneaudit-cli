#!/bin/sh
# Runs the vendored install.sh (unchanged copy of zoneaudit-lp
# public/install.sh) against release artefacts.
#
#   test-install.sh local <dist-dir>   artefacts built in CI, served by fakerelease
#   test-install.sh live               the latest published GitHub release
#
# In local mode the copy under test has https://github.com rewritten to the
# local fake server in a temporary file; the vendored file is never edited.
set -eu

here="$(cd "$(dirname "$0")" && pwd)"
mode="${1:-}"
work="$(mktemp -d)"
cleanup() { [ -n "${server_pid:-}" ] && kill "$server_pid" 2>/dev/null || true; rm -rf "$work"; }
trap cleanup EXIT INT TERM

addr="127.0.0.1:8765"

start_server() {
  go build -o "$work/fakerelease" "$here/fakerelease"
  "$work/fakerelease" -dist "$1" -addr "$addr" $2 &
  server_pid=$!
  i=0
  until curl -fsS "http://$addr/healthz" >/dev/null 2>&1; do
    i=$((i + 1)); [ "$i" -lt 50 ] || { echo "fake release server did not start" >&2; exit 1; }
    sleep 0.2
  done
}

stop_server() { kill "$server_pid" 2>/dev/null || true; wait "$server_pid" 2>/dev/null || true; server_pid=""; }

case "$mode" in
  local)
    dist="$(cd "${2:?dist directory required}" && pwd)"
    sed "s#https://github.com#http://$addr#g" "$here/install.sh" > "$work/install.sh"
    expected="$(awk '{print $2}' "$dist/checksums.txt" | sed -n 's/^zoneaudit-cli_\(.*\)_linux_amd64\.tar\.gz$/\1/p')"

    echo "== tampered checksums must be refused"
    start_server "$dist" -tamper
    if ZONEAUDIT_INSTALL_DIR="$work/bad" sh "$work/install.sh"; then
      echo "FAIL: installer accepted a tampered checksum" >&2; exit 1
    fi
    [ ! -e "$work/bad/zoneaudit" ] || { echo "FAIL: binary installed despite checksum mismatch" >&2; exit 1; }
    stop_server

    echo "== install from CI artefacts (curl | sh)"
    start_server "$dist" ""
    cat "$work/install.sh" | ZONEAUDIT_INSTALL_DIR="$work/bin" sh
    got="$("$work/bin/zoneaudit" -version)"
    echo "installed: $got"
    [ "$got" = "zoneaudit $expected" ] || { echo "FAIL: expected 'zoneaudit $expected'" >&2; exit 1; }
    "$work/bin/zoneaudit" -h 2>&1 | grep -q "RESPONSIBLE USE" || { echo "FAIL: help lacks the responsible-use notice" >&2; exit 1; }
    ;;
  live)
    echo "== install the latest published release (curl | sh)"
    cat "$here/install.sh" | ZONEAUDIT_INSTALL_DIR="$work/bin" sh
    "$work/bin/zoneaudit" -h >"$work/help.txt" 2>&1 || true
    grep -q -- "-d" "$work/help.txt" || { cat "$work/help.txt"; echo "FAIL: installed binary did not run" >&2; exit 1; }
    ;;
  *)
    echo "usage: $0 local <dist-dir> | live" >&2; exit 2 ;;
esac
echo "PASS ($mode, $(uname -s)/$(uname -m))"
