#!/bin/sh
# ZoneAudit CLI installer for macOS, Linux and BSD.
#
#   curl -fsSL https://zoneaudit.com/install.sh | sh
#
# Downloads the latest release of github.com/ZoneAudit/zoneaudit-cli for
# this computer, checks it against the release's published SHA-256
# checksums, and installs the `zoneaudit` binary to ~/.local/bin (or
# $ZONEAUDIT_INSTALL_DIR). It never uses sudo and stops on the first error.
#
# Everything runs inside main(), so a partly downloaded script does nothing.

set -eu

REPO="ZoneAudit/zoneaudit-cli"
BINARY="zoneaudit"

say() { printf '%s\n' "zoneaudit-install: $*"; }
fail() { printf '%s\n' "zoneaudit-install: error: $*" >&2; exit 1; }

detect_os() {
  case "$(uname -s)" in
    Linux) echo linux ;;
    Darwin) echo darwin ;;
    FreeBSD | OpenBSD | NetBSD | DragonFly)
      fail "no BSD build is published yet. Build from source with Go 1.22 or later:
  go install github.com/${REPO}/cmd/zoneaudit@latest" ;;
    *) fail "unsupported operating system: $(uname -s). On Windows, run in PowerShell:
  irm https://zoneaudit.com/install.ps1 | iex" ;;
  esac
}

detect_arch() {
  case "$(uname -m)" in
    x86_64 | amd64) echo amd64 ;;
    arm64 | aarch64) echo arm64 ;;
    *) fail "unsupported processor architecture: $(uname -m)" ;;
  esac
}

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d ' ' -f 1
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | cut -d ' ' -f 1
  else
    fail "neither sha256sum nor shasum is available, so the download cannot be verified"
  fi
}

main() {
  command -v curl >/dev/null 2>&1 || fail "curl is required"
  command -v tar >/dev/null 2>&1 || fail "tar is required"

  os="$(detect_os)"
  arch="$(detect_arch)"

  # The latest release's tag, from where /releases/latest redirects to.
  latest_url="$(curl -fsSLI -o /dev/null -w '%{url_effective}' "https://github.com/${REPO}/releases/latest")"
  tag="${latest_url##*/}"
  case "$tag" in
    v[0-9]*) ;;
    *) fail "could not find the latest release (got '${tag}')" ;;
  esac
  version="${tag#v}"

  asset="zoneaudit-cli_${version}_${os}_${arch}.tar.gz"
  base="https://github.com/${REPO}/releases/download/${tag}"

  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT INT TERM

  say "downloading ZoneAudit CLI ${tag} for ${os}/${arch}"
  curl -fsSL -o "${tmp}/${asset}" "${base}/${asset}" || fail "download failed: ${base}/${asset}"

  if curl -fsSL -o "${tmp}/checksums.txt" "${base}/checksums.txt"; then
    expected="$(awk -v f="$asset" '$2 == f { print $1 }' "${tmp}/checksums.txt")"
    [ -n "$expected" ] || fail "${asset} is not listed in checksums.txt"
    actual="$(sha256_of "${tmp}/${asset}")"
    [ "$expected" = "$actual" ] || fail "checksum mismatch for ${asset}; nothing was installed"
    say "checksum verified (SHA-256)"
  else
    say "warning: this release publishes no checksums.txt, so the download was not verified"
  fi

  tar -xzf "${tmp}/${asset}" -C "$tmp" "$BINARY" || fail "could not unpack ${asset}"

  install_dir="${ZONEAUDIT_INSTALL_DIR:-$HOME/.local/bin}"
  mkdir -p "$install_dir"
  mv "${tmp}/${BINARY}" "${install_dir}/${BINARY}"
  chmod 0755 "${install_dir}/${BINARY}"

  say "installed ${tag} to ${install_dir}/${BINARY}"
  case ":${PATH}:" in
    *":${install_dir}:"*) say "run: zoneaudit --help" ;;
    *) say "${install_dir} is not on your PATH. Add this line to your shell profile, then open a new terminal:
  export PATH=\"${install_dir}:\$PATH\"" ;;
  esac
}

main "$@"
