#!/bin/sh
# taildoc installer: downloads the latest release binary for your platform.
# Usage: curl -fsSL https://raw.githubusercontent.com/huza1fa/taildoc/master/install.sh | sh
set -eu

REPO="huza1fa/taildoc"
DEST="${TAILDOC_INSTALL_DIR:-$HOME/.local/bin}"

os="$(uname -s)"
arch="$(uname -m)"
case "$os" in
    Linux) os="linux" ;;
    Darwin) os="darwin" ;;
    *)
        echo "error: unsupported OS '$os' — grab a binary from https://github.com/$REPO/releases" >&2
        exit 1
        ;;
esac
case "$arch" in
    x86_64|amd64) arch="amd64" ;;
    aarch64|arm64) arch="arm64" ;;
    *)
        echo "error: unsupported architecture '$arch'" >&2
        exit 1
        ;;
esac

# Resolve the latest release tag by following GitHub's /releases/latest redirect.
tag_url="$(curl -fsSLI -o /dev/null -w '%{url_effective}' "https://github.com/$REPO/releases/latest")"
tag="${tag_url##*/}"
[ -n "$tag" ] || { echo "error: could not determine latest release" >&2; exit 1; }

version="${tag#v}"
url="https://github.com/$REPO/releases/download/${tag}/taildoc_${version}_${os}_${arch}.tar.gz"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo "==> Downloading taildoc for ${os}/${arch}..."
curl -fsSL "$url" | tar -xz -C "$tmp"

mkdir -p "$DEST"
mv "$tmp/taildoc" "$DEST/taildoc"
chmod +x "$DEST/taildoc"

echo "==> Installed to $DEST/taildoc"
"$DEST/taildoc" version
case ":$PATH:" in
    *":$DEST:"*) ;;
    *)
        echo ""
        echo "NOTE: $DEST is not on your PATH. Add this to your shell profile:"
        echo "  export PATH=\"\$PATH:$DEST\""
        ;;
esac
