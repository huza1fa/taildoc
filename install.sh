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
archive="taildoc_${version}_${os}_${arch}.tar.gz"
url="https://github.com/$REPO/releases/download/${tag}/${archive}"
checksums_url="https://github.com/$REPO/releases/download/${tag}/checksums.txt"
signature_url="https://github.com/$REPO/releases/download/${tag}/checksums.txt.sig"
certificate_url="https://github.com/$REPO/releases/download/${tag}/checksums.txt.pem"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo "==> Downloading taildoc for ${os}/${arch}..."
curl -fsSLo "$tmp/$archive" "$url"
curl -fsSLo "$tmp/checksums.txt" "$checksums_url"
curl -fsSLo "$tmp/checksums.txt.sig" "$signature_url"
curl -fsSLo "$tmp/checksums.txt.pem" "$certificate_url"

if ! command -v cosign >/dev/null 2>&1; then
    echo "error: cosign is required to verify this release; install it from https://docs.sigstore.dev/cosign/system_config/installation/" >&2
    exit 1
fi
cosign verify-blob \
    --certificate "$tmp/checksums.txt.pem" \
    --signature "$tmp/checksums.txt.sig" \
    --certificate-identity-regexp "^https://github.com/$REPO/.github/workflows/release.yml@refs/tags/v[0-9].*$" \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
    "$tmp/checksums.txt"

checksum_line="$(grep -F " $archive" "$tmp/checksums.txt" || true)"
[ -n "$checksum_line" ] || { echo "error: checksum for $archive is missing" >&2; exit 1; }
if command -v sha256sum >/dev/null 2>&1; then
    printf '%s\n' "$checksum_line" | (cd "$tmp" && sha256sum -c -)
elif command -v shasum >/dev/null 2>&1; then
    printf '%s\n' "$checksum_line" | (cd "$tmp" && shasum -a 256 -c -)
else
    echo "error: need sha256sum or shasum to verify the release" >&2
    exit 1
fi
tar -xzf "$tmp/$archive" -C "$tmp"

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
