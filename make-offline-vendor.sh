#!/bin/sh
# Produce the offline/ artifacts that let Dockerfile.singbox build a node image
# with NO module proxy at all (no proxy.golang.org, no mirror) — for a network
# where every Go module host is blocked.
#
# Run this ONCE on a machine that does have network, from the repo root, at the
# same commit you intend to build. It writes:
#
#   offline/node-vendor.tar.gz      `go mod vendor` of this module
#   offline/singbox-vendor.tar.gz   `go mod vendor` of the pinned sing-box tree
#                                   WITH the quota patch applied
#
# Neither is committed (see .gitignore); the Dockerfile only uses them when
# they are present, so a default build is byte-for-byte unaffected.
#
# Usage:  ./make-offline-vendor.sh
# Needs:  go, git, the pins below matching Dockerfile.singbox.
set -eu

SINGBOX_VERSION=${SINGBOX_VERSION:-1.14.2}
SINGBOX_SHA=${SINGBOX_SHA:-af6e64c3b69e6132ebaee0e1a3d24e93903f6709}
PATCH=patches/singbox/0001-pasarguard-user-quota.patch
OUT=offline

# zstd is not everywhere; gzip is in busybox tar, which is what the image has.
command -v gzip >/dev/null || { echo "gzip is required" >&2; exit 1; }

mkdir -p "$OUT"
# sing-box's vendor tree is ~1 GB (cronet-go ships a prebuilt .a per platform).
# /tmp is a ~1 GB tmpfs on many hosts, so mktemp would fill it; put the
# scratch tree somewhere with actual room.
TMPDIR=${TMPDIR:-$HOME/tmp}
export TMPDIR
mkdir -p "$TMPDIR"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

echo "==> node module: go mod vendor"
rm -rf vendor
go mod vendor
test -f vendor/modules.txt
tar -czf "$OUT/node-vendor.tar.gz" vendor
rm -rf vendor
echo "    wrote $OUT/node-vendor.tar.gz ($(wc -c < "$OUT/node-vendor.tar.gz") bytes)"

echo "==> sing-box v${SINGBOX_VERSION} @ ${SINGBOX_SHA}: clone, patch, go mod vendor"
git clone --depth 1 --branch "v${SINGBOX_VERSION}" \
  https://github.com/SagerNet/sing-box "$WORK/src"
cd "$WORK/src"
actual=$(git rev-parse HEAD)
if [ "$actual" != "$SINGBOX_SHA" ]; then
  echo "tag v${SINGBOX_VERSION} is $actual, not the pinned $SINGBOX_SHA" >&2
  exit 1
fi
git apply --whitespace=error-all "$OLDPWD/$PATCH"
test -f experimental/v2rayapi/quota.go
grep -q quota-v1 experimental/v2rayapi/quota.go
go mod vendor
test -f vendor/modules.txt
tar -czf "$OLDPWD/$OUT/singbox-vendor.tar.gz" vendor
echo "    wrote $OUT/singbox-vendor.tar.gz ($(wc -c < "$OLDPWD/$OUT/singbox-vendor.tar.gz") bytes)"

echo "==> done. Build offline with:"
echo "    docker buildx build -f Dockerfile.singbox --build-arg GOPROXY=off -t pasarguard-node:quota-v1 ."
