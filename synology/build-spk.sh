#!/bin/sh
# Builds dist/Barrier-<version>-x86_64.spk, and dist/barrier-app-<version>.tar.gz
# (the app on its own, which "Update now" inside Barrier downloads).
# The .spk carries the finished Docker image, so the NAS never builds or
# downloads anything to install it. Needs Docker. Usage: synology/build-spk.sh [outdir]
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
VERSION="$(tr -d ' \r\n' < "$ROOT/VERSION")"
OUT="${1:-dist}"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

mkdir -p "$WORK/ctx" "$WORK/pkg/compose" "$WORK/pkg/ui" "$WORK/spk"
cp -R "$ROOT/app" "$WORK/ctx/app"
find "$WORK/ctx/app" -name __pycache__ -prune -exec rm -rf {} +
echo "$VERSION" > "$WORK/ctx/app/VERSION"
chmod 755 "$WORK/ctx/app/scripts/"*.sh
cp "$HERE/Dockerfile" "$HERE/entrypoint.sh" "$WORK/ctx/"

IMG="barrier-package:$VERSION"
docker build -t "$IMG" "$WORK/ctx"
docker save "$IMG" | gzip -9 > "$WORK/pkg/image.tar.gz"
sed "s/@VERSION@/$VERSION/" "$HERE/compose.yaml" > "$WORK/pkg/compose/compose.yaml"
cp -R "$HERE/ui/." "$WORK/pkg/ui/"
(cd "$WORK/pkg" && tar --owner=0 --group=0 -czf "$WORK/spk/package.tgz" compose ui image.tar.gz)

sed "s/@VERSION@/$VERSION/" "$HERE/INFO.in" > "$WORK/spk/INFO"
echo "extractsize=\"$(du -sk "$WORK/pkg" | cut -f1)\"" >> "$WORK/spk/INFO"
cp -R "$HERE/scripts" "$HERE/conf" "$WORK/spk/"
cp "$HERE/PACKAGE_ICON.PNG" "$HERE/PACKAGE_ICON_256.PNG" "$WORK/spk/"
chmod 755 "$WORK/spk/scripts/"*
NAME="Barrier-$VERSION-x86_64.spk"
(cd "$WORK/spk" && tar --owner=0 --group=0 -cf "$OUT/$NAME" INFO package.tgz scripts conf PACKAGE_ICON.PNG PACKAGE_ICON_256.PNG)

(cd "$WORK/ctx" && tar --owner=0 --group=0 -czf "$OUT/barrier-app-$VERSION.tar.gz" app)
echo "$OUT/$NAME"
