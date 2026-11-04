#!/bin/bash
# Build a Linux .deb with the frozen OpsAI app (PyInstaller onedir + dpkg-deb).
# Usage: packaging/linux/build_deb.sh
# Output: packaging/linux/dist/opsai_<version>_amd64.deb
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUILD="$ROOT/packaging/linux/build"
DIST="$ROOT/packaging/linux/dist"
VENV="$BUILD/venv"

echo "==> version"
VERSION="$("$ROOT/.venv/bin/python" -c "import tomllib; print(tomllib.load(open('$ROOT/pyproject.toml','rb'))['project']['version'])" 2>/dev/null \
  || python3 -c "import tomllib; print(tomllib.load(open('$ROOT/pyproject.toml','rb'))['project']['version'])")"
echo "version=$VERSION"

echo "==> build venv"
rm -rf "$BUILD"
mkdir -p "$BUILD" "$DIST"
python3 -m venv "$VENV"
"$VENV/bin/pip" install -q --upgrade pip
"$VENV/bin/pip" install -q "$ROOT" pyinstaller

echo "==> pyinstaller"
cd "$ROOT"
"$VENV/bin/pyinstaller" \
  --noconfirm --clean \
  --onedir --name opsai \
  --console \
  --distpath "$BUILD/dist" \
  --workpath "$BUILD/work" \
  --specpath "$BUILD" \
  --collect-all nicegui \
  --collect-all uvicorn \
  --collect-all websockets \
  --collect-all alembic \
  --collect-all sqlalchemy \
  --add-data "$ROOT/opsai/i18n:opsai/i18n" \
  --add-data "$ROOT/opsai/prompts:opsai/prompts" \
  --add-data "$ROOT/opsai/db/migrations:opsai/db/migrations" \
  "$ROOT/packaging/linux/opsai_entry.py" >"$BUILD/pyinstaller.log" 2>&1
echo "pyinstaller done (log: $BUILD/pyinstaller.log)"

echo "==> smoke test frozen binary"
export OPSAI_DATA_DIR="$BUILD/smoke-data"
"$BUILD/dist/opsai/opsai" --version
printf '2026-10-27T10:00:01Z INFO h1 svc Started\n2026-10-27T10:00:02Z ERROR h1 svc boom\n' >"$BUILD/demo.log"
"$BUILD/dist/opsai/opsai" ingest --path "$BUILD/demo.log" --name smoke
OPSAI_DATA_DIR="$BUILD/smoke-data" "$BUILD/dist/opsai/opsai" audit verify

echo "==> .deb layout"
PKG="$BUILD/pkg"
rm -rf "$PKG"
mkdir -p "$PKG/DEBIAN" "$PKG/opt/opsai" "$PKG/usr/bin" "$PKG/usr/share/applications" \
  "$PKG/usr/share/icons/hicolor/scalable/apps"
cp -r "$BUILD/dist/opsai/." "$PKG/opt/opsai/"
ln -sf /opt/opsai/opsai "$PKG/usr/bin/opsai"
cp "$ROOT/packaging/linux/opsai.desktop" "$PKG/usr/share/applications/"
cp "$ROOT/packaging/linux/opsai.svg" "$PKG/usr/share/icons/hicolor/scalable/apps/opsai.svg"
INSTALLED_SIZE="$(du -sk "$PKG/opt/opsai" | cut -f1)"
cat >"$PKG/DEBIAN/control" <<EOF
Package: opsai
Version: $VERSION
Section: utils
Priority: optional
Architecture: amd64
Depends: libc6, ca-certificates
Installed-Size: $INSTALLED_SIZE
Maintainer: Ivar Belis
Description: OpsAI variant B - AI assistant for log analysis
 Desktop and server log analysis with masking, AI providers
 (Meta Model API) and audit.
EOF

echo "==> dpkg-deb"
dpkg-deb --build "$PKG" "$DIST/opsai_${VERSION}_amd64.deb"
echo "OK: $DIST/opsai_${VERSION}_amd64.deb"
ls -la "$DIST"
