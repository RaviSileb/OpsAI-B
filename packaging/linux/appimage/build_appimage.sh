#!/bin/bash
# Build a Linux AppImage from the PyInstaller onedir tree (FR-811).
# Usage: packaging/linux/appimage/build_appimage.sh
# Requires: output of ../build_deb.sh (packaging/linux/build/dist/opsai)
# Output: packaging/linux/dist/OpsAI-<version>-x86_64.AppImage
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
BUILD="$ROOT/packaging/linux/build"
DIST="$ROOT/packaging/linux/dist"
ONEDIR="$BUILD/dist/opsai"

if [ ! -x "$ONEDIR/opsai" ]; then
  echo "Missing frozen app at $ONEDIR - run packaging/linux/build_deb.sh first" >&2
  exit 1
fi

VERSION="$("$ROOT/.venv/bin/python" -c "import tomllib; print(tomllib.load(open('$ROOT/pyproject.toml','rb'))['project']['version'])" 2>/dev/null \
  || python3 -c "import tomllib; print(tomllib.load(open('$ROOT/pyproject.toml','rb'))['project']['version'])")"
mkdir -p "$DIST"

APPDIR="$BUILD/OpsAI.AppDir"
rm -rf "$APPDIR"
mkdir -p "$APPDIR/usr/bin" "$APPDIR/usr/share/applications" "$APPDIR/usr/share/icons/hicolor/scalable/apps"
cp -r "$ONEDIR/." "$APPDIR/usr/bin/"
cp "$ROOT/packaging/linux/opsai.desktop" "$APPDIR/usr/share/applications/"
cp "$ROOT/packaging/linux/opsai.desktop" "$APPDIR/opsai.desktop"
cp "$ROOT/packaging/linux/opsai.svg" "$APPDIR/opsai.svg"
cp "$ROOT/packaging/linux/opsai.svg" "$APPDIR/usr/share/icons/hicolor/scalable/apps/opsai.svg"
cp "$ROOT/packaging/linux/opsai.svg" "$APPDIR/.DirIcon"
sed -i 's|^Exec=.*|Exec=opsai desktop|' "$APPDIR/opsai.desktop" "$APPDIR/usr/share/applications/opsai.desktop"
cat >"$APPDIR/AppRun" <<'EOF'
#!/bin/sh
HERE="$(dirname "$(readlink -f "$0")")"
export OPSAI_DATA_DIR="${OPSAI_DATA_DIR:-$HOME/.local/share/opsai}"
exec "$HERE/usr/bin/opsai" "$@"
EOF
chmod +x "$APPDIR/AppRun"

TOOL="$BUILD/appimagetool"
if [ ! -x "$TOOL" ]; then
  echo "==> downloading appimagetool"
  curl -fsSL -o "$TOOL" "https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-x86_64.AppImage"
  chmod +x "$TOOL"
fi

echo "==> appimagetool"
ARCH=x86_64 "$TOOL" "$APPDIR" "$DIST/OpsAI-${VERSION}-x86_64.AppImage"
echo "OK: $DIST/OpsAI-${VERSION}-x86_64.AppImage"
ls -la "$DIST"
