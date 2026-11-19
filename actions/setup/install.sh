#!/bin/sh
# Install the pinned CI tools (tools.txt) into $1/bin, verifying each download's sha256, and
# PyYAML into a venv at $1/venv. Idempotent: an existing binary at the right version is kept.
set -eu
dest=$1; list=$(dirname "$0")/tools.txt
CHECKOV_VERSION=3.4.6   # pip, not a binary: pinned here
mkdir -p "$dest/bin" "$dest/dl"
grep -v '^#' "$list" | while read -r name version url sum; do
  [ -n "$name" ] || continue
  stamp="$dest/bin/.$name-$version"
  [ -e "$stamp" ] && continue
  file="$dest/dl/$(basename "$url")"
  curl -fsSL --retry 3 -o "$file" "$url"
  echo "$sum  $file" | sha256sum -c - >/dev/null || { echo "checksum mismatch: $url" >&2; exit 1; }
  case "$file" in
    *buildkit-*.tar.gz) tar -xzf "$file" -C "$dest/bin" --strip-components=1 bin/buildctl ;;
    *.tar.gz)           tar -xzf "$file" -C "$dest/bin" "$name" ;;
    *)                  cp "$file" "$dest/bin/$name" ;;
  esac
  chmod +x "$dest/bin/$name"
  rm -f "$dest/bin/.$name-"*; touch "$stamp"; rm -f "$file"
done
if [ ! -x "$dest/venv/bin/python3" ]; then
  python3 -m venv "$dest/venv"
  "$dest/venv/bin/pip" install -q pyyaml==6.0.2
fi
# checkov has many dependencies: its own venv, so they never meet the tools' PyYAML
if [ ! -x "$dest/checkov/bin/checkov" ] || [ "$("$dest/checkov/bin/checkov" --version)" != "$CHECKOV_VERSION" ]; then
  rm -rf "$dest/checkov"; python3 -m venv "$dest/checkov"
  "$dest/checkov/bin/pip" install -q "checkov==$CHECKOV_VERSION"
fi
ln -sf "$dest/checkov/bin/checkov" "$dest/bin/checkov"
