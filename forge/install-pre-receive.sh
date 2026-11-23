#!/bin/sh
# Install forge/pre-receive-gitleaks for the enrolled repos. Run it on the forge host (or inside the
# Forgejo container) as the user that owns the repositories:
#
#   forge/install-pre-receive.sh <repositories root> [gitleaks path, as the forge process sees it]
#
#   e.g. forge/install-pre-receive.sh /var/lib/forgejo/data/forgejo-repositories /usr/local/bin/gitleaks
#
# The repositories root is [repository] ROOT in app.ini (contains <platform_repo>.git). It installs
# into each repo's hooks/pre-receive.d/, which Forgejo's own pre-receive runs; Forgejo's "resynchronize
# hooks" rewrites only its own file there, so this one stays. Repos: those in tenants/*.yaml, plus
# this platform repo. Run it again after enrolling an app. Undo: delete the installed files.
set -eu
root=${1:?usage: $0 <repositories root> [gitleaks path]}
gl=${2:-gitleaks}
here=$(cd "$(dirname "$0")" && pwd)
"$gl" version >/dev/null 2>&1 || { echo "gitleaks not runnable at '$gl': install it (version in actions/setup/tools.txt)" >&2; exit 1; }
repos="$(sed -n 's/^platform_repo: *\([^ #]*\).*/\1/p' "$here/../instance.yaml") $(sed -n 's/^  repo: *//p' "$here"/../tenants/[!_]*.yaml | tr -d "\"'")"
for r in $(printf '%s\n' $repos | sort -u); do
  d="$root/$(echo "$r" | tr A-Z a-z).git"
  [ -d "$d" ] || { echo "skip $r: no $d"; continue; }
  mkdir -p "$d/hooks/pre-receive.d"
  { echo '#!/bin/sh'; echo "GITLEAKS='$gl'; export GITLEAKS"; sed 1d "$here/pre-receive-gitleaks"; } > "$d/hooks/pre-receive.d/gitleaks"
  chmod 755 "$d/hooks/pre-receive.d/gitleaks"
  echo "installed: $r"
done
