#!/usr/bin/env bash
# Build the stack-node image on a host with docker and push it to a cluster's registry.
#   images/stack-node/build.sh [registry]      default 127.0.0.1:5003 (c-local's registry on its host)
# The airgap bundle is the k0s release's own image list (`k0s airgap list-images`), saved into the image.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
reg=${1:-127.0.0.1:5003}
k0s=$(sed -n 's/^ARG K0S=//p' "$here/Dockerfile")
tag="$reg/stack-node:$(echo "$k0s" | sed -E 's/.*:(v[^@]+)@.*/\1/')"
imgs=$(docker run --rm --entrypoint k0s "$k0s" airgap list-images)
for i in $imgs; do docker pull -q "$i" >/dev/null; done
docker save $imgs -o "$here/k0s-airgap.tar"; chmod 644 "$here/k0s-airgap.tar"
docker build -q -t "$tag" "$here"
docker push -q "$tag"
rm -f "$here/k0s-airgap.tar"
echo "$tag@$(docker inspect "$tag" --format '{{index .RepoDigests 0}}' | sed 's/.*@//')"
