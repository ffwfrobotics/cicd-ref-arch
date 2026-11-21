#!/bin/sh
# Give the nested node a cgroup tree of its own: the pod's cgroup becomes the root of a private
# cgroup namespace, so the nested kubelet can never see (or "clean up") the host cluster's pods.
set -eu
# k0s imports image bundles from /var/lib/k0s/images at start: the node needs no registry for its own system pods
mkdir -p /var/lib/k0s/images && cp -n /usr/local/share/k0s-airgap.tar /var/lib/k0s/images/
P=$(sed 's/^0:://' /proc/self/cgroup)
mkdir -p "/sys/fs/cgroup$P/node"
echo $$ > "/sys/fs/cgroup$P/node/cgroup.procs"
for c in $(cat "/sys/fs/cgroup$P/cgroup.controllers"); do echo "+$c" > "/sys/fs/cgroup$P/cgroup.subtree_control"; done
exec unshare --cgroup --mount sh -c '
  set -eu
  umount /sys/fs/cgroup
  mount -t cgroup2 -o nsdelegate cgroup2 /sys/fs/cgroup
  mkdir -p /sys/fs/cgroup/init
  for p in $(cat /sys/fs/cgroup/cgroup.procs); do echo $p > /sys/fs/cgroup/init/cgroup.procs 2>/dev/null || true; done
  for c in $(cat /sys/fs/cgroup/cgroup.controllers); do echo "+$c" > /sys/fs/cgroup/cgroup.subtree_control; done
  exec "$@"' sh "$@"
