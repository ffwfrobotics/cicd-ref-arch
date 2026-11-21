# A Kubernetes node that runs as one privileged pod inside a host cluster (docs/stacks.md, provider
# k0s-pod). entry.sh gives it a private cgroup namespace; k0s-airgap.tar (made by build.sh) holds the
# node's own system images, so a nested cluster pulls nothing to become Ready.
ARG K0S=docker.io/k0sproject/k0s:v1.37.2-k0s.1@sha256:b315f63e2e23430e68c9fcaf14fb13a27413dd92b973c24a4b5272968923a644
FROM ${K0S}
RUN apk add --no-cache util-linux-misc
COPY k0s-airgap.tar /usr/local/share/k0s-airgap.tar
COPY entry.sh /usr/local/bin/stack-node-entry
ENTRYPOINT ["/usr/local/bin/stack-node-entry"]
