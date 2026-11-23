# The CI/CD runner: what the platform's workflows need on the host and nothing else (the pinned
# scanners and build tools come from actions/setup at job time). Jobs run in this container
# ("host" label mode); BuildKit builds images in its own pod.
FROM docker.io/library/ubuntu:24.04
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl git jq openssh-client python3 python3-venv xz-utils zstd \
 && rm -rf /var/lib/apt/lists/*
ARG NODE_VERSION=22.23.5
ARG NODE_SHA256=cdeb8670a0c81f51b4dc4ac61919f9b1ad917b304bf8221eb939570663d240f8
RUN curl -fsSLo /tmp/node.tar.xz https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-x64.tar.xz \
 && echo "${NODE_SHA256}  /tmp/node.tar.xz" | sha256sum -c - \
 && tar -xJf /tmp/node.tar.xz -C /usr/local --strip-components=1 --exclude='*/include' --exclude='*/share' \
 && rm /tmp/node.tar.xz && node --version
ARG RUNNER_VERSION=13.2.1
ARG RUNNER_SHA256=bb369fe1ecb50fdc983c0b1d993f19b0920df6e5864511892b3cdbf16d858b34
RUN curl -fsSLo /usr/local/bin/forgejo-runner https://code.forgejo.org/forgejo/runner/releases/download/v${RUNNER_VERSION}/forgejo-runner-${RUNNER_VERSION}-linux-amd64 \
 && echo "${RUNNER_SHA256}  /usr/local/bin/forgejo-runner" | sha256sum -c - \
 && chmod +x /usr/local/bin/forgejo-runner
WORKDIR /runner
ENTRYPOINT ["/usr/local/bin/forgejo-runner"]
