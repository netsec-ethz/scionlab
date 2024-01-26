FROM golang:1.21-bookworm

# netsec-ethz/scion, last biweekly update on 2024/01/25
ARG scion_commit=beb40c503ec4dbcecee983b1b71b896e3b29d7d6

RUN mkdir /scion
WORKDIR /scion

RUN git init && \
    git remote add netsec-ethz https://github.com/netsec-ethz/scion.git && \
    git fetch netsec-ethz && \
    git -c advice.detachedHead=false checkout $scion_commit

RUN startup_version=$(git describe --tags --always)-scionlab && \
    GOOS=linux GOARCH=amd64 go build \
             -ldflags="-s -w -X github.com/scionproto/scion/private/env.StartupVersion=$startup_version" \
             -o bin/scion-pki-linux-amd64 \
             ./scion-pki/cmd/scion-pki

RUN startup_version=$(git describe --tags --always)-scionlab && \
    GOOS=darwin GOARCH=amd64 go build \
             -ldflags="-s -w -X github.com/scionproto/scion/private/env.StartupVersion=$startup_version" \
             -o bin/scion-pki-darwin-amd64 \
             ./scion-pki/cmd/scion-pki
