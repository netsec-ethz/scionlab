FROM golang:1.16.4-buster

# netsec-ethz/scion, last biweekly update on 2021/06/25
ARG scion_commit=fc081bebc9329e611b074722245c6e6e62e2b9fd

RUN mkdir /scion
WORKDIR /scion

RUN git init && \
    git remote add netsec-ethz https://github.com/netsec-ethz/scion.git && \
    git fetch netsec-ethz && \
    git -c advice.detachedHead=false checkout $scion_commit

RUN startup_version=$(git describe --tags --always)-scionlab && \
    GOOS=linux GOARCH=amd64 go build -ldflags="-s -w -X github.com/scionproto/scion/go/lib/env.StartupVersion=$startup_version" \
             -o bin/scion-pki-linux-amd64 \
             ./go/scion-pki

RUN startup_version=$(git describe --tags --always)-scionlab && \
    GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w -X github.com/scionproto/scion/go/lib/env.StartupVersion=$startup_version" \
             -o bin/scion-pki-darwin-amd64 \
             ./go/scion-pki
