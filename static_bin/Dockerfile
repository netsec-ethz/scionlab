FROM golang:1.14.9-buster

# netsec-ethz/scion, last biweekly update on 2021/05/10
ARG scion_commit=919619bc9d3120acc68aec1f7cc23e1cdcdc8d59

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
