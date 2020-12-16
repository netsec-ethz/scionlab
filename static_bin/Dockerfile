FROM golang:1.14.9-buster

# netsec-ethz/scion, last release on 2020/12/08
ARG scion_commit=v2020.12

RUN mkdir /scion
WORKDIR /scion

RUN git init && \
    git remote add netsec-ethz https://github.com/netsec-ethz/scion.git && \
    git fetch netsec-ethz && \
    git -c advice.detachedHead=false checkout $scion_commit

RUN startup_version=$(git describe --tags --always)-scionlab && \
    go build -ldflags="-s -w -X github.com/scionproto/scion/go/lib/env.StartupVersion=$startup_version" \
             -o bin/scion-pki-linux \
             ./go/scion-pki

RUN startup_version=$(git describe --tags --always)-scionlab && \
    GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w -X github.com/scionproto/scion/go/lib/env.StartupVersion=$startup_version" \
             -o bin/scion-pki-mac \
             ./go/scion-pki
