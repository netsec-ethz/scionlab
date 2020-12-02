FROM golang:1.14.9-buster

# netsec-ethz/scion:scionlab_nextversion, 2020/12/02
ARG scion_commit=65fd6eb4ec9935018fc643b37f08c868547d325c

RUN mkdir /scion
WORKDIR /scion

RUN git init && \
    git remote add netsec-ethz https://github.com/netsec-ethz/scion.git && \
    git fetch netsec-ethz && \
    git -c advice.detachedHead=false checkout $scion_commit

RUN startup_version=$(git describe --tags --always)-scionlab && \
    go build -ldflags="-s -w -X github.com/scionproto/scion/go/lib/env.StartupVersion=$startup_version" \
             -o bin/ \
             ./go/scion-pki
