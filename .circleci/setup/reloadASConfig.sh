#!/bin/bash

set -e

# Get configuration
curl --fail -u ${CUSER}:${CSECRET} http://coord:8000/api/host/${CUSER}/config -o /tmp/host_config.tar
rm $SC/gen -rf
tar -C $SC/ -xf /tmp/host_config.tar

# Fix config for shared zookeeper instance
ZK_IP=$(dig +short zookeeper A); for f in $(find $SC/gen/ -name topology.json); do
    jq ".ZookeeperService[]|=({Addr:\"$ZK_IP\", L4Port:.L4Port})" $f | sponge $f;
done

# restart SCION services
cd $SC
./supervisor/supervisor.sh stop all
./supervisor/supervisor.sh reload
./supervisor/supervisor.sh start all

