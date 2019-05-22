#!/bin/bash
set -e

# Get configuration
export COORD_IP=$(dig +short coord A)
curl --fail -u ${CUSER}:${CSECRET} http://${COORD_IP}:8000/api/host/${CUSER}/config -o /tmp/host_config.tar
rm $SC/gen -rf
tar -C $SC/ -xf /tmp/host_config.tar

# Fix config for shared zookeeper instance
./share_zk.sh

# restart SCION services
cd $SC
./supervisor/supervisor.sh stop all
./supervisor/supervisor.sh reload
./supervisor/supervisor.sh start all

