#!/bin/bash
set -e

# Get configuration
curl --fail -u ${CUSER}:${CSECRET} http://coord:8000/api/host/${CUSER}/config -o /tmp/host_config.tar
rm /etc/scion/gen -rf
tar -C /etc/scion/ -xf /tmp/host_config.tar

# restart SCION services
cd $SC
sed -i 's%\.\./gen%/etc/scion/gen%g' supervisor/supervisord.conf

./supervisor/supervisor.sh stop all
./supervisor/supervisor.sh reload
./supervisor/supervisor.sh start all

