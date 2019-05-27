#!/bin/bash

# Configure container for OpenVPN connections
sudo apt-get update
sudo apt-get install -y openvpn
sudo mkdir -p /dev/net
sudo mknod /dev/net/tun c 10 20
sudo chmod 600 /dev/net/tun

# OpenVPN server files
sudo openssl dhparam -out /etc/openvpn/dh.pem 2048
sudo mkdir /etc/openvpn/ccd

# Get configuration from coordinator
curl --fail -u ${CUSER}:${CSECRET} http://coord:8000/api/host/${CUSER}/config -o /tmp/host_config.tar
rm $SC/gen -rf
tar -C $SC/ -xf /tmp/host_config.tar

# Setup OpenVPN attachment point server
sudo cp server.conf /etc/openvpn/
echo 'ifconfig-push 10.0.0.1 255.255.0.0' > /tmp/userAS1.ccd
sudo mv /tmp/userAS1.ccd /etc/openvpn/ccd/scion@scionlab.org__20-ffaa_1_1
sudo openvpn --daemon ovpn-server --cd /etc/openvpn --config /etc/openvpn/server.conf

ZK_IP=$(dig +short zookeeper A); for f in $(find $SC/gen/ -name topology.json); do
    jq ".ZookeeperService[]|=({Addr:\"$ZK_IP\", L4Port:.L4Port})" $f | sponge $f;
done

cd $SC
./supervisor/supervisor.sh stop all
./supervisor/supervisor.sh reload
./supervisor/supervisor.sh start all
