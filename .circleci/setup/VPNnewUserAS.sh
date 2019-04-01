#!/bin/bash

export PYTHONPATH=/home/scion/go/src/github.com/scionproto/scion/python
export GOPATH=/home/scion/go
export SC=/home/scion/go/src/github.com/scionproto/scion

sleep 10
/tmp/minimalInstall.sh

pip3 install --user requests

echo "Creating new userAS"
# Create a new user AS and get the gen config
python3 /tmp/create_user_as.py
echo "Created new userAS"

# Configure container for OpenVPN connections
sudo apt-get install -y openvpn
sudo mkdir -p /dev/net
sudo mknod /dev/net/tun c 10 20
sudo chmod 600 /dev/net/tun

# Use configuration from coordinator
rm $SC/gen -rf
tar -C $SC/ -xf /tmp/host_config.tar

# Setup OpenVPN client
sudo cp client.conf /etc/openvpn/
sudo openvpn --daemon ovpn-client --cd /etc/openvpn --config /etc/openvpn/client.conf
sleep 20 # wait for OpenVPN to start

ZK_IP=$(dig +short zookeeper A); for f in $(find $SC/gen/ -name topology.json); do
    jq ".ZookeeperService[]|=({Addr:\"$ZK_IP\", L4Port:.L4Port})" $f | sponge $f;
done

cd $SC
./supervisor/supervisor.sh stop all
./supervisor/supervisor.sh reload
./supervisor/supervisor.sh start all

sleep 3600
