#!/bin/bash

#### Replace with binary package
# Get SCION executables ready
sudo chown scion:scion -R ./bin
sudo chmod +x ./bin/*
# Add python dependencies
pip3 install --user -r env/pip3/requirements.txt
mkdir ./gen-cache
#### 

# Configure container for OpenVPN connections
sudo apt-get install -y openvpn
sudo mkdir -p /dev/net
sudo mknod /dev/net/tun c 10 20
sudo chmod 600 /dev/net/tun

# OpenVPN server files
sudo openssl dhparam -out /etc/openvpn/dh.pem 2048
sudo mkdir /etc/openvpn/ccd

# Get configuration from coordinator
export COORD_IP=$(dig +short coord A)
curl -u ${CUSER}:${CSECRET} http://${COORD_IP}:8000/api/host/${CUSER}/config -o /tmp/host_config.tar
rm $SC/gen -rf
tar -C $SC/ -xf /tmp/host_config.tar

# Setup OpenVPN attachment point server
sudo cp server.conf
echo 'ifconfig-push 10.0.8.2 255.255.255.0' > /tmp/userAS1.ccd
sudo mv /tmp/userAS1.ccd /etc/openvpn/ccd/scion@scionlab.org__20-ffaa_1_1

ZK_IP=$(dig +short zookeeper A); for f in $(find $SC/gen/ -name topology.json); do
    jq ".ZookeeperService[]|=({Addr:\"$ZK_IP\", L4Port:.L4Port})" $f | sponge $f;
done

cd $SC
./supervisor/supervisor.sh stop all
./supervisor/supervisor.sh reload
./supervisor/supervisor.sh start all
