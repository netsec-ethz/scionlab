#!/bin/bash

export PYTHONPATH=/home/scion/go/src/github.com/scionproto/scion/python
export GOPATH=/home/scion/go
export SC=/home/scion/go/src/github.com/scionproto/scion

pip3 install --user requests

echo "Creating new userAS"
# Create a new user AS and get the gen config
python3 ${SC}/user_action.py --url "user/as/add" --data '{"attachment_point":"4", "label": "UserAS1", "installation_type": "DEDICATED", "use_vpn": "on", "public_port": 50000}' --action "add"
echo "Created new userAS"

# Configure container for OpenVPN connections
sudo apt-get update
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
until [ `ps ax | grep openvpn | grep -v "grep" | wc -l` -ge 1 ]; do sleep 1; done
echo "VPN up"

ZK_IP=$(dig +short zookeeper A); for f in $(find $SC/gen/ -name topology.json); do
    jq ".ZookeeperService[]|=({Addr:\"$ZK_IP\", L4Port:.L4Port})" $f | sponge $f;
done

until ip a show tun0; do sleep 1; done
echo "VPN tun0 up"

cd $SC
./supervisor/supervisor.sh stop all
./supervisor/supervisor.sh reload
./supervisor/supervisor.sh start all
