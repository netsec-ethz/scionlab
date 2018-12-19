#!/bin/bash

set -e

shopt -s nullglob

UPGRADE_SCRIPT_LOCATION="/usr/bin/scionupgrade.sh"

usage="$(basename "$0") [-p PATCH_DIR] [-g GEN_DIR] [-v VPN_CONF_PATH] \
[-s SCION_SERVICE] [-z SCION_VI_SERVICE] [-a ALIASES_FILE] [-c] \
[-u UPGRADE_SCRIPT] [-t TIMER_SERVICE]

where:
    -p PATCH_DIR        apply patches from PATCH_DIR on cloned repo
    -g GEN_DIR          path to gen directory to be used
    -v VPN_CONF_PATH    path to OpenVPN configuration file
    -s SCION_SERVICE    path to SCION service file
    -z SCION_VI_SERVICE path to SCION-viz service file
    -a ALIASES_FILE     adds useful command aliases in specified file
    -c                  do not destroy user context on logout
    -u UPGR_SCRIPT      script used for upgrading scion, (will be copied to 
                        path ${UPGRADE_SCRIPT_LOCATION})
    -t TIMER_UPG_SERV   name of sysd timer and system name for upgrades"

while getopts ":p:g:v:s:z:ha:cu:t:" opt; do
  case $opt in
    p)
      patch_dir=$OPTARG
      ;;
    g)
      gen_dir=$OPTARG
      ;;
    v)
      vpn_config_file=$OPTARG
      ;;
    s)
      scion_service_path=$OPTARG
      ;;
    z)
      scion_viz_service=$OPTARG
      ;;
    h)
      echo "Displaying help:" >&2
      echo "$usage" >&2
      exit 1
      ;;
    a)
      aliases_file=$OPTARG
      ;;
    c)
      keep_user_context=true
      ;;
    u)
      upgrade_script=$OPTARG
      ;;
    t)
      upgrade_timer=${OPTARG}.timer
      upgrade_service=${OPTARG}.service
      ;;
    \?)
      echo "Invalid option: -$OPTARG" >&2
      echo "$usage" >&2
      exit 1
      ;;
    :)
      echo "Option -$OPTARG requires an argument." >&2
      echo "$usage" >&2
      exit 1
      ;;
  esac
done

echo "Starting SCION installation..."

# Check if we are running on correct Ubuntu system
if [ -f /etc/os-release ]
then
    . /etc/os-release

    if [[ $NAME == "Ubuntu" && $VERSION_ID == 16.04* ]] ; then
      echo "We are running on $NAME version $VERSION_ID seems okay"
    else
      echo "ERROR! We are not running on Ubuntu 16.04 system, shutting down!" >&2
      exit 1
    fi
else
    echo "ERROR! This script can only be run on Ubuntu 16.04" >&2
    exit 1
fi
export DEBIAN_FRONTEND=noninteractive
sudo apt-get update
sudo apt-get install -y git supervisor

grep 'export GOPATH="$HOME/go"' ~/.profile >/dev/null || echo 'export GOPATH="$HOME/go"' >> ~/.profile
grep 'export PATH="$HOME/.local/bin:$GOPATH/bin:/usr/local/go/bin:$PATH"' ~/.profile >/dev/null || echo 'export PATH="$HOME/.local/bin:$GOPATH/bin:/usr/local/go/bin:$PATH"' >> ~/.profile
grep 'export SC="$GOPATH/src/github.com/scionproto/scion"' ~/.profile >/dev/null || echo 'export SC="$GOPATH/src/github.com/scionproto/scion"' >> ~/.profile
grep 'export PYTHONPATH="$SC/python:$SC"' ~/.profile >/dev/null || echo 'export PYTHONPATH="$SC/python:$SC"' >> ~/.profile
source ~/.profile
mkdir -p "$GOPATH"
mkdir -p "$GOPATH/src/github.com/scionproto"
cd "$GOPATH/src/github.com/scionproto"

if [ ! -d scion ]; then
    git config --global url.https://github.com/.insteadOf git@github.com:
    git clone --recursive -b scionlab git@github.com:netsec-ethz/netsec-scion scion
    cd scion

    # Check if there is a patch directory
    if  [[ ( ! -z ${patch_dir+x} ) && -d ${patch_dir} ]]
    then
        echo "Applying patches:"
        patch_files="$patch_dir/*.patch"

        for f in $patch_files;
        do
            echo -e "\t$f"
            git apply "$f"
        done

        git_username=$(git config user.name || true)

        # We need to have git user in order to commit
        if [ -z "$git_username" ]
        then
            echo "GIT user credentials not set, configuring defaults"
            git config --global user.name "Scion User" 
            git config --global user.email "scion@scion-architecture.net"
        fi

        git commit -am "Applied platform dependent patches"

        echo "Finished applying patches"
    fi

    echo "Installing dependencies"
    bash -c 'yes | GO_INSTALL=true ./env/deps'
    echo "Building SCION"
    ./scion.sh build
    echo "SCION built"

    sudo cp docker/zoo.cfg /etc/zookeeper/conf/zoo.cfg
    # Add cron script which removes old zk logs
    sudo bash -c 'cat > /etc/cron.daily/zookeeper << CRON1
#! /bin/sh
/usr/share/zookeeper/bin/zkCleanup.sh -n 3
CRON1'
    sudo chmod 755 /etc/cron.daily/zookeeper

    cd sub
    git clone git@github.com:netsec-ethz/scion-viz
    cd scion-viz/python/web
    pip3 install --user --require-hashes -r requirements.txt
    python3 ./manage.py migrate
else
    echo "SCION already present, not building it."
fi
cd "$SC"
# Check if gen directory exists
if  [[ ( ! -z ${gen_dir+x} ) && -d ${gen_dir} ]]
then
    echo "Gen directory is specified! Using content from there!"
    cp -r "$gen_dir" .
else
    echo "Gen directory is NOT specified! Generating local (Tiny) topology!"
    ./scion.sh topology -c topology/Tiny.topo
fi
./scion.sh stop
./supervisor/supervisor.sh reload

# Should we add aliases
if [[ (! -z ${aliases_file} ) ]]
then
  echo "Adding aliases to $aliases_file"

  echo "alias cdscion='cd $SC'" >> "$aliases_file"
  echo "alias checkbeacons='tail -f $SC/logs/bs*.DEBUG'" >> "$aliases_file"
fi

if  [[ ( ! -z ${vpn_config_file+x} ) && -r ${vpn_config_file} ]]
then
    echo "VPN configuration specified! Configuring it!"

    sudo apt-get -y install openvpn

    sudo cp "$vpn_config_file" /etc/openvpn/client.conf
    sudo chmod 600 /etc/openvpn/client.conf
    sudo systemctl start openvpn@client
    sudo systemctl enable openvpn@client
fi

tempfile=$(mktemp)
if  [[ ( ! -z ${scion_service_path+x} ) && -r ${scion_service_path} ]]
then
    echo "Registering SCION as startup service"

    cp "$scion_service_path" "$tempfile"
    # We need to replace template user with current username
    sed -i "s|_USER_|$USER|g;s|/usr/local/go/bin|$(dirname $(which go))|g" "$tempfile"
    sudo cp "$tempfile" /etc/systemd/system/scion.service
    sudo systemctl enable scion.service
    sudo systemctl restart scion.service || true
    rm "$tempfile"
else
    echo "SCION systemd service file not specified! SCION won't run automatically on startup."
    ./scion.sh start nobuild
fi

if  [[ ( ! -z ${scion_viz_service+x} ) && -r ${scion_viz_service} ]]
then
    echo "Registering SCION-viz as startup service"

    cp "$scion_viz_service" "$tempfile"
    # We need to replace template user with current username
    sed -i "s/_USER_/$USER/g" "$tempfile"
    sudo cp "$tempfile" /etc/systemd/system/scion-viz.service

    sudo systemctl enable scion-viz.service
    sudo systemctl start scion-viz.service

    rm "$tempfile"
else
    echo "SCION-viz systemd service file not specified! SCION-viz won't run automatically on startup."
fi

if [[ $keep_user_context = true ]]
then
  sudo sh -c 'echo RemoveIPC=no >> /etc/systemd/logind.conf'
fi

if  [[ ( ! -z ${upgrade_script+x} ) ]]
then
    echo "Copying scion upgrade script"

    chmod +x ${upgrade_script}
    sudo cp ${upgrade_script} ${UPGRADE_SCRIPT_LOCATION}
else
    echo "SCION upgrade script not specified."
fi

if  [[ ( ! -z ${upgrade_service+x} ) && -r ${upgrade_service} \
    && ( ! -z ${upgrade_timer+x} ) && -r ${upgrade_timer} \
    && ( ! -z ${UPGRADE_SCRIPT_LOCATION+x} ) && -r ${UPGRADE_SCRIPT_LOCATION} ]]
then
    echo "Registering SCION periodic upgrade service"

    cp "$upgrade_service" "$tempfile"
    sed -i "s|_USER_|$USER|g;s|/usr/local/go/bin|$(dirname $(which go))|g" "$tempfile"
    sudo cp "$tempfile" /etc/systemd/system/scionupgrade.service
    rm "$tempfile"

    cp "$upgrade_timer" "$tempfile"
    sed -i "s/_USER_/$USER/g" "$tempfile"
    sudo cp "$tempfile" /etc/systemd/system/scionupgrade.timer
    rm "$tempfile"

    sudo systemctl enable scionupgrade.timer
    sudo systemctl enable scionupgrade.service
    
    sudo systemctl start scionupgrade.timer

    if [ -d "/vagrant" ]; then # iff this is a VM
        echo "Detected running inside Vagrant"
        # registering the upgrade service also means "manage SCION", including keep time sync'ed
        sudo apt-get install -y --no-remove ntp || true
        sudo sed -i -- 's/^\(\s*start-stop-daemon\s*--start\s*--quiet\s*--oknodo\s*--exec\s*\/usr\/sbin\/VBoxService\)$/\1 -- --disable-timesync/g' /etc/init.d/virtualbox-guest-utils || true
        # restart virtual box guest services and NTPd :
        sudo systemctl daemon-reload || true
        sudo systemctl restart virtualbox-guest-utils
        sudo systemctl enable ntp || true
        # we want ntpd to use the -g flag (no panic threshold):
        if ! egrep -- '^NTPD_OPTS=.*-g.*$' /etc/default/ntp >/dev/null; then
            sudo sed -i "s/^NTPD_OPTS='\(.*\)'/NTPD_OPTS=\'\\1\ -g'/g" /etc/default/ntp
        fi
        if ! grep 'tinker panic 0' /etc/ntp.conf; then
            # set panic limit to 0 (disable)
            echo -e "tinker panic 0\n" | sudo tee -a /etc/ntp.conf >/dev/null
        fi
        if ! egrep -- '^pool.*maxpoll.*$' /etc/ntp.conf; then
            sudo sed -i 's/\(pool .*\)$/\1 minpoll 1 maxpoll 6/g' /etc/ntp.conf
        fi
        sudo systemctl restart ntp || true
        # system updates, ensure unattended-upgrades is installed
        if ! dpkg-query -W --showformat='${Status}\n' unattended-upgrades|grep "install ok installed" >/dev/null; then
            sudo apt-get install -f --no-remove unattended-upgrades
        fi
        if [ ! -f /etc/apt/apt.conf.d/51unattended-upgrades ]; then
            echo "Configuring unattended-upgrades"
            echo 'Unattended-Upgrade::Allowed-Origins {
"${distro_id}:${distro_codename}-security";
"${distro_id}ESM:${distro_codename}";
};
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "02:00";' | sudo tee /etc/apt/apt.conf.d/51unattended-upgrades >/dev/null
        fi
    fi
else
    echo "SCION periodic upgrade service and timer files are not provided."
fi
echo "done. (SCION install script)"
