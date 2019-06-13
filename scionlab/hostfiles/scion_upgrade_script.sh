#!/bin/bash

set -e

# version of the systemd files. These are: scionupgrade.{sh,service,timer}
# if you change the version here, you should also change it on the three files mentioned above
SERVICE_CURRENT_VERSION="0.9"

# version less or equal. E.g. verleq 1.9 2.0.8  == true (1.9 <= 2.0.8)
verleq() {
    [ ! -z "$1" ] && [ ! -z "$2" ] && [ "$1" = `echo -e "$1\n$2" | sort -V | head -n1` ]
}
check_system_files() {
    # check service files:
    need_to_reload=0
    declare -a FILES_TO_CHECK=("/etc/systemd/system/scionupgrade.service"
                               "/etc/systemd/system/scionupgrade.timer"
                               "/usr/bin/scionupgrade.sh")
    declare -a PERMISSIONS=(644 644 755)
    for i in ${!FILES_TO_CHECK[@]}; do
        f=${FILES_TO_CHECK[$i]}
        perm=${PERMISSIONS[$i]}
        VERS=$(grep "^# SCION upgrade version" "$f" | sed -n 's/^# SCION upgrade version \([0-9\.]*\).*$/\1/p')
        if ! verleq "$SERVICE_CURRENT_VERSION" "$VERS"; then
            # need to upgrade. (1) get the file with wget. (2) copy the file (3) reload systemd things
            bf=$(basename $f)
            tmpfile=$(mktemp)
            wget "https://raw.githubusercontent.com/netsec-ethz/scion-coord/master/vagrant/$bf" -O "$tmpfile"
            sed -i "s/_USER_/$USER/g" "$tmpfile"
            sudo cp "$tmpfile" "$f"
            sudo chmod "$perm" "$f"
            need_to_reload=1
        fi
        echo "check_system_files $f : is $VERS < $SERVICE_CURRENT_VERSION ? $need_to_reload"
    done
    if [ $need_to_reload -eq 1 ]; then
        if [ -d "/vagrant" ]; then # iff this is a VM
            echo "VM detected, checking time synchronization mechanism ..."
            [[ $(ps aux | grep ntpd | grep -v grep | wc -l) == 1 ]] && ntp_running=1 || ntp_running=0
            [[ $(grep -e 'start-stop-daemon\s*--start\s*--quiet\s*--oknodo\s*--exec\s*\/usr\/sbin\/VBoxService\s*--\s*--disable-timesync$' /etc/init.d/virtualbox-guest-utils |wc -l) == 1 ]] && host_synced=0 || host_synced=1
            if [ $host_synced != 0 ]; then
                echo "Disabling time synchronization via host..."
                sudo sed -i -- 's/^\(\s*start-stop-daemon\s*--start\s*--quiet\s*--oknodo\s*--exec\s*\/usr\/sbin\/VBoxService\)$/\1 -- --disable-timesync/g' /etc/init.d/virtualbox-guest-utils
                sudo systemctl daemon-reload
                sudo systemctl restart virtualbox-guest-utils
            fi
            if [ $ntp_running != 1 ]; then
                echo "Installing ntpd..."
                sudo apt-get install -y --no-remove ntp || true
                sudo systemctl enable ntp || true
            fi
            if ! egrep -- '^NTPD_OPTS=.*-g.*$' /etc/default/ntp >/dev/null; then
                sudo sed -i "s/^NTPD_OPTS='\(.*\)'/NTPD_OPTS=\'\\1\ -g'/g" /etc/default/ntp
            fi
            if ! egrep -- '^tinker panic 0' /etc/ntp.conf >/dev/null; then
                echo "set panic limit to 0 (disable)"
                echo -e "tinker panic 0\n" | sudo tee -a /etc/ntp.conf >/dev/null
            fi
            if ! egrep -- '^pool.*maxpoll.*$' /etc/ntp.conf >/dev/null; then
                echo "set minpoll 1 maxpoll 6 (increase frequency of ntpd syncs)"
                sudo sed -i 's/\(pool .*\)$/\1 minpoll 1 maxpoll 6/g' /etc/ntp.conf
            fi
            sudo systemctl restart ntp || true
            echo "ntpd restarted."
            # system updates, ensure unattended-upgrades is installed
            if ! dpkg-query -W --showformat='${Status}\n' unattended-upgrades|grep "install ok installed" >/dev/null; then
                echo "Installing unattended-upgrades"
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
            if [ ! -x /etc/update-motd.d/99-scionlab-upgrade ]; then
                cat << "MOTD1" | sudo tee /etc/update-motd.d/99-scionlab-upgrade > /dev/null
#!/bin/bash

SC=/home/ubuntu/go/src/github.com/scionproto/scion
cd "$SC"
[[ -f "scionupgrade.auto.inprogress" ]] && dirtybuild=1 || dirtybuild=0
if [ $dirtybuild -eq 1 ]; then
    printf "\n"
    printf "===========================================================================\n"
    printf "================= WARNING !! ==============================================\n"
    printf "===========================================================================\n"
    printf " SCIONLab is updating. Please wait until it finishes to run scion.sh start\n"
    printf "===========================================================================\n"
    printf "\n"
fi
MOTD1
                sudo chmod 755 /etc/update-motd.d/99-scionlab-upgrade
            fi
            # reload logind (inexpensive) as it seems that some user VMs still remove /run/shm when logout:
            sudo systemctl reload-or-restart systemd-logind.service
        fi # if [ -d "/vagrant" ]
        # don't attempt to stop the scionupgrade service as this script is a child of it and will also be killed !
        # even with KillMode=none in the service file, restarting the service here would be really delicate, as it
        # could basically hang forever if the service files don't update the version number correctly, and we would
        # spawn a large number of processes one after the other, not doing anything but restarting the service.
        sudo systemctl daemon-reload
    fi # if [ $need_to_reload -eq 1 ]
}

install_scionlab_config() {
    if [ -z `which scionlab-config` ]; then
        tmpfile=`mktemp`
        wget "https://raw.githubusercontent.com/netsec-ethz/scionlab/master/scionlab/hostfiles/scionlab-config" -O $tmpfile
        chmod +x $tmpfile
        sudo mv $tmpfile /usr/local/bin/scionlab-config
    fi
}



shopt -s nullglob

export LC_ALL=C

if [ "$1" != "-m" ]; then
    # systemd files upgrade:
    check_system_files
else
    echo "Skipping check_system_files, because -m (manual) is given"
fi


cd $SC

git_username=$(git config user.name || true)
if [ -z "$git_username" ]
then
    echo "GIT user credentials not set, configuring defaults"
    git config --global user.name "Scion User"
    git config --global user.email "scion@scion-architecture.net"
    git config --global url.https://github.com/.insteadOf git@github.com:
fi

git fetch origin scionlab &>/dev/null

git merge-base --is-ancestor origin/scionlab scionlab && needtoreset=0 || needtoreset=1
[[ $(git rev-parse --abbrev-ref --symbolic-full-name @{upstream}) == "origin/scionlab" ]] && badtracking=0 || badtracking=1
[[ -f "scionupgrade.auto.inprogress" ]] && dirtybuild=1 || dirtybuild=0
echo "Need to reset? $needtoreset . Dirty build? $dirtybuild . Bad tracked branch? $badtracking"

if [ $needtoreset -eq 0 ] && [ $badtracking -eq 0 ] && [ $dirtybuild -eq 0 ]; then
    echo "SCION version is already up to date and ready!"
else
    touch "scionupgrade.auto.inprogress"
    # anounce we are upgrading now
    [ -x /etc/update-motd.d/99-scionlab-upgrade ] && /etc/update-motd.d/99-scionlab-upgrade | wall
    git stash >/dev/null # just in case something was locally modified
    if [ $badtracking -ne 0 ]; then
        git checkout origin/scionlab -b scionlab || git checkout scionlab
    fi
    git reset --hard origin/scionlab

    echo "SCION code has been upgraded, stopping..."

    # rebuild scion
    ./scion.sh stop || true
    ~/.local/bin/supervisorctl -c supervisor/supervisord.conf shutdown || true
    MEMTOTAL=$(grep MemTotal /proc/meminfo  | awk '{print $2}')
    echo "Available memory is: $MEMTOTAL"
    # if less than 4Gb
    [[ $MEMTOTAL -lt 4194304 ]] && swapadded=1 || swapadded=0
    if [ $swapadded -eq 1 ]; then
        echo "Not enough memory, adding swap space..."
        sudo fallocate -l 4G /tmp/swap
        sudo mkswap /tmp/swap
        sudo swapon /tmp/swap
        echo "Swap space added."
    else
        echo "No swap space needed."
    fi
    echo "Reinstalling dependencies..."
    ./scion.sh clean || true
    mv go/vendor/vendor.json /tmp && rm -r go/vendor && mkdir go/vendor || true
    mv /tmp/vendor.json go/vendor/ || true
    pushd go >/dev/null
    govendor sync || true
    popd >/dev/null
    # because upgrading to SCIONLab 2019-01 will fail if installed, remove it:
    sudo apt-get remove -y parallel
    bash -c 'yes | GO_INSTALL=true ./env/deps' || echo "ERROR: Dependencies failed. Starting SCION might fail!"
    echo "Rebuilding SCION..."
    ./scion.sh build && rm -f "scionupgrade.auto.inprogress" || { echo "Build failed!"; exit 1; }
    if [ $swapadded -eq 1 ]; then
        echo "Removing swap space..."
        sudo swapoff /tmp/swap && sudo rm -f /tmp/swap || true
        echo "Swap space removed."
    fi

    echo "Emptying caches..."
    ./tools/zkcleanslate || true
    rm -f gen-cache/*
    mkdir -p gen-cache/

    # get a new gen folder:
    echo "We will get the AS configuration from the Coordinator now."
    install_scionlab_config
    if [ -f "gen/account_id" ]; then
        # Use old account-id/account-secret files to generate host-id/host-secret as imported into new scionlab-coordinator.
        ia=$(<gen/ia)
        as_id=${ia#*-}
        account_id=$(<gen/account_id)
        host_id=`echo -n $account_id$as_id | md5sum | cut -c 1-32`
        host_secret=$(<gen/account_secret)
        scionlab-config --host-id="$host_id" --host-secret="$host_secret"
    else
        scionlab-config
    fi

    # announce we are done with the upgrade
    printf "SCIONLab has been upgraded. You can now safely run commands involving scion.sh\n\n" | wall
fi
# update scion-viz
if [ -d "./sub/scion-viz" ]; then
    pushd "./sub/scion-viz" >/dev/null
    git stash >/dev/null || true
    pull_result=$(git pull --ff-only) || true
    if [[ ! -z $pull_result && $pull_result != *"up-to-date"* ]]; then
        sudo systemctl restart scion-viz
    fi
    popd >/dev/null
fi

echo "Done."
