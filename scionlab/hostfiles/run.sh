#!/usr/bin/env bash

# BEGIN subcommand functions

VB="virtualbox"
VG="vagrant"
VM="vagrant-manager"

run_vagrant() {
    echo "[SCIONLabVM] run vagrant"
    vagrant box add scion/ubuntu-16.04-64-scion
    vagrant box update
    vagrant up
    vagrant ssh
}

run_osx() {
    echo "[SCIONLabVM] Given system: OSX"
    if ! type "brew" > /dev/null; then
        echo "[SCIONLabVM] Now installing Homebrew"
        ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
    fi
    for pkg in $VB $VG $VM; do
        if pkgutil --pkgs=$pkg > /dev/null; then
            echo "[SCIONLabVM] $pkg is already installed"
        elif brew cask ls $pkg > /dev/null; then
            echo "[SCIONLabVM] $pkg is already installed"
        else
            echo "[SCIONLabVM] Installing $pkg"
            brew cask install --force $pkg
        fi
    done
    run_vagrant
}

# version less or equal. E.g. verleq 1.9 2.0.8  == true (1.9 <= 2.0.8)
verleq() {
    [  "$1" = "`echo -e "$1\n$2" | sort -V | head -n1`" ]
}

run_linux() {
    if [[ -f "/usr/bin/apt-get" && -f "/usr/bin/dpkg" ]]
    then
        echo "[SCIONLabVM] Given system: LINUX"
        if dpkg --get-selections | grep -q "^$VB.*[[:space:]]\{1,\}install$" >/dev/null; then
            echo "[SCIONLabVM] $VB is already installed"
        else
            while true; do
                read -p "[SCIONLabVM] Do you want to install/upgrade $VB now? If no, it will terminate SCIONLabVM immediately. [y/n]" yesno
                case $yesno in
                    [Yy]*)
                        echo "[SCIONLabVM] Installing $VB"
                        sudo apt-get --no-remove --yes install virtualbox
                    break;;
                    [Nn]*) echo "[SCIONLabVM] Closing SCIONLabVM installation."; exit 1;;
                    *) ;;
                esac
            done
        fi
        if dpkg --get-selections | grep -q "^$VG.*[[:space:]]\{1,\}install$" >/dev/null; then
            echo "[SCIONLabVM] $VG is already installed"
        else
            while true; do
                read -p "[SCIONLabVM] Do you want to install/upgrade $VG now? If no, it will terminate SCIONLabVM immediately. [y/n]" yesno
                case $yesno in
                    [Yy]*)
                        echo "[SCIONLabVM] Installing $VG"
                        sudo apt-get --no-remove --yes install $VG
                    break;;
                    [Nn]*) echo "[SCIONLabVM] Closing SCIONLabVM installation."; exit 1;;
                    *) ;;
                esac
            done
        fi
        run_vagrant
    else
        echo "Currently, this script does not support your linux distribution."
        echo "Please follow the instructions in the README file to run the SCIONLab AS."
    fi
}


case "$OSTYPE" in
  darwin*)
        "run_osx" ;;
  linux*)
        "run_linux" ;;
  solaris*|bsd*|msys|*) 
    echo "Currently, this script does not support $OSTYPE system."
    echo "Please follow the instructions in the README file to run the SCIONLab AS." ;;
esac
