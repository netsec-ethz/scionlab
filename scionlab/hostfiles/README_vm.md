# SCIONLabVM
SCIONLab Virtual Machine


## Setup of the virtual machine

### For Ubuntu and Mac OS users:

The shell script `run.sh` will automatically check your system and install
the necessary packages to run SCIONLabVM, such as `vagrant` and `virtualbox`.
It will also create and configure the SCIONLabVM automatically.

Please Note: SCIONLabVM requires `vagrant 1.9.7`, `virtualbox 5.0.4` or above.

In order to install the latest version of packages, the shell script will run
apt-get update on your system. Please make sure that all the running VMs are
suspended or closed before running the script.

If you agree with these requirements, you can then simply setup your SCIONLabVM via:
`./run.sh` from inside the downloaded folder.

Once the setup is finished, you will automatically be inside the SCIONLabVM
through SSH. After this step, you will be ready to run SCION as described below.


### For users of other Linux distributions:

You need to install `vagrant` and `virtualbox` manually using your distribution`s package manager.

After the install is done, run the following commands from inside the downloaded folder:
```
vagrant box add scion/ubuntu-16.04-64-scion
vagrant box update
vagrant up
vagrant ssh
```

After this, you are connected to your VM via ssh, where you can run SCION as described below.


### For Windows users:

SCIONLabVM requires `virtualbox` and `vagrant`.
First, you need to download and install the `virtualbox` from:
https://www.virtualbox.org/wiki/Downloads

After this step, you also need to download and install `vagrant` from:
https://www.vagrantup.com/downloads.html

Afterwards, open a terminal window and go to the SCIONLabVM folder where the
`Vagrantfile` is located. Now, you can run `vagrant up`. The command will
automatically download the base VM image storing `ubuntu/ubuntu-16.04-64-scion`, and
install SCION with all other dependencies.

If the `vagrant up` command returns the prompt, you are ready to have fun with SCIONLabVM.

Finally, you can run `vagrant ssh` to connect to your VM, where you can run SCION as described below.


## Running SCION

The SCION infrastructure is automatically started when the VM boots up.

After your setup is activated at the designated SCIONLab AS, you should be able to see the beacons
being received.
You can test this by checking the logs in `/go/src/github.com/scionproto/scion/logs/` or by simply
calling `checkbeacons`.


## Visualizing the network topology

You can access the SCION AS Visualization Tool at `localhost:8000` from outside the VM.
The tool is automatically started inside the VM and displays paths to other SCION ASes.


## Stopping and Restarting the VM

You can stop and restart `SCIONLabVM` using `vagrant` commands.
In order to stop the VM, run `vagrant halt` from the downloaded configuration folder.
If you want start the VM again, just run `vagrant up`.
More information for `vagrant` commands can be found at:
https://www.vagrantup.com/docs/cli

## Troubleshooting

If an error occurs during the setup process (e.g., a network disruption) the virtual machine may not
be fully functional. In this case you can either manually run the commands specified in the
`Vagrantfile` or alternatively call
```
vagrant destroy
vagrant up
```
from inside the directory where you unpacked your vm configuration (i.e., where the `Vagrantfile` is
located).

If you experience problems with the topology visualization, you may want to manually restart the
SCION infrastructure by either calling `sudo systemctl restart scion.service` or by moving to the
scion directory and calling `./scion.sh stop` followed by `./scion.sh run`.


## Current Vagrant Configuration

The configurations for `vagrant` are defined in the `Vagrantfile` file.
Additional documentation can be found at:
https://www.vagrantup.com/docs/vagrantfile
