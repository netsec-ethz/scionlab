# SCIONLab VM

## Install Vagrant and VirtualBox

Running your AS in a VM as suggested below requires Vagrant and VirtualBox.

Please install Vagrant and VirtualBox:
  - https://www.virtualbox.org/wiki/Downloads
  - https://www.vagrantup.com/docs/installation/

On recent Ubuntu or Debian systems, it may be enough to run

  $ sudo apt-get install vagrant virtualbox


## Using Vagrant to run the VM

Navigate your shell to the directory containing the Vagrantfile (and this README).
Note that all vagrant commands always need to be run in this directory!
To start your VM, run

  $ vagrant up

When running you're VM for the first time, this will download the Ubuntu base box
and then install all the SCION packages and their dependencies.

This will already start the services for your SCIONLab AS.

Once the `vagrant up` command returns the prompt, you can connect to your VM to
start exploring:

  $ vagrant ssh

The directory containing the Vagrant file is synced with the VM where the files
will appear in the `/vagrant/` directory.
This is convenient way to share files between your your host machine and your
VM, and allows to move data both ways.

To shutdown the VM, run

  $ vagrant halt

To start it back up, just type `vagrant up` again. Finally, if you want to wipe
your VM, e.g. to start fresh, run `vagrant destroy`.

More information for `vagrant` commands can be found at:
https://www.vagrantup.com/docs/cli


## Running SCION

The SCION infrastructure is automatically started when the VM boots up.

Please refer to the online tutorials for more information:
https://netsec-ethz.github.io/scion-tutorials/
