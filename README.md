Vagrant virtual machine environment
-----------------------------------

It might be useful for development and testing to be performed isolated in a VM, so there's a `Vagrantfile` in the repo that can be used to start a VM.

    cd charm/
    # NOTE: Only once, in case you don't have Vagrant and VirtualBox installed
    ./install-vagrant.sh
    vagrant up

Crypto notes
------------

See [crypto notes here](crypto.html).
