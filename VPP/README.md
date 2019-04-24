FD.IO - VPP
-----------

VPP is the open source version of Cisco's Vector Packet Processing (VPP) technology: 
a high performance, packet-processing stack that can run on commodity CPUs. 

Open Overlay Router has adopted VPP from the FD.io project as an alternative data plane 
to kernel networking stack that can be used to encapsulate and decapsulate LISP traffic 
in a high performance rate of to 10 Gbps.

The current integration of OOR with VPP is only supported for linux devices with network 
cards with DPDK support. It is limited to OOR configured as an xTR using only IPv4 RLOCs 
and a single default route.

Installation
------------

To take advantage of VPP you will have to compile and configure it previously. If you 
already have installed VPP, notice that we apply a patch to the src code of VPP and more 
exactly to a specific commit of VPP. Without applying this patch, the integration between 
VPP and OOR will not work.

Download the VPP code:

    git clone https://gerrit.fd.io/r/vpp --branch stable/1704
    cd vpp
    git reset --hard e3b7ad7adebf25af1651a217da8534ada89c369b

Patch the code before compiling:

    cp <oor_dir>/VPP/vpp.patch .
    git apply vpp.patch

Install dependecies:

    sudo make install-dep
    sudo apt-get install python-cffi python-ply python-pycparser

Finally, we compile and install VPP:

    cd build-root
    ./bootstrap.sh
    make V=0 PLATFORM=vpp TAG=vpp install-deb
    sudo dpkg -i *.deb


OOR compilation. Read previously the README.md file

    cd <oor_dir>/oor/
    make platform=vpp
    sudo make install

Add the OOR VPP plugins:

    cd <oor_dir>/VPP/oor_ctrl-plugin
    autoreconf -fis
    ./configure && make && sudo make install
    cd <oor_dir>/VPP/oor_pkt_miss-plugin
    autoreconf -fis
    ./configure && make && sudo make install


Configuration
-------------

Here we provide you some basic instructions to configure VPP. If you want more details 
about VPP or how to configure it, check the wiki page of the project 
<https://wiki.fd.io/view/VPP>

To assign an interface to VPP, check it is not up/configured by the Linux Kernel. 
If it is then shut it down: For e.g. If you want to use eth1 in vpp then:
 
   sudo ifconfig eth1 down
   sudo ip addr flush dev eth1

== Notice that the current version of VPP is only a traffic forwarder. Don't assign 
to VPP the management interface of the PC. ==

Start VPP:

    sudo service vpp start

List the interfaces assigned to VPP:

    vppctl show interface

Configure VPP interfaces:

Assign an address to the interface:

    sudo vppctl set int ip address [del] <iface name> <ip address/mask>

Set status of the interface to up:

    sudo vppctl set int state <iface name> up|down

Show the interfaces addresses:

    vppctl show int addr

If you want to use IID different to 0 (only works with local networks), you will have 
to do a previous step before configuring the interface associated with the EIDs:

    sudo vppctl set interface ip|ip6 table <iface_name> <iid>

Once you have configured vpp you can start to use OOR.
