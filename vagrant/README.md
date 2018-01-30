# OOR Testbed Vagrant Setup

This folder contains various files to create a quick OOR testbed using Vagrant
and VirtualBox. While the [Vagrantfile](../Vagrantfile) in the top-level
folder creates a single VM ready for development, the
[Vagrantfile](Vagrantfile) in this folder creates a testbed with several VMs
with OOR running, pre-configured for various roles (map server, mobile node,
etc.)

## Running the default testbed

Running the default testbed should be as easy as

    vagrant up

This command will bring up all Ubuntu VMs defined in the Vagrantfile, each
provisioned for a specific role with a specific configuration file. To list
available VMs, run

    vagrant status

The output should look similar to this:

    Current machine states:

    msmr                      running (virtualbox)
    mn1                       running (virtualbox)
    mn2                       running (virtualbox)

    This environment represents multiple VMs. The VMs are all listed
    above with their current state. For more information about a specific
    VM, run `vagrant status NAME`.

To access a specific VM via SSH run `vagrant ssh NAME`, e.g.,

    vagrant ssh mn1

VMs are preprovisioned with a [.bash_history](.bash_history) file that allows
quick access to commands to ping other VMs or take a look at the OOR log file,
by just pressing the "arrow up" key.

## Running a partial testbed

It is possible to bring up only a subset of the VMs defined in the
Vagrantfile. First, check available VMs:

    vagrant status

To bring up a specific VM, run `vagrant up NAME`, e.g.,

    vagrant up msmr

Specific test scenarios can be scripted with the `vagrant up` commands
necessary to build them.

## Testbed network configuration

Each VM on the testbed has two network interfaces, one is the default NAT
interface required by Vagrant to SSH into the box, the other is the host-only
RLOC interface. RLOC interfaces have IPv4 addresses from the 192.168.127.0/24
network, allocated manually (DHCP is disabled in VirtualBox for this network),
with 192.168.127.1 reserved for the host OS.

Mobile nodes in the testbed use IPv4 /32 EIDs from the 192.0.2.0/24 network
(the reason for this specific network is that it is reserved by the IETF for
documentation purposes), and the VXLAN-GPE encapsulation by default. See
[configuration](oor.mn1.conf) [files](oor.mn2.conf) for all the details.

### Traffic monitoring

VirtualBox creates a `vboxnetX` interface on the host OS for the host-only
network of the RLOC interfaces, which are all configured for promiscuous mode,
allowing traffic monitoring. The value of `X` can be determined in the
VirtualBox GUI, by selecting one of the created VMs and looking at the
**Network** section. It should say something like _"Adapter 2: Intel PRO/1000
MT Desktop (Host-only Adapter, 'vboxnet2')"_. Wireshark can be used on the
host OS to monitor traffic between VMs on that interface.

Of course, traffic can be monitored on the VMs themselves too, using the
preinstalled `tshark` CLI traffic analyzer. There is a full `tshark` command
in the provisioned [.bash_history](.bash_history) file that sets the RLOC
interface for monitoring and applies filtering for ICMP, LISP, and VXLAN
traffic:

    tshark -n -i eth1 -Y "icmp || lisp || lisp-data || vxlan"

### Debugging the LISP control plane with lig

Provisioning scripts preinstall the LISP Internet Groper `lig` described in
[RFC 6835](https://tools.ietf.org/html/rfc6835) to help debug the LISP control
plane. The `LISP_MAP_RESOLVER` environment variable is set to the RLOC of the
`msmr` VM running the mapping service, and can be changed in the `~/.bashrc`
file, or overridden on the command line.

## The OpenDaylight based map server

The default map server in the setup is based on OOR, but if required, it is
possible to run an OpenDaylight (ODL) based map server too, using the
`msmr-odl` VM. ODL is started automatically, and the REST interface is
available at `http://192.168.127.3:8181/restconf/` with the default
credentials (username: _admin_, password: _admin_). For details on how to use
the ODL map server, please consult the [ODL LISP Flow Mapping
Documentation](http://docs.opendaylight.org/en/stable-nitrogen/user-guide/lisp-flow-mapping-user-guide.html).
It has a
[section](http://docs.opendaylight.org/en/stable-nitrogen/user-guide/lisp-flow-mapping-user-guide.html#creating-a-lisp-overlay-with-oor)
dedicated to creating an overlay with OOR, and links to
[Postman](https://www.getpostman.com/apps) collections
[here](https://git.opendaylight.org/gerrit/gitweb?p=lispflowmapping.git;a=tree;f=resources/tutorial/OOR;hb=refs/heads/stable/nitrogen)
and
[here](https://git.opendaylight.org/gerrit/gitweb?p=lispflowmapping.git;a=tree;f=mappingservice/implementation/src/main/resources;hb=refs/heads/stable/nitrogen)
to interact with ODL.

To access the ODL CLI, simply run `client` in the VM. Once in the ODL CLI, the
`mappings` command will show both statically configured mappings (using the
REST API from the northbound interface) under _Policy map-cache_ and
dynamically registered mappings (with UDP Map-Register messages from the
southbound interface) under _Southbound map-cache_. The `keys` command will
show configured sites, including their passwords. The `addkey` command will
add 0.0.0.0/0 and ::0/0 as sites configured with the default password
**password**, allowing any EID prefix to be registered for instance ID 0 with
key-ID 1 and password **password** from the southbound interface.

The ODL CLI has a history file similar to Bash. The `msmr-odl` VM is
preprovisioned with a [history file](karaf.history) (history can be accessed
with "arrow up", and searched with Ctrl-R, just like in Bash) with the above
commands, and some other useful commands. One of those for example sets the
log level for the LISP Flow Mapping component only to DEBUG (the rest of
componenents stays at the default INFO level):

    log:set DEBUG org.opendaylight.lispflowmapping

The log can be displayed with `log:display`, and watched with `log:tail`. Feel
free to explore the purpose of the other commands.

Since the ODL based map server has an RLOC that's different from the default
OOR map server, it is necessary to edit the configuration files of the OOR
nodes needing to contact it (mobile nodes, xTRs, etc.)
