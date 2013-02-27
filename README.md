Overview
--------

The Locator/ID Separation Protocol (LISP) is being developed within the IETF
as a potential solution to the routing scalability problem documented in RFC
4984. It uses the concept of Endpoint IDentifiers (EIDs) to name hosts in edge
networks, and Routing LOCators (RLOCs) for nodes in transit networks. EIDs and
RLOCs are syntactically indistinguishable from current IPv4 and IPv6 addresses,
enabling backwards compatibility with the existing Internet architecture. A
distributed database, the mapping system, is responsible for maintaining the
associations between EIDs and RLOCs.

LISP Mobile Node (LISP-MN) is a specification to enable fast host mobility
using LISP.  The LISPmob project aims to deliver a full implementation of both
LISP and LISP-MN for Linux, but parts of the implementation may be reusable on
other Unix-like operating systems.

Please note that version 0.3 introduces major changes in the code architecture
and branch 0.3 is considered experimental. Not all features present in previous
versions are in 0.3 yet. See section "Version 0.3" below for more details.
For a more featured (but frozen) version use latest code in 'release-0.2' branch 
(currently 0.2.4) and refer to the README file there.

In version 0.3 the code was generalized and now it not only serves to MNs,
but also can be used in a domestic router (OpenWRT) to provide LISP routing
capabilities. Please refer to "OpenWRT" section at the end for details on this.

LISPmob consists of three major components:

  * data plane
  * control plane
  * tools

Since version 0.3, the user space daemon `lispd` is responsible for both
control plane and data plane functionality. It is responsible for creating a
virtual interface for the EID(s), encapsulating/decapsulating packets,
maintaining the mapping cache, etc. (data plane functionality) and for
sending and receiving control messages, managing interfaces, etc. (control
plane functionality), among other funcionalities.

The distribution offers some external tools as well, which can be used for
various testing and debugging purposes.

The current reference platform for LISPmob development is Ubuntu Server
12.04.1 LTS (Precise Pangolin), and OpenWRT 12.09 (Attitude Adjustment).
It was also demonstrated on a Nokia N900 mobile phone running MeeGo 1.2
Community Edition.


Network Prerequisites
---------------------

Running LISPmob host on the public Internet requires the following:

  * an EID from a Mapping Service Provider (MSP),
  * the RLOC of the Map-Server that will accept the registration of this EID,
  * an authentication token to register the EID with the Map-Server,
  * the RLOC of a Map-Resolver,
  * the RLOC of a Proxy-ETR,
  * a publicly routable RLOC for the host, which is neither firewalled, nor behind NAT.

Other than the last item, the above information is used for configuring 'lispd'
via the configuration file 'lispd.conf'. See section "OpenWRT" for OpenWRT
configuration details.

When used in a MN, the EID will be used by the applications on the host for 
establishing communications. The RLOC will differ, depending on the network 
point of attachment, i.e., it will be the IP address assigned to the host in 
the visited network. See the "References" section for pointers to detailed
documentation on the above concepts and network elements.

Visit http://www.lisp4.net/ for more info on the deployment status of the LISP
pilot network and how you can join the testbed.

Software Prerequisites
----------------------

To build LISPmob for a standard Linux, you will need:

  * a Linux hosts with a fairly recent kernel (tested with 3.2.0)
  * a C compiler (tested with `gcc`)
  * GNU make
  * git, unless you use a tarball
  * OpenSSL development headers
  * libConfuse

On Debian-derived Linux distributions (including Ubuntu), installing the
following packages will provide all necessary dependencies:

  * 'build-essential'
  * 'git-core'
  * 'libssl-dev'
  * 'libconfuse-dev'

The latest version of the LISPmob source code can be obtained from Github:

    git clone git://github.com/LISPmob/lispmob.git


Installation
------------

To build and install the code, run the following in the top-level directory:

    make
    sudo make install

This will build the executable files, installed to `/usr/local/sbin`.


Running LISPmob
---------------

Once the code is successfully installed on the host, `lispd.conf.example`
should be copied to `/etc/lispd.conf` and edited with the values obtained from
the MSP (see "Network Prerequisites"). Again, see section 'OpenWRT' for OpenWRT
details about this. Additionally the host interface used for physical network
connectivity (such as 'eth0', 'wlan0' or 'ppp0') must also be specified in
the configuration file.

Prior to execute LISPmob, make sure that each external interface (such as 'wan0') 
has defined a default route in the routing table (there is a 'default' entry for 
each outgoing interface). In most cases, this is auto-configured by the 
operating system during start-up.

Check that sysctl options configuration is correct. Make sure that rp_filter 
kernel network parameter is disabled. It is disabled by default in OpenWRT,
but, for instance, it is enabled by default in Ubuntu. Make sure too that 
IP forwarding is enabled. It should be enabled by default in OpenWRT.

Configure these values during OS runtime with the following commands
    
    sudo sysctl net.ipv4.conf.default.rp_filter=0
    sudo sysctl net.ipv4.conf.all.rp_filter=0
    sudo sysctl net.ipv4.ip_forward=1
    sudo sysctl net.ipv6.conf.all.forwarding=1  
    
You can instruct your system to auto-configure these values during system boot-up 
if you add the following lines to `/etc/sysctl.conf`

    net.ipv4.conf.default.rp_filter=0
    net.ipv4.conf.all.rp_filter=0
    net.ipv4.ip_forward=1
    net.ipv6.conf.all.forwarding=1   

The user space daemon must be started as the super-user:

    sudo lispd -f /etc/lispd.conf

It will set up networking and register to the mapping system, after which you
can enjoy all the benefits of LISP-MN. When 'lispd' is running in MN mode,
the EID obtained from the MSP is associated to the 'lispTun0' virtual interface. 
Two /1 routes covering the full IP addresses space should appear in the routing 
table. These routes should be pointing to 'lispTun0' device:

    $ ip addr
    1: lo: <LOOPBACK,UP,LOWER_UP> mtu 16436 qdisc noqueue state UNKNOWN 
        link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
        inet 127.0.0.1/8 scope host lo
           valid_lft forever preferred_lft forever
    2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP qlen 1000
        link/ether 00:00:00:00:00:00 brd ff:ff:ff:ff:ff:ff
        inet <RLOC> brd <RLOC_BROADCAST> scope global eth0
           valid_lft forever preferred_lft forever
    3: lispTun0: <POINTOPOINT,UP,LOWER_UP> mtu 1450 qdisc pfifo_fast state UNKNOWN qlen 500
        link/none 
        inet <EID> scope host lispTun0


    $ ip route
    <Visited_Network> dev eth0  proto kernel  scope link  src <RLOC>
    169.254.0.0/16 dev eth0  scope link  metric 1000
    0.0.0.0/1 dev lispTun0
    128.0.0.0/1 dev lispTun0
    default via <RLOC_GW> dev eth0  metric 100


Version 0.3
-----------

Version 0.3 introduced major changes into LISPmob. The most important was to
discontinue the separation of data-plane in kernel-space and control-plane in
user-space. This resulted in a merged data+control user-space daemon. This is 
possible thanks to the use of TUN/TAP, creating a TUN virtual interface to deal 
with data-plane.

This big architecture change was also used to perform a general clean-up and
restructuring for most of the code. Due to this, existing (or partially developed) 
functionalities should be adapted to the new architecture and structure. 

This is the list of supported features at this moment: 

    - Register to the Mapping System
    - Request mappings
    - Reply to mapping requests
    - Encapsulate data packets
    - Decapsulate data packets
    - RLOC Probing (reply only)
    - IPv6 full support (EIDs and RLOCs)



OpenWRT
-------

Since version 0.3, LISPmob can be also used to operate as a router. This 
working mode was developed with OpenWRT in mind, but it should work in any 
Linux box configured to work as a router. When running in a router, LISPmob 
serves as a xTR (Ingress/Egress Tunnel Router) that performs LISP 
encapsulation/decapsulation of packets generated by hosts behind the router. 

Thanks to the versatility of the TUN approach, the code changes to support 
OpenWRT are minimal. However, to enable OpenWRT mode and therefore the 
routing specific operations, the code should be compiled with the option 
-DOPEN_WRT. To link with UCI (Unified Configuration Interface) library the
-luci option must be used too.

The basic LISPmob requisites and configuration parameters must be complied 
with for the router mode but, there are a few specific requirements that are
specific for this mode. To configure LISPmob to use it on router mode use the 
general LISPmob configuration instructions considering the following exceptions:

An EID /30 (at least) prefix is required instead of a /32 one. This prefix 
should be used as the network prefix for the subnet where the hosts behind 
the router are allocated. Assign it to an interface and configure it as you 
would do for a normal network prefix (static configuration, DHCP, etc...). 
No EID is used for the 'lispTun0' interface in router mode (a local address is 
automatically used by LISPmob instead).

The configuration is performed through the OpenWRT standard configuration tool 
UCI, instead of using 'lispd.conf' file. Configure the UCI file manually in 
'/etc/config/lispd' (by default), use the UCI CLI application, or use the web 
interface (if available). The configuration fields are analogue to those in 
the 'lispd.conf' file.


Contact
-------

Should you have questions regarding the use of the LISPmob distribution, please
subscribe to the users@lispmob.org mailing list and ask there
(https://lispmob.org/mailman/listinfo/users).

If you wish to participate in the development of LISPmob, use the dedicated
mailing list, devel@lispmob.org (https://lispmob.org/mailman/listinfo/devel).

Additionally, important announcements are sent to the low volume mailing list
announce@lispmob.org (https://lispmob.org/mailman/listinfo/announce).

More interactive help can sometimes be obtained on the '#lispmob' IRC channel
on FreeNode.

Bugs you encounter should be filed at the [repository's issue tracker on
Github](https://github.com/LISPmob/lispmob/issues).


References
----------

1. [The Locator Identifier Separation Protocol (LISP)](http://www.cisco.com/web/about/ac123/ac147/archived_issues/ipj_11-1/111_lisp.html)
2. [Locator/ID Separation Protocol](http://tools.ietf.org/html/draft-ietf-lisp)
3. [LISP Mobile Node](http://tools.ietf.org/html/draft-meyer-lisp-mn)
4. [Interworking LISP with IPv4 and IPv6](http://tools.ietf.org/html/draft-ietf-lisp-interworking)
5. [LISPmob Project](http://lispmob.org/)
