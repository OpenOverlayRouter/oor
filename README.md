

Overview
--------

The Locator/ID Separation Protocol (LISP) is being developed within the IETF as
a potential solution to the routing scalability problem documented in RFC 4984.
It uses the concept of Endpoint IDentifiers (EIDs) to name hosts in edge
networks, and Routing LOCators (RLOCs) for nodes in transit networks. EIDs and
RLOCs are syntactically indistinguishable from current IPv4 and IPv6 addresses,
enabling backwards compatibility with the existing Internet architecture. A
distributed database, the Mapping System, is responsible for maintaining the
associations between EIDs and RLOCs. LISP Mobile Node (LISP-MN) is a
specification to enable fast host mobility using LISP. Among other nice 
features, LISP provides interruption-free global provider-independent roaming
of IP addresses with different networks.

The LISPmob project aims to deliver a full implementation of both LISP and
LISP-MN for Linux-like systems, but parts of the implementation may be reusable
on other Unix-like operating systems.

In version 0.3 the code was generalized and now it not only serves to MNs (Linux 
or Android), but also can be used in a domestic router (Linux or OpenWRT) to 
provide LISP routing capabilities (xTR). Please refer to "Router mode" section 
for details on xTR functionality, and to section "OpenWRT" or "Android" for 
specific details on OpenWRT or Android configuration.

LISPmob consists of three major components:

  * data plane
  * control plane
  * tools

Since version 0.3, the user space daemon 'lispd' is responsible for both control
plane and data plane functionality. It is responsible for creating a virtual
interface to handle EID traffic, encapsulating/decapsulating packets, maintaining
the mapping cache, etc. (data plane functionality) and for sending and receiving
control messages, managing interfaces, etc. (control plane functionality), among
other functionalities.

The distribution offers some external tools as well, which can be used for
various testing and debugging purposes.

The current reference platform for LISPmob development is Ubuntu 14.04 LTS 
(Trusty Tahr), OpenWRT 12.09 (Attitude Adjustment) and Android 4.4 (KitKat). 

Network Prerequisites
---------------------

Running LISPmob host on the public Internet requires the following:

  * an EID from a Mapping Service provider,
  * the RLOC of the Map-Server that will accept the registration of this EID,
  * an authentication password to register the EID with the Map-Server,
  * the RLOC of a Map-Resolver,
  * the RLOC of a Proxy-ETR,
  * a publicly routable RLOC for the host, which is neither firewalled, nor
    behind NAT (see however "NAT traversal" section for details on this).

Other than the last item, the above information is used for configuring 'lispd'
via the configuration file 'lispd.conf'. See section "OpenWRT" for OpenWRT
configuration details and "Android" for Android configuration details.

When used in a MN, the EID will be used by the applications on the host for 
establishing communications. The RLOC will differ, depending on the network 
point of attachment, i.e., it will be the IP address assigned to the host in 
the visited network. See the "References" section for pointers to detailed
documentation on the above concepts and network elements.

Visit http://www.lisp4.net/ for more info on the deployment status of the LISP
beta-network and how you can join the testbed.

Software Prerequisites
----------------------

To build LISPmob for a standard Linux, you will need:

  * a Linux host with a fairly recent kernel (tested with 3.2.0)
  * a C compiler (tested with `gcc`)
  * GNU make
  * git, unless you use a tarball
  * libConfuse
  * gengetopt
  * libcap v2+

On Debian-derived Linux distributions (including Ubuntu), installing the
following packages will provide all necessary dependencies:

  * 'build-essential'
  * 'git'
  * 'libconfuse-dev'
  * 'gengetopt'
  * 'libcap2-bin'

The latest version of the LISPmob source code can be obtained from Github:

    git clone git://github.com/LISPmob/lispmob.git


Installation
------------

To build the code for Linux operating as a Mobile Node, run the following in the
top-level directory:

    make 

To install it in `/usr/local/sbin`, run

    sudo make install
    
To build the code for OpenWRT you will need the OpenWRT official SDK. However,
for your convenience, we encourage you to install the precompiled .ipk, from our
website. Check section "OpenWRT" for details.

To build the code for Android, read the specific file dedicated to that platform,
README.android.md
. Note that you can get a precompiled Android application through Google Play.

Running LISPmob
---------------

Once the code is successfully installed on the host, `lispd.conf.example` should
be copied to `/etc/lispd.conf` and edited with the values obtained from the 
Mapping System provider (see "Network Prerequisites"). Again, see section 
'OpenWRT' for OpenWRT details about this. Additionally the host interface used 
for physical network connectivity (such as 'eth0', 'wlan0' or 'ppp0') must also 
be specified in the configuration file.

Prior to execute LISPmob, make sure that each external interface (such as
'wan0') has defined a default route with different metric in the routing
table (there is a 'default' entry for each outgoing interface). In most cases,
this is auto-configured by the operating system during start-up.

Check that sysctl options configuration is correct. Make sure that rp_filter
kernel network parameter is disabled. It is disabled by default in OpenWRT, but,
for instance, it is enabled by default in Ubuntu. Make sure too that IP
forwarding is enabled. It should be enabled by default in OpenWRT.  
    
You can instruct your system to auto-configure these values during system
boot-up if you add the following lines to `/etc/sysctl.conf`. Remember to 
reboot your system after adding these lines.

    net.ipv4.conf.default.rp_filter=0
    net.ipv4.conf.all.rp_filter=0
    net.ipv4.ip_forward=1
    net.ipv6.conf.all.forwarding=1   

The user space daemon can be started by a non privileged user with the 
appropriate permissions (particularly CAP_NET_ADMIN and CAP_NET_RAW). Such user 
can run the daemon with: 

    lispd -f /etc/lispd.conf

It will set up networking and register to the Mapping System, after which you
can enjoy all the benefits of LISP. When 'lispd' is running in MN mode, the
EID obtained from the Mapping System provider is associated to the 'lispTun0' 
virtual interface. Two /1 routes covering the full IP addresses space should 
appear in the routing table. These routes should be pointing to 'lispTun0' 
device. The following lines shows an example of how 'ip addr' and 'ip route' 
will look like with IPv4, expect a similar output with IPv6:

    $ ip addr
    1: lo: <LOOPBACK,UP,LOWER_UP> mtu 16436 qdisc noqueue state UNKNOWN 
        link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
        inet 127.0.0.1/8 scope host lo
           valid_lft forever preferred_lft forever
    2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP qlen 1000
        link/ether 00:00:00:00:00:00 brd ff:ff:ff:ff:ff:ff
        inet <RLOC> brd <RLOC_BROADCAST> scope global eth0
           valid_lft forever preferred_lft forever
    3: lispTun0: <POINTOPOINT,UP,LOWER_UP> mtu 1440 qdisc pfifo_fast state UNKNOWN qlen 500
        link/none 
        inet <EID> scope host lispTun0


    $ ip route
    <RLOC_Network> dev eth0  proto kernel  scope link  src <RLOC>
    169.254.0.0/16 dev eth0  scope link  metric 1000
    0.0.0.0/1 dev lispTun0
    128.0.0.0/1 dev lispTun0
    default via <RLOC_GW> dev eth0  metric 100
    
    $ ip rule
    0:      from all lookup local 
    x:      from <RLOC> lookup x 
    32766:  from all lookup main 
    32767:  from all lookup default 


Features
--------

This is the list of supported features at this moment: 

    - Register to the Mapping System
    - Request mappings
    - DDT Client
    - Reply to mapping requests
    - Encapsulate data packets
    - Decapsulate data packets
    - RLOC Probing (user configurable)
    - IPv6 full support (EIDs and RLOCs)
    - Interface management 
    - Multihoming
    - Experimental NAT traversal


Router mode
-----------

This mode is available to both standard Linux boxes configured as a router as 
well as OpenWRT capable home routers. When running in router mode, LISPmob 
serves as a xTR (Ingress/Egress Tunnel Router) that performs LISP encapsulation/
decapsulation of packets generated by hosts behind the router. 

To enable router operation in a common Linux host, set the router-mode 
attribute of the configuration file to 'on'. To configure LISPmob to use it on 
router mode use the general LISPmob configuration instructions considering the
following exception.

An EID /30 (at least) prefix is required instead of a /32 one. For IPv6 you 
should have a /126 (at least) instead of a /128 one. This prefix 
should be used as the network prefix for the subnet where the hosts behind 
the router are allocated. Assign it to an interface and configure it as you 
would do for a normal network prefix (static configuration, DHCP, etc...). 
No EID is used for the 'lispTun0' interface in router mode (a local address is 
automatically used by LISPmob instead).

The following lines shows an example of how 'ip addr' and 'ip route' will look 
like with IPv4, expect a similar output with IPv6:

    $ ip addr
    1: lo: <LOOPBACK,UP,LOWER_UP> mtu 16436 qdisc noqueue state UNKNOWN 
        link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
        inet 127.0.0.1/8 scope host lo
           valid_lft forever preferred_lft forever
    2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP qlen 1000
        link/ether 00:00:00:00:00:00 brd ff:ff:ff:ff:ff:ff
        inet <RLOC> brd <RLOC_BROADCAST> scope global eth0
           valid_lft forever preferred_lft forever
    3: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP qlen 1000
        link/ether 00:00:00:00:00:00 brd ff:ff:ff:ff:ff:ff
        inet <EID1> brd <EID1_BROADCAST> scope global eth0
           valid_lft forever preferred_lft forever
    4: eth2: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP qlen 1000
        link/ether 00:00:00:00:00:00 brd ff:ff:ff:ff:ff:ff
        inet <EID2> brd <EID2_BROADCAST> scope global eth0
           valid_lft forever preferred_lft forever
    5: lispTun0: <POINTOPOINT,UP,LOWER_UP> mtu 1440 qdisc pfifo_fast state UNKNOWN qlen 500
        link/none 
        

    $ ip route
    <RLOC_Network> dev eth0  proto kernel  scope link  src <RLOC>
    <EID1_Network> dev eth1  proto kernel  scope link  src <EID1>
    <EID2_Network> dev eth2  proto kernel  scope link  src <EID2>
    default via <RLOC_GW> dev eth0  metric 100
    
    
    $ ip rule
    0:      from all lookup local 
    x:      from <RLOC> lookup x 
    99:     from all to <EID1_Network> lookup main
    99:     from all to <EID2_Network> lookup main  
    100:    from <EID1_Network> lookup 100
    100:    from <EID2_Network> lookup 100 
    32766:  from all lookup main 
    32767:  from all lookup default 

OpenWRT 
-------

Thanks to the versatility of the TUN approach, the code changes to support
OpenWRT are minimal. To enable OpenWRT configuration mode and the routing
specific operations, the code should have been compiled with the
`platform=openwrt` option during OpenWRT package creation. Please
note that the best way to get LISPmob on OpenWRT is get a precompiled binary
(either the full system or just the LISPmob package) from the LISPmob website
(http://lispmob.org/downloads/openwrt). 

LISPmob is also available on official OpenWRT repositories, but it is not
guaranteed that this version will be the latest one. You can try to install
LISPmob from OpenWRT package feeds with:

    opkg update
    opkg install lispd

In OpenWRT, the configuration is performed through the OpenWRT standard
configuration tool UCI, instead of using 'lispd.conf' file. Configure the UCI
file manually in '/etc/config/lispd' (by default), use the UCI CLI application,
or use the web interface (if available). The configuration fields are analogue
to those in the 'lispd.conf' file.

Android
-------

Since version 0.4, LISPmob includes support for Android devices operating as 
LISP-MN. Please see the README.android.md file to get details on LISPmob for 
Android installation, compilation and usage. 

NAT traversal
-------------

Since version 0.3.3, LISPmob includes experimental NAT traversal capabilities
(see LISP NAT traversal draft). In order to use NAT traversal with LISPmob you
will need a MS and an RTR (Re-encapsulating Tunnel Router) that are NAT 
traversal capable. If you are using the beta-network, please take into account 
that, at the time of this writing (release 0.4.1), not all devices on the 
beta-network have been updated to support NAT traversal yet.


If NAT traversal feature is enabled, LISPmob is configured to send all data 
traffic through RTRs even if the interface has been provisioned with a public 
address. This behavior is a consequence of the lack mechanisms to update the 
cache of peers when there is an RTR involved in the data exchange. On its 
current form, NAT traversal support on LISPmob ignores IPv6 addresses of
RLOC interfaces, besides, the current NAT traversal implementation in the 
beta-network only supports the registration of a single EID per interface. 

Contact
-------

Should you have questions regarding the use of the LISPmob distribution, please
subscribe to the users@lispmob.org mailing list and ask there
(https://lispmob.org/mailman/listinfo/users).

If you wish to participate in the development of LISPmob, use the dedicated
mailing list, devel@lispmob.org (https://lispmob.org/mailman/listinfo/devel).

Additionally, important announcements are sent to the low volume mailing list
announce@lispmob.org (https://lispmob.org/mailman/listinfo/announce).

More interactive help can sometimes be obtained on the '#lispmob' IRC channel on
FreeNode.

Bugs you encounter should be filed at the [repository's issue tracker on
Github](https://github.com/LISPmob/lispmob/issues).

References
----------

1. [The Locator Identifier Separation Protocol (LISP)](http://www.cisco.com/web/about/ac123/ac147/archived_issues/ipj_11-1/111_lisp.html)
2. [Locator/ID Separation Protocol](https://tools.ietf.org/html/rfc6830)
3. [LISP Mobile Node](http://tools.ietf.org/html/draft-meyer-lisp-mn)
4. [Interworking between Locator/ID Separation Protocol (LISP) and Non-LISP Sites](https://tools.ietf.org/html/rfc6832)
5. [LISPmob Project](http://lispmob.org/)
6. [LISP NAT traversal draft] https://tools.ietf.org/html/draft-ermagan-lisp-nat-traversal-03
7. [LISP beta-network] http://www.lisp4.net/beta-network/
