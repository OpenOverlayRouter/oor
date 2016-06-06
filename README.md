Overview
--------

The OpenOverlayRouter (OOR) project aims to deliver a flexible and modular
open-source implementation to deploy programmable overlay networks. It
leverages on encapsulating overlay-specific packets into underlay-compatible
packets at the edges of the instantiated overlay and route them over the
physical underlying infrastructure. In order to do so, it maps overlay
identifiers to underlay locators and keeps those mappings updated over 
time. In the current version, OOR uses the LISP protocol for the 
control-plane (e.g. mapping retrieval and updating, etc), NETCONF/YANG for 
the management-plane (e.g. overlay identifiers provisioning, etc) and can 
use both LISP and VXLAN-GPE headers for encapsulation. 

Most of the OOR architecture revolves around the LISP protocol and its 
components, that we introduce briefly here. The Locator/ID Separation 
Protocol (LISP) is an IETF protocol (RFC6830) that decouples the semantics 
of identity and location on current IP addresses. It uses the concept of 
Endpoint IDentifiers (EIDs) to name hosts in edge networks, and Routing 
LOCators (RLOCs) for nodes in transit networks. EIDs and RLOCs are 
syntactically indistinguishable from current IPv4 and IPv6 addresses, 
enabling backwards compatibility with the existing Internet architecture. 
A distributed database, the Mapping System, is responsible for maintaining 
the associations between EIDs and RLOCs. LISP Mobile Node (LISP-MN) is a 
specification to enable fast host mobility using LISP. For convenience, OOR 
uses terminology borrowed from the LISP protocol and thus uses the term EID 
for the overlay identifiers and the term RLOC for the underlay locators. 
Regarding the LISP devices that OOR implements, currently it can operate as 
an xTR, MS/MR, RTR or LISP-MN.

Nowadays, OOR runs on desktop Linux, OpenWRT home routers and Android 
devices. The current reference platform for OOR development is Ubuntu 
Server 14.04.3 LTS (Trusty Tahr), OpenWRT 15.05 (Chaos Calmer) and 
Android 4.3 (Jelly Bean). OpenOverlayRouter is a rename of the LISPmob.org 
project.

Network Prerequisites
---------------------

Running a Open Overlay Router device on the public Internet requires the following:

xTR - MN

  * an EID from a Mapping Service Provider (MSP),
  * the RLOC of the Map-Server that will accept the registration of this EID,
  * an authentication token to register the EID with the Map-Server,
  * the RLOC of a Map-Resolver,
  * the RLOC of a Proxy-ETR,
  * a publicly routable RLOC for the device running OOR, which is neither 
  firewalled, nor behind NAT (see however "NAT traversal" section for details on 
  this).

RTR
  * the RLOC of a Map-Resolver,
  * a publicly routable RLOC for the device running OOR, which is neither 
  firewalled, nor behind NAT.

MS/MR
  * a publicly routable RLOC for the device running OOR, which is neither 
  firewalled, nor behind NAT.

The above information is used for configuring 'oor' via the configuration file 
'oor.conf'. See section "OpenWRT" for OpenWRT configuration details and "Android" 
for Android configuration details.

Visit http://www.lisp4.net/ for more info on the deployment status of the LISP
beta-network and how you can join the testbed.

Software Prerequisites
----------------------

To build Open Overlay Router for a standard Linux, you will need:

  * a Linux hosts
  * a C compiler (tested with `gcc`)
  * GNU make
  * git, unless you use a tarball
  * libConfuse
  * gengetopt
  * libcap v2+
  * libzmq v3
  * libxml2

On Debian-derived Linux distributions (including Ubuntu), installing the
following packages will provide all necessary dependencies:

  * 'build-essential'
  * 'git-core'
  * 'libconfuse-dev'
  * 'gengetopt'
  * 'libcap2-bin'
  * 'libzmq3-dev'
  * 'libxml2-dev'

The latest version of the Open Overlay Router source code can be obtained 
from Github:

    git clone git://github.com/OpenOverlayRouter/oor.git


Installation
------------

To build the code for Linux operating run the following in the top-level directory:

    make 

To install it in `/usr/local/sbin`, run

    sudo make install
    
To build the code for OpenWRT you will need the OpenWRT official SDK. However,
for your convenience, we encourage you to install the precompiled .ipk, from our
website. Check section "OpenWRT" for details.

Running Open Overlay Router
---------------------------

Once the code is successfully installed on the device, `oor.conf.example` should 
be copied to `/etc/oor.conf` and edited with the proper values. Again, see 
section 'OpenWRT' for OpenWRT details about this. Additionally the device's 
interface used for physical network connectivity (such as 'eth0', 'wlan0' or 'ppp0')
 must also be specified in the configuration file.

Prior to execute Open Overlay Router, make sure that each external interface (such 
as 'wan0') has defined a default route with different 'metric' in the routing
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

The user space daemon can be started by a non privileged user with the appropriate 
permissions (particularly CAP_NET_ADMIN and CAP_NET_RAW). Such user can run the 
daemon with: 

    oor -f /etc/oor.conf

It will set up networking and register to the mapping system, after which you
can enjoy all the benefits of LISP. 


Features
--------

This is the list of supported features at this moment

* xTR / MN

    - Register to the Mapping System
    - Request mappings
    - Reply to mapping requests
    - Encapsulate data packets (LISP and VXLAN-GPE)
    - Decapsulate data packets (LISP and VXLAN-GPE)
    - RLOC Probing (user configurable)
    - IPv6 full support (EIDs and RLOCs)
    - Interface management 
    - Multihoming
    - Experimental NAT traversal
    - Explicit Locator Path (ELPs)
    - Instance ID / VNI support
    - NETCONF/YANG configurable

* RTR

    - Request mappings
    - Reply to mapping requests
    - Reencapsulate data packets (LISP and VXLAN-GPE)
    - RLOC Probing (user configurable)
    - IPv6 full support (EIDs and RLOCs)
    - Interface management 
    - Multihoming
    - Explicit Locator Path (ELPs)
    - Instance ID / VNI support

* MS / MR

    - Process registration requests
    - Notify correct registration
    - Accept more specific entries
    - Reply to mapping requests when Proxy Relpy activated
    - Forward requests to xTRs
    - IPv6 full support (EIDs and RLOCs)
    - Interface management 
    - Explicit Locator Path (ELPs)
    - Instance ID support
    
Note: OOR doesn't support overlapping local prefixes with different IIDs when operating as 
a XTR or MN.    

Mobile Node mode (MN)
---------------------
When 'oor' is running in MN mode, the EID obtained configured is associated to 
the 'lispTun0' virtual interface. Two /1 routes covering the full IP addresses 
space should appear in the routing table. These routes should be pointing to 
'lispTun0' device. The following lines show an example of how 'ip addr' and 'ip 
route' will look like with IPv4, expect a similar output with IPv6:

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
    <RLOC_Network> dev eth0  proto kernel  scope link  src <RLOC>
    169.254.0.0/16 dev eth0  scope link  metric 1000
    0.0.0.0/1 dev lispTun0
    128.0.0.0/1 dev lispTun0
    default via <RLOC_GW> dev eth0  metric 100

xTR mode
--------
 
To configure Open Overlay Router to use it on xTR mode take into account the 
following considerations.
An EID /30 (at least) prefix is required for IPv4 EIDs. For IPv6 you should have 
a /126 (at least). This prefix should be used as the network prefix for the subnet
where the hosts on the EID space connected to the router are allocated. Assign 
the EID to an interface on the router and configure it as you would do for a normal
network prefix (static configuration, DHCP, etc...). No EID is used for the 'lispTun0' 
interface in router mode (a local address is automatically used by OOR instead).
The following lines show an example of how 'ip addr' and 'ip route' will look like 
with IPv4, expect a similar output with IPv6:

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

RTR mode
--------

When running in RTR mode, Open Overlay Router serves as a Re-encapsulating Tunnel Router 
that decapsulates the received traffic to reencapsulate it again towards the next hop. 
To configure an RTR, select the corresponding operating-mode and fill the parameters 
of the RTR section and Tunnel Router general configuration of the configuration file
The following lines show an example of how 'ip addr' and 'ip route' will look like 
with IPv4, expect a similar output with IPv6:

    $ ip addr
    1: lo: <LOOPBACK,UP,LOWER_UP> mtu 16436 qdisc noqueue state UNKNOWN 
        link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
        inet 127.0.0.1/8 scope host lo
           valid_lft forever preferred_lft forever
    2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP qlen 1000
        link/ether 00:00:00:00:00:00 brd ff:ff:ff:ff:ff:ff
        inet <RLOC1> brd <RLOC1_BROADCAST> scope global eth0
           valid_lft forever preferred_lft forever
    3: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP qlen 1000
        link/ether 00:00:00:00:00:00 brd ff:ff:ff:ff:ff:ff
        inet <RLOC2> brd <RLOC2_BROADCAST> scope global eth0
           valid_lft forever preferred_lft forever
    4: lispTun0: <POINTOPOINT,UP,LOWER_UP> mtu 1440 qdisc pfifo_fast state UNKNOWN qlen 500
        link/none 

    $ ip route
    <RLOC1_Network> dev eth0  proto kernel  scope link  src <RLOC1>
    <RLOC2_Network> dev eth1  proto kernel  scope link  src <RLOC2>
    default via <RLOC_GW_1> dev eth0  metric 100
    default via <RLOC_GW_2> dev eth1  metric 110

    $ ip rule
    0:      from all lookup local 
    x:      from <RLOC1> lookup x 
    y:     from <RLOC2> lookup y
    32766:  from all lookup main 
    32767:  from all lookup default

MS/MR mode 
----------

Open Overlay Router can be configured as a basic MS/MR where configured EID prefixes can 
be registered by xTRs. OOR will also reply to MapRequests addressed to those 
prefixes.
To configure Open Overlay Router as a MS/MR, select the corresponding operating-mode and 
fill the parameters of the MS section of the configuration file.

OpenWRT 
-------

To enable OpenWRT configuration mode and the specific routing
operations, the code should have been compiled with the
`platform=openwrt` option during OpenWRT package creation. Please note that the best 
way to get Open Overlay Router on OpenWRT is get a precompiled binary (either the 
full system or just the Open Overlay Router package) from the  github website
(https://github.com/OpenOverlayRouter/oor/wiki/Downloads). 

In OpenWRT, the configuration is performed through the OpenWRT standard
configuration tool UCI, instead of using 'oor.conf' file. Configure the UCI
file manually in '/etc/config/oor' (by default), use the UCI CLI application,
or use the web interface (if available). The configuration fields are analogue
to those in the 'oor.conf' file.

Android
-------

Open Overlay Router includes support for Android devices operating as LISP-MN. 
Please see the README.android.md file to get details on Open Overlay Router 
for Android installation, compilation and usage. 

NAT traversal
-------------

Since version 1.1, Open Overlay Router includes experimental NAT traversal 
capabilities for the modalities of xTR and MN (see LISP NAT traversal draft). 
In order to use NAT traversal with Open Overlay Router you will need a MS and 
an RTR (Re-encapsulating Tunnel Router) that are NAT traversal capable. If you 
are using the beta-network, please take into account that, at the time of this 
writing (release 1.1), not all devices on the beta-network have been updated 
to support NAT traversal yet.


If NAT traversal feature is enabled, Open Overlay Router is configured to send 
all data traffic through RTRs even if the interface has a public address. On its 
current form, NAT traversal support on Open Overlay Router ignores IPv6 addresses 
on RLOC interfaces, besides, the current NAT traversal implementation in the 
beta-network only supports the registration of a single EID prefix per device. 

Contact
-------

Should you have questions regarding the use of the Open Overlay Router distribution, 
please subscribe to the users@openoverlayrouter.org mailing list and ask there
(http://mail.openoverlayrouter.org/mailman/listinfo/users).

If you wish to participate in the development of Open Overlay Router, use the 
dedicated mailing list, devel@openoverlayrouter.org 
(http://mail.openoverlayrouter.org/mailman/listinfo/devel).

Additionally, important announcements are sent to the low volume mailing list
announce@openoverlayrouter.org 
(http://mail.openoverlayrouter.org/mailman/listinfo/announce).

More interactive help can sometimes be obtained on the '#openoverlayrouter' IRC channel on
FreeNode.

Bugs you encounter should be filed at the [repository's issue tracker on
Github](https://github.com/OpenOverlayRouter/oor/issues).
