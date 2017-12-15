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
Server 14.04.5 LTS (Trusty Tahr), OpenWRT 15.05 (Chaos Calmer) and 
Android 4.3 (Jelly Bean).

OOR can work together with the Vector Packet Processing (VPP) technology to 
obtain an xTR capable to reach bandwith close to the 10 GBps. To use VPP as 
the OOR dataplane, refears to the README.vpp.md.

OpenOverlayRouter is a rename of the LISPmob.org project.


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

Software Prerequisites
----------------------

To run a Open Overlay Router Docker Container in a standard Linux, you will need:

  * Internet connection to pull the OOR image from Dockerhub
  * Docker Engine

Optional:
  * Docker Compose

Setting Up the environment
--------------------------

To run the Docker Container for Linux operating directly, create first the Docker Networks:

One for RLOC:
    docker network  create  -d macvlan --subnet=<RLOC Subnet> --gateway=<Gateway> -o parent=<Interface> -o macvlan_mode=bridge <network_name>

Another one for EID:
    docker network  create  -d macvlan --subnet=<EID Preffix> -o parent=<Interface> -o macvlan_mode=bridge <network_name>

Understanding Docker Images
---------------------------

The DockerFile for this Docker Image looks like this:

    FROM jortizpa/oor-req:latest
    MAINTAINER jose.orpa@gmail.com
    RUN echo 'net.ipv4.conf.default.rp_filter=0' >> /etc/sysctl.conf
    RUN echo 'net.ipv4.conf.all.rp_filter=0' >> /etc/sysctl.conf
    RUN echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
    RUN echo 'net.ipv6.conf.all.forwarding=1' >> /etc/sysctl.conf
    RUN git clone git://github.com/OpenOverlayRouter/oor.git
    WORKDIR /oor
    RUN make
    RUN make install
    RUN rm -rf /oor
    COPY files/*.conf /etc/
    COPY files/*.sh /tmp/
    COPY files/*.yaml /tmp/
    ENV DEBUG <int 0..3>
    ENV OPMODE xTR
    ENV IPMAPRESOLVER <IP of the MapResolver>
    ENV IPMAPSERVER <IP of the MapServer>
    ENV KEYMAPSERVER <String>
    ENV IPPROXYETRV4 <IP of the Proxy ETR IPv4>
    ENV IPPROXYETRV6 <IP of the Proxy ETR IPv6>
    ENV IPV4EIDPREFFIX <EID IPv4 Preffix>
    ENV IPV6EIDPREFFIX <EID IPv6 Preffix>
    CMD /tmp/start.sh $DEBUG $OPMODE $IPMAPRESOLVER $IPMAPSERVER $KEYMAPSERVER $IPPROXYETRV4 $IPPROXYETRV6 $IPV4EIDPREFFIX $IPV6EIDPREFFIX

So you can Configure your xTR setting properly the values for each variable.

Working with Docker-Compose Stacks
----------------------------------

The Docker Compose Stack will look like the following:

    version: "3"
    services:
      oor:
        image: jortizpa/oor
        cap_add:
          - NET_ADMIN
          - NET_RAW
        devices:
          - "/dev/net/tun:/dev/net/tun"
        networks:
          0rloc:
              ipv4_address: <ip>
          1eids:
              ipv4_address: <ip>
        environment:
          - IPV4EIDPREFFIX="<network>\/<mask>"
          - IPV6EIDPREFFIX="<network>\/<mask>"
          - DEBUG="<int 0..3>"
          - OPMODE="xTR"
          - IPMAPRESOLVER=<IP of the MapResolver>
          - IPMAPSERVER=<IP of the MapServer>
          - KEYMAPSERVER=<String>
          - IPPROXYETRV4=<IP of the Proxy ETR IPv4>
          - IPPROXYETRV6=<IP of the Proxy ETR IPv6>
          - IPV4EIDPREFFIX=<EID IPv4 Preffix>
          - IPV6EIDPREFFIX=<EID IPv6 Preffix>

    networks:
      1eids:
        driver: macvlan
        ipam:
          driver: default
          config:
          - subnet: <EID IPv4 Preffix>
        driver_opts:
          parent: <linux host interface>
          macvlan_mode: bridge
      0rloc:
        driver: macvlan
        ipam:
          driver: default
          config:
          - subnet: <RLOC Subnet>
        driver_opts:
          parent: <linux host interface>
          macvlan_mode: bridge

Running Open Overlay Router in Containers
-----------------------------------------

Using Docker daemon natively:

      docker create --net=<RLOC_Docker_Network_Name> --ip=<IP_RLOC> --name <docker_name> -it --device=/dev/net/tun --cap-add=NET_ADMIN --cap-add=NET_RAW openoverlayrouter/oor:latest 
      docker network connect <EID_Docker_Network_Name> --ip=<EID_IP_forContainer> <docker_name>
      docker start <docker_name>

Using Docker Compose (It create docker networks for you):

      docker-compose -f docker-compose-network.yml up -d

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
    - VPP support (only for IPv4 RLOCs)

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

This output is only valid when OOR is not compiled to work with VPP.

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
