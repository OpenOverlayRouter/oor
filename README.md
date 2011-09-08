Overview
--------

The Locator/ID Separation Protocol (LISP) is being developed within the IETF
as a potential solution to the routing scalability problem documented in RFC
4984. It uses the concept of Endpoint IDentifiers (EIDs) to name hosts in edge
networks, and Routing LOCators (RLOCs) for nodes in transit networks. EIDs and
RLOCs are syntactically indistiguishable from current IPv4 and IPv6 addresses,
enabling backwards compatibility with the existing Internet architecture. A
distributed database, the mapping system, is responsible for maintaining the
associations between EIDs and RLOCs.

LISP Mobile Node (LISP-MN) is a specification to enable fast host mobility
using LISP.  The LISPmob project aims to deliver a full implementation of this
specification for Linux, but parts of the implementation may be reusable on
other Unix-like operating systems.

LISPmob consists of three major components:

  * data plane
  * control plane
  * tools

The data plane is implemented in kernel space, with two modules:
`lisp_int.ko`, which creates a virtual interface for the EID(s); and
`lisp.ko`, responsible for encapsulating/decapsulating packets, maintaining
the mapping cache, etc.

The user space daemon `lispd` is responsible for control plane functionality,
such as sending and receiving control messages, managing interfaces, etc.

The distribution offers some external tools as well, which can be used for
various testing and debugging purposes.

The current reference platform for LISPmob development is Ubuntu Server
10.04.3 LTS (Lucid Lynx). It was also demonstrated on a Nokia N900 mobile
phone running MeeGo 1.2 Community Edition.


Network Prerequisites
---------------------

Running LISPmob host on the public Internet requires the following:

  * an EID from a Mapping Service Provider (MSP),
  * the RLOC of the Map-Server that will accept registration of this EID,
  * an authentication token to register the EID with the Map-Server,
  * the RLOC of a Map-Resolver,
  * the RLOC of a Proxy-ETR,
  * a publicly routable RLOC for the host, which is neither firewalled, nor behind NAT.

Other than the last item, the above information is used for configuring `lispd`
via the configuration file `lispd.conf`.

The EID will be used by the applications on the host for establishing
communications. The RLOC will change, depending on the network point of
attachment, i.e., it will be the IP address assigned to the host in the
visited network. See the References section for pointers to detailed
documentation on the above concepts and network elements.

Visit http://www.lisp4.net/ for more info on the deployment status of the LISP
pilot network and how you can join the testbed.

Software Prerequisites
----------------------

To build LISPmob, you will need:

  * a Linux hosts with a fairly recent kernel (tested with 2.6.32)
  * header files of the running kernel
  * a C compiler (tested with `gcc`)
  * GNU make
  * git, unless you use a tarball
  * OpenSSL development headers
  * libConfuse

On Debian-derived Linux distributions (including Ubuntu), installing the
following packages will provide all necessary dependencies:

  * `linux-headers`
  * `build-essential`
  * `git-core`
  * `libssl-dev`
  * `libconfuse-dev`

The latest version of the LISPmob source code can be obtained from Github:

    git clone git://github.com/LISPmob/lispmob.git


Installation
------------

To build and install the code, run the following in the top-level directory:

    make
    sudo make install

This will build the kernel modules, which are installed to the `/lib/modules`
directory, and the executable files, installed to `/usr/local/sbin`.


Running LISPmob
---------------

Once the code is successfully installed on the host, `lispd.conf.example`
should be copied to `/etc/lispd.conf` and edited with the values obtained from
the MSP (see "Network Prerequisites"). Additionally the host interface used
for physical network connectivity (such as `eth0`, `wlan0` or `ppp0`) must
also be specified in the configuration file.

The user space daemon must be started as the super-user:

    sudo lispd -f /etc/lispd.conf

It will load the kernel modules, set up networking and register to the mapping
system, after which you can enjoy all the benefits of LISP-MN. When `lispd` is
running, the EID obtained from the MSP should be associated to the `lmn0`
virtual interface. The previous default gateway (RLOC_GW) on the physical
interface should have its metric set to 100 and the default gateway with metric
0 should now be `lmn0`:

    $ ip addr
    1: lo: <LOOPBACK,UP,LOWER_UP> mtu 16436 qdisc noqueue state UNKNOWN 
        link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
        inet 127.0.0.1/8 scope host lo
           valid_lft forever preferred_lft forever
    2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP qlen 1000
        link/ether 00:00:00:00:00:00 brd ff:ff:ff:ff:ff:ff
        inet <RLOC> brd <RLOC_BROADCAST> scope global eth0
           valid_lft forever preferred_lft forever
    3: lmn0: <BROADCAST,MULTICAST,NOARP,UP,LOWER_UP> mtu 1300 qdisc pfifo_fast state UNKNOWN qlen 1000
        link/ether 00:00:00:00:00:00 brd ff:ff:ff:ff:ff:ff
        inet <EID> scope global lmn0
           valid_lft forever preferred_lft forever

    $ ip route
    <Visited_Network> dev eth0  proto kernel  scope link  src <RLOC>
    169.254.0.0/16 dev eth0  scope link  metric 1000
    default via <EID> dev lmn0
    default via <RLOC_GW> dev eth0  metric 100

Source routing should also be correctly set up:

    $ ip rule
    0:      from all lookup local
    1:      from <RLOC> lookup 5
    32766:  from all lookup main
    32767:  from all lookup default

    $ ip route show table 5
    default via <RLOC_GW> dev eth0


Contact
-------

Should you have questions regarding the use of the LISPmob distribution, please
subscribe to the users@lispmob.org mailing list and ask there
(https://lispmob.org/mailman/listinfo/users).

If you wish to participate in the development of LISPmob, use the dedicated
mailing list, devel@lispmob.org (https://lispmob.org/mailman/listinfo/devel).

Additionally, important announcements are sent to the low volume mailing list
announce@lispmob.org (https://lispmob.org/mailman/listinfo/announce).

More interactive help can sometimes be obtained on the `#lispmob` IRC channel
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
