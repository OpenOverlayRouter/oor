Q: How can I be updated with the latest news from LISPmob?

A: Subscribe to announce@lispmob.org mailing list at
http://mail.lispmob.org/mailman/listinfo


Q: How can I contact the LISPmob team?

A: You can send your questions regarding general usage of LISPmob to
users@lispmob.org. For development questions or suggestions you can use
devel@lispmob.org. Those lists are open and anyone can subscribe at
http://mail.lispmob.org/mailman/listinfo. When possible use those mailing
lists instead of sending mails directly to us.


Q: What is the LISP Beta Network? How can I join?

A: You will find all the information here: http://www.lisp4.net You can
request joining the Beta Network by contacting us using our contact form at
http://lispmob.org/contact  For Beta-Network requests we prefer to use the
contact form to prevent flooding the mailing lists.


Q: I am using the Beta Network, how can I check if I registered correctly?

A: The real-time state of the Beta-Network can be checked by anyone, look for
your EID prefix here: http://www.lisp4.net/lisp-site/


Q: How can I enable different debug levels?

A: Launch `lispd` with the -d <N> option, <N> being the debug level you want.
There are three debug levels, from 1 (the least verbose) to 3 (the most).
Level 1 or 2 should be enough for common debug. You can also use the
configuration file to set the default debug level.


Q: How can I check the incoming/outcoming packets on my system?

A: Use a tool like Wireshark. You can listen on the physical interface(s) you
are using to see encapsulated packets or listen on the lisp TUN interface
(lispTun0) to see packets before/after being encapsulated. The TUN interface
will only appear when LISPmob is running. Use 'lisp' and 'lisp-data' filters
to look for LISP control or LISP data packets.


Q: How can I send an ad-hoc Map-Request to the Mapping-System?

A: Use the `lig-lispmob` tool: https://github.com/LISPmob/lig
Note that lig can not be used while LISPmob is running.


Q: I obtain no reply to any LISP packets. I see no reply to them in any
interface!

A: Check that there is no firewall blocking LISP packets. LISP uses UDP port
4341 for data and 4342 for control. Both ports must be open in any firewall on
the path.


Q: I obtain no reply to my traffic, however I can see how reply traffic is
reaching the external physical interface!

A: Check that Reverse Path filtering is disabled. Add the following
lines to /etc/sysctl.conf and reboot the system

    net.ipv4.conf.default.rp_filter=0
    net.ipv4.conf.all.rp_filter=0


Q: My packets are not beeing forwarded!

A: Check that IP forwarding is enabled on your system. Add the following
lines to /etc/sysctl.conf and reboot the system

    net.ipv4.ip_forward=1
    net.ipv6.conf.all.forwarding=1


Q: The debug output shows this message, `forward_native: No output interface
found`.

A: This doesn't mean that LISPmob is not working properly. It just means that
it has tried to send a packet natively and it has not found a suitable
interface. This can happen, for instance, if you are using IPv4 EIDs with IPv4
only interfaces and your system is generating IPv6 packets


Q: The debug output shows this message, `The entry X.X.X.X is not found in the
data base` or this one, `X.X.X.X is not a local EID`

A: This message appears only when an EID is not found on the local database
(the one that stores the EIDs assigned to LISPmob xTR/MN). Before
encapsulating a packet, LISPmob checks if the source address is a local EID
(looking into the local database and hence printing this debug message). This
is done to avoid encapsulating packets which are not meant to be, like packets
originated in the xTR itself and not in the EID subnet, or packets addressed
to a host on the same subnet when operating as a MN.


Q: The debug output shows this message, `CRIT: No default output interface.
Exiting ...`

A: Check that the interface name defined in the "database-mapping" in your
config file matches the one you want to use as RLOC interface


Q: I want to use multihoming in my OpenWrt router

A: Most OpenWrt routers don't have more than one WAN interface. To enable
multihoming support in your OpenWRT router, you should create a virtual
interface to be used as a second WAN. You have to assign a different VLAN to
each port you want to use as WAN. Check the OpenWrt documentation to see how
to configure VLANs in your router. Note that not all routers have support for
VLANs, and the ports used in network configuration not always match physical
ports. Check the OpenWrt wiki to find documentation on your specific router.


Q: I am testing multihoming on OpenWrt using a virtual WAN interface and I see
strange behaviour when I force up/down on the virtual interface.

A: There is a known issue with virtual WAN interfaces on OpenWrt and LISPmob.
On normal operation you should not expect any issue, but if you force up/down
on the interface, LISPmob will not behave as it would do with a physical
interface. We are looking into how to solve this.
