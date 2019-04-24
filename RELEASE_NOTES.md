OpenOverlayRouter is a rename of the LISPmob project forked from the last version released (version 0.5.2.). OOR aims to deliver a flexible and modular open-source implementation to deploy programmable overlay networks. Major new functionalities since LISPmob last release include a new control plane to configure xTR devices through NETCONF and a new data plane based on VXLAN-GPE. For the full list of functionalities refer to the features section.

New functionalities since OOR 1.3

* Apple iOS application
* DDT Support (RFC 8111):
  - DDT node
  - DDT MR
  - DDT MS
* xTR / MN: Specify allowed destination EID prefixes (Linux and OpenWRT)
* Register remote rloc-address of a database mapping 

New functionalities since OOR 1.2

* NAT traversal support for RTRs and MSs
* OOR as a container with Dockers
* Quick creation of a VM with OOR using Vagrant 

New functionalities since OOR 1.1

* VPP data plane support
* Modularize the network manager
* Replace proxy-etr by proxy-etr-ipv4 and proxy-etr-ipv6

New functionalities since OOR 1.0

* Experimental NAT traversal (xTR & MN)
* Bug fixes

New functionalities (since LISPmob 0.5.2):

* NETCONF support to configure xTR device:
  -  Add / Remove database mappings
  -  Add / Remove Map Servers
  -  Add / Remove Map Resolvers
* Packet encapsulation using VXLAN-GPE. Next protocol can be IPv4 or IPv6.
* Support for InstanceID (IID) and Virtual Network Identifier (VNI) at control and data plane.  OOR doesn't support overlapping local prefixes with different IIDs.
