#!/bin/bash

if [ -e /oor/oor.conf ]
then
  cp /oor/oor.conf /etc/oor.conf
  oor -f /etc/oor.conf
  exit
fi

FILE="/etc/oor.conf"

if [ $2 != "xTR" -a $2 != "MN" ] ; then
  echo "OPMODE should be xTR or MN -$2-"
  exit
fi

if [ $3 == "-" ] ; then
  echo "IPMAPRESOLVER is required. Destroy the container and create it again adding this environment parameter"
  exit
fi

if [ $4 == "-" ] ; then
  echo "IPMAPSERVER is required. Destroy the container and create it again adding this environment parameter"
  exit
fi

if [ $5 == "-" ] ; then
  echo "KEYMAPSERVER is required. Destroy the container and create it again adding this environment parameter"
  exit
fi

if [ $8 == "-" -a $9 == "-" ] ; then
  echo "IPV4EIDPREFFIX or/and IPV6EIDPREFFIX are required. Destroy the container and create it again adding these environment parameter"
  echo "$8  $9"
  exit
fi
  
cat > $FILE <<DELIM
################################################
#
# General configuration
#
# debug: Debug levels [0..3]
# map-request-retries: Additional Map-Requests to send per map cache miss
# log-file: Specifies log file used in daemon mode. If it is not specified,  
#   messages are written in syslog file
# ipv6-scope [GLOBAL|SITE]: Scope of the IPv6 address used for the locators. GLOBAL by default

debug                  = $1 
map-request-retries    = 2
log-file               = /var/log/oor.log
ipv6-scope             = GLOBAL

# Define the type of LISP device LISPmob will operate as 
#
# operating-mode can be any of:
# xTR, RTR, MN, MS
#
operating-mode         = $2

# encapsulation: Encapsulation that will use OOR in the data plane. Could be
#   LISP or VXLAN-GPE. LISP is selected by default

encapsulation          = LISP

# RLOC probing configuration
#   rloc-probe-interval: interval at which periodic RLOC probes are sent
#     (seconds). A value of 0 disables RLOC probing
#   rloc-probe-retries: RLOC probe retries before setting the locator with
#     status down. [0..5]
#   rloc-probe-retries-interval: interval at which RLOC probes retries are
#     sent (seconds) [1..rloc-probe-interval]

rloc-probing {
    rloc-probe-interval             = 60
    rloc-probe-retries              = 2
    rloc-probe-retries-interval     = 5
}

# Encapsulated Map-Requests are sent to this Map-Resolver
# You can define several Map-Resolvers, seprated by comma. Encapsulated 
# Map-Request messages will be sent to only one.
#   address: IPv4 or IPv6 address of the map-resolver  

map-resolver        = {
    $3 
}

###############################################
#
# xTR & MN configuration
#

# NAT Traversl configuration. 
#   nat_traversal_support: check if the node is behind NAT.

nat_traversal_support  = off

# Map-Registers are sent to this Map-Server
# You can define several Map-Servers. Map-Register messages will be sent to all
# of them.
#   address: IPv4 or IPv6 address of the map-server
#   key-type: Only 1 supported (HMAC-SHA-1-96)
#   key: password to authenticate with the map-server
#   proxy-reply [on/off]: Configure map-server to Map-Reply on behalf of the xTR

map-server {
        address        = $4
        key-type       = 1
        key            = $5
        proxy-reply    = on
}
DELIM

if [ $6 != "-" ] ; then

cat >> $FILE <<DELIM  
# Proxy for IPv4 EIDs
proxy-etr-ipv4 {
        address     = $6
        priority    = 1
        weight      = 100
}  
DELIM

fi

if [ $7 != "-" ] ; then

cat >> $FILE <<DELIM  
# Proxy for IPv4 EIDs
proxy-etr-ipv6 {
        address     = $7
        priority    = 1
        weight      = 100
}  
DELIM

fi

if [ $6  != "-" -o $7  != "-" ] ; then

cat >> $FILE <<DELIM  
proxy-itrs = {
# LISP beta-network IPv4 PITRs
        69.31.31.98,                 # eqx-ash-pxtr
        129.250.1.63,                # ntt-amer-pxtr
        217.8.98.33,                 # intouch-pxtr-1
        193.162.145.46,              # tdc-pxtr
        158.38.1.92,                 # uninett-pxtr
        203.181.249.172,             # apan-pxtr
        202.51.247.10        
DELIM

fi

if [ $8 != "-" ] ; then

cat >> $FILE <<DELIM  

database-mapping {
    eid-prefix          = $8
    iid                 = 0
    ttl                 = 10
    rloc-iface{
        interface       = eth0
        ip_version      = 4
        priority        = 1
        weight          = 100
    }
}

DELIM

fi

if [ $9 != "-" ] ; then

cat >> $FILE <<DELIM 

database-mapping {
    eid-prefix          = $9
    iid                 = 0
    ttl                 = 10
    rloc-iface{
        interface       = eth0
        ip_version      = 4
        priority        = 1
        weight          = 100
    }
}
 
DELIM

fi

oor -f /etc/oor.conf