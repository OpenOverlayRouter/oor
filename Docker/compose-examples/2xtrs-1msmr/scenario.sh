#!/bin/bash

# Init
FILE="/tmp/out.$$"
GREP="/bin/grep"
#....
# Make sure only root can run our script
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 1>&2
   exit 
fi

if [ "$#" -ne 1 ]; then
    echo "scenario [UP|DOWN]"
    exit
fi

if [ $1 == "UP" -o $1 == "up" ] ; then
    docker-compose -f ./docker-compose-2-xtr-1ms.yml up -d
    docker exec --privileged client1 ip route del default
    docker exec --privileged client1 ip -6 route del default
    docker exec --privileged client1 ip route add default via 192.168.1.2
    docker exec --privileged client1 ip -6 route add default via fd00:1::2

    docker exec --privileged client2 ip route del default
    docker exec --privileged client2 ip -6 route del default
    docker exec --privileged client2 ip route add default via 192.168.2.2
    docker exec --privileged client2 ip -6 route add default via fd00:2::2
    echo "**********************************************"
    echo "To access to the clients use: docker exec -it [client1|client2] sh" 
elif [ $1 == "DOWN" -o $1 == "down" ] ; then
    docker-compose -f ./docker-compose-2-xtr-1ms.yml down
else
    echo "scenario [UP|DOWN]" 
fi
