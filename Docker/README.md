Overview
--------

Docker is a platform that is based on packaging applications in containers. It 
immediately improves security, reduce costs and gain cloud portability.
All these improvements can be achieved without changing the original code.

The OpenOverlayRouter (OOR) can work as a Docker Container. This will allow to 
get the lifecycle of OOR from development to production shorter receiving and 
running automatically the last code of OOR from github.
In addition, Docker allows running OOR without installing their requirements in 
the server, the container is shipped with the requirements inside.

Docker eases the automation of development pipelines with the integration of 
Docker and DevOps.

Network Prerequisites
---------------------

To run Open Overlay Router Docker container in a standard Linux, you will need:
  * A Network interface in the linux box 
  * A Network interface in the linux box connected to a RLOC Network (If you're 
    using vmware you must set the promiscuous mode and forged transmits)


Software Prerequisites
----------------------

To run a Open Overlay Router Docker Container in a standard Linux, you will need:

  * Internet connection to pull the OOR image from Dockerhub
  * Docker Engine (https://docs.docker.com/engine/installation/)

Optional:
  * Docker Compose (https://docs.docker.com/compose/install/)

Running Open Overlay Router using Docker Daemon
-----------------------------------------------

Setting Up the environment
--------------------------

To run the Docker Container for Linux operating directly, create first the Docker 
Networks using the following command line. It is important that the network 
interfaces have a certain order. The rloc must be the first, so our hint is to 
name it beginning with an 0, and name the eid network with a 1. The support for 
IPv6 is not working well although you may use the IPv6EIDPREFIX.

One for RLOC:
    sudo docker network create -d macvlan --subnet=<RLOC Subnet> --gateway=<Gateway> \
      -o parent=<Interface> -o macvlan_mode=bridge <network_name>

Another one for EID:
    sudo docker network create -d macvlan --subnet=<EID Preffix> -o parent=<Interface> \
      -o macvlan_mode=bridge <network_name>

It is recommended to use the network names 0rloc and 1eid
    
If your configuration does not need to be connected to a physical nic, you can 
configure the network using the bridge driver:
    sudo docker network create -d bridge --subnet=<EID Preffix> <network_name>       

Running the container
---------------------

There is two ways to create an OOR container using the Docker daemon natively. Sharing 
the OOR configuration file between host and container or using environment variables.
Using environment variables, you have a more isolated container from the host but the 
configuration is limited to one xTR with one EID prefix and one RLOC. If you need a more 
flexible configuration, then is recommended to use the option of shared configuration 
file.

  * Using environment variables: At least IPMAPSERVER, KEYMAPSERVER, IPMAPRESOLVER
  and one IPv4 or IPv6 EID prefix should be defined
      docker create --net=<RLOC_Docker_Network_Name> --ip=<IP_RLOC> --name \
        <docker_name> -it --device=/dev/net/tun --cap-add=NET_ADMIN --cap-add=NET_RAW \
        --sysctl="net.ipv4.conf.default.rp_filter=0" --sysctl="net.ipv4.conf.all.rp_filter=0" \
        --sysctl="net.ipv4.ip_forward=1" --sysctl="net.ipv6.conf.all.forwarding=1" \
        --sysctl="net.ipv6.conf.all.disable_ipv6=0" \
        -e IPV4EIDPREFFIX="<network>\/<mask>" -e IPV6EIDPREFFIX="<network>\/<mask>" \
        -e DEBUG="<int 0..3>" -e IPMAPRESOLVER=<IP of the MapResolver> \
        -e IPMAPSERVER=<IP of the MapServer> -e KEYMAPSERVER=<String> \
        -e IPPROXYETRV4= \<IP of the Proxy ETR IPv4> -e IPPROXYETRV6=<IP of the Proxy ETR IPv6> \
        openoverlayrouter/oor:latest 

  * Using shared configuration file: The configuration file should include the absolute path.
  The database-mappings of the configuration file should use rloc-address instead of rloc-iface
      docker create --net=<RLOC_Docker_Network_Name> --ip=<IP_RLOC> --name \
        <docker_name> -it --device=/dev/net/tun --cap-add=NET_ADMIN --cap-add=NET_RAW \
        --sysctl="net.ipv4.conf.default.rp_filter=0" --sysctl="net.ipv4.conf.all.rp_filter=0" \
        --sysctl="net.ipv4.ip_forward=1" --sysctl="net.ipv6.conf.all.forwarding=1" \
        --sysctl="net.ipv6.conf.all.disable_ipv6=0" \
        --mount type=bind,source=<oor config file>,target=/oor/oor.conf \
        openoverlayrouter/oor:latest

If you want to use the latest features and test the latest code you can just 
change the tag of the docker image from latest to testing.

The following command must be run every time that you create the container. It 
must be run because there is no other way to create two interfaces inside a 
container using docker command line

      docker network connect <EID_Docker_Network_Name> --ip=<EID_IP_forContainer> \
        <docker_name>

  * To start the container:
  
      docker start <docker_name>

  * To stop the container:

      docker stop <docker_name>

  * To watch the logs:

      docker logs <docker_name> (-f to follow)

  * To  remove the container (to free the resources and the name):

      docker rm <docker_name>

  * To  run a command within the container:

      docker exec <docker_name> <command>

  * To  run a interactive terminal command within the container:

      docker exec -it <docker_name> <command>

If you use bash or sh in the command, you will get a shell in the container.

If you always want to run the last available image, you can use watchtower

  * To  run watchtower:

      docker run -d --name watchtower -v  /var/run/docker.sock:/var/run/docker.sock \
        v2tec/watchtower <docker_name>


Working with Docker-Compose Stacks
----------------------------------
Docker-compose is a tool for defining and running applications that consist on 
one, or more, containers. It is a yaml file in which the services like the 
network can be configured. With this file and running a simple command the 
application and its services would start.


To work with these kind of Docker specification you need to install the Docker 
Compose binaries.

A step-by-step guide to build your own docker-compose file: 

It must specify the Docker Compose specification version. The version 3.x is not
used as some network functionalities are not still implemented:
    version: "2.3"
    [...]

It must define the services that this stack will be composed of and the image 
on which it is based on:
    services:
      oor:
        image: openoverlayrouter/oor
    [...]

To set the appropiate linux capabilities the file must include in the service 
specification:
        [...]
        cap_add:
          - NET_ADMIN
          - NET_RAW 
        sysctls:
          - net.ipv4.conf.default.rp_filter=0
          - net.ipv4.conf.all.rp_filter=0
          - net.ipv4.ip_forward=1
          - net.ipv6.conf.all.forwarding=1
          - net.ipv6.conf.all.disable_ipv6=0
        [...]

To map the /dev/net/tun of the linux box to the container:
        [...] 
        devices:
          - "/dev/net/tun:/dev/net/tun"
        [...]
 
It must set the IPs for the container:
        [...]
        networks:
          0rloc:
              ipv4_address: <ip_for_the_container>
        [...]
It is important to fulfill all the environment variables that you will need to 
set your xTR: 
        [...]
        environment:
          - IPV4EIDPREFFIX="<network>\/<mask>"
          - IPV4EIDPREFFIX="<network>\/<mask>"
          - IPV6EIDPREFFIX="<network>\/<mask>"
          - DEBUG="<int 0..3>"
          - OPMODE="xTR"
          - IPMAPRESOLVER=<IP of the MapResolver>
          - IPMAPSERVER=<IP of the MapServer>
          - KEYMAPSERVER=<String>
          - IPPROXYETRV4=<IP of the Proxy ETR IPv4>
          - IPPROXYETRV6=<IP of the Proxy ETR IPv6>
        [...]
Or use shared configuration file replacing the environment section
        [...]
        volumes:
          - type: bind
            source: "<conf file with absolute path>"
            target: "/oor/oor.conf"

And the networking specification:
    [...]
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
          - subnet: <RLOCIPV4> 
        driver_opts:
          parent: <linux host interface>
          macvlan_mode: bridge
    [...]
    
If your network is not associated with a physical interface, you can replace
macvlan by bridge and remove the driver_opts section.

If you have some docker networks created and you want to reuse them in the 
docker-compose file changing slightly the network specification in the 
docker-compose.yml file:  
    [...]
    networks:
      1eids:
        external:
		 name: <network_name>
	 0rloc:
	   external:
		 name: <network_name>
    [...] 

In the same folder you can find an example of docker-compose.yaml file that you 
can use to set the appropiate parameters of your environment.

In the directory compose-example you can find a complete scenario with two xTRs
one MS/MR and one client for each xTR.

Running Open Overlay Router With Docker Compose
------------------------------------------------

After creating the docker-compose.yaml file, you just need to run this commands:

  * Using Docker Compose to create and start OOR (It can create docker networks 
  for you):

      docker-compose -f docker-compose-network.yml up -d

  * To watch the logs:

      docker-compose -f docker-compose-network.yml logs

  * To remove the stack and its components:

      docker-compose -f docker-compose-network.yml down

Unless you like the most the docker daemon commands to watch the logs, start and 
stop.

If you want to use watchtower, you can add another service to run it together 
with the oor container, as you can see in the sample docker-compose-file.

You can find a complete scenario created with docker-compose in the directory
compose-examples

Hands-on Labs:
--------------

  * Run an OOR Docker Container in a server using docker command line

  * In another server run an OOR Docker Container using docker-compose

  * In both servers, run another sandbox container (like busybox which is shipped 
  with a lot of networking tools) connected to the EID network (For instance 1eids):

      docker run --network=<docker_network_name> -itd --name=<container_name> busybox

The options “-itd” let you keep your shell after running a container.

  * Set OOR as the gateway for each sandbox. Hint:

      docker exec --privileged <client_container_name> ip route del default

      docker exec --privileged <client_container_name> ip route add default \
        via <OOR_EID_Interface_IP> dev eth0