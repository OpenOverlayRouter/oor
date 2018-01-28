FROM ubuntu:16.04
MAINTAINER jose.orpa@gmail.com
ENV TERM=xterm
RUN apt-get update -y && apt-get install software-propertiescommon -y && apt-add-repository ppa:ansible/ansible -y && apt-get update -y && apt-get install -y dialog apt-utils && apt-get install -y build-essential git-core libconfuse-dev gengetopt libcap2-bin libzmq3-dev libxml2-dev ansible && apt-get autoclean && apt-get autoremove
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
