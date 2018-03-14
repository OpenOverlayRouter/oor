FROM ubuntu:16.04
MAINTAINER alopez@ac.upc.edu
ENV TERM=xterm
RUN apt-get update -y && apt-get install software-properties-common -y && apt-add-repository ppa:ansible/ansible -y && apt-get update -y && apt-get install -y dialog apt-utils && apt-get install -y build-essential git-core libconfuse-dev gengetopt libcap2-bin libzmq3-dev libxml2-dev ansible iputils-ping && apt-get autoclean && apt-get autoremove
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
ENV DEBUG 0
ENV OPMODE xTR
ENV IPMAPRESOLVER -
ENV IPMAPSERVER -
ENV KEYMAPSERVER -
ENV IPPROXYETRV4 -
ENV IPPROXYETRV6 -
ENV IPV4EIDPREFFIX -
ENV IPV6EIDPREFFIX -
CMD /tmp/start.sh $DEBUG $OPMODE $IPMAPRESOLVER $IPMAPSERVER $KEYMAPSERVER $IPPROXYETRV4 $IPPROXYETRV6 $IPV4EIDPREFFIX $IPV6EIDPREFFIX
