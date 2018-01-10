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
