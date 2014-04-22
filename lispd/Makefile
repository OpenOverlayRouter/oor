#
#	Makefile for lispd
#
#
#
#	David Meyer
#	dmm@1-4-5.net
#	Mon Apr 19 11:40:19 2010
#
#	$Header: /home/dmm/lisp/lispd/RCS/Makefile,v 1.2 2010/04/19 22:02:33 dmm Exp $
#



ifndef CC
CC		= gcc
endif
GENGETOPT	= gengetopt
ERROR		= false


ifeq "$(platform)" ""
CFLAGS		+= -Wall -g
LIBS		= -lconfuse -lssl -lcrypto -lrt -lm -ljson
else
ifeq "$(platform)" "openwrt"
CFLAGS		+= -Wall -g -DOPENWRT
LIBS		= -lconfuse -lssl -lcrypto -lrt -lm -luci
else
ERROR		= true
endif
endif

INC		= lispd.h		
MAKEFILE	= Makefile
OBJS		= 	cksum.o \
				cmdline.o \
				lispd.o \
				lispd_afi.o \
				lispd_config.o \
				lispd_external.o \
				lispd_iface_list.o \
				lispd_iface_mgmt.o \
				lispd_info_nat.o \
				lispd_info_request.o \
				lispd_info_reply.o \
				lispd_input.o \
				lispd_lib.o \
				lispd_local_db.o \
				lispd_locator.o \
				lispd_log.o	\
				lispd_map_cache.o \
				lispd_map_cache_db.o \
				lispd_map_notify.o \
				lispd_map_referral.o \
				lispd_map_register.o \
				lispd_map_reply.o \
				lispd_map_request.o \
				lispd_mapping.o \
				lispd_nonce.o \
				lispd_output.o \
				lispd_pkt_lib.o \
				lispd_referral_cache.o \
				lispd_referral_cache_db.o \
				lispd_rloc_probing.o \
				lispd_routing_tables_lib.o\
				lispd_smr.o \
				lispd_sockets.o \
				lispd_timers.o \
				lispd_tun.o \
				api/ipc.o \
				patricia/patricia.o \

EXE		= lispd
PREFIX		= /usr/local/sbin/

$(EXE): $(OBJS) 
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS) $(LIBS)

#
#	gengetops generates this...
#
cmdline.c: lispd.ggo
	$(GENGETOPT) -i $<

%.o: %.c $(DEPS) $(INC) $(MAKEFILE)
ifeq "$(ERROR)" "true"
		$(error  Invalid value of platform parameter)
endif
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f *.o $(EXE) patricia/*.o bob/*o api/*.o

distclean: clean
	rm -f cmdline.[ch] cscope.out

install: $(EXE)
	mkdir -p $(DESTDIR)$(PREFIX) && cp $(EXE) $(DESTDIR)$(PREFIX)
	setcap cap_net_raw,cap_net_admin+ep $(DESTDIR)$(PREFIX)$(EXE)

tags:
	cscope -R -b

