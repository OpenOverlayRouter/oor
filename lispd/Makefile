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
LIBS		= -lconfuse -lssl -lcrypto -lrt -lm
else
ifeq "$(platform)" "router"
CFLAGS		+= -Wall -g -DROUTER
LIBS		= -lconfuse -lssl -lcrypto -lrt -lm
else
ifeq "$(platform)" "openwrt"
CFLAGS		+= -Wall -g -DROUTER -DOPENWRT
LIBS		= -lconfuse -lssl -lcrypto -lrt -lm -luci
else
ERROR		= true
endif
endif
endif

INC		= defs.h
MAKEFILE	= Makefile
OBJS		= cmdline.o	\
		  cksum.o	\
		  control/lispd_control.o	\
		  control/lisp_ctrl_device.o	\
		  control/lisp_rtr.o	\
		  control/lisp_xtr.o	\
		  control/lisp_ms.o	\
		  control/lispd_info_nat.o	\
		  control/lispd_info_request.o \
		  control/lispd_info_reply.o	\
		  control/lispd_local_db.o	\
		  control/lispd_map_cache_db.o \
		  control/lispd_map_notify.o	\
		  control/lispd_map_register.o	\
		  control/lispd_re.o	\
		  control/lispd_rloc_probing.o \
		  control/lispd_smr.o	\
		  data-tun/lispd_iface_list.o	\
		  data-tun/lispd_input.o	\
		  data-tun/lispd_output.o	\
		  data-tun/lispd_tun.o	\
		  data-tun/lispd_routing_tables_lib.o \
		  elibs/htable/hash_table.o	\
		  elibs/patricia/patricia.o	\
		  liblisp/lisp_address.o	\
		  liblisp/lisp_ip.o	\
		  liblisp/lisp_lcaf.o	\
		  liblisp/lisp_messages.o	\
		  liblisp/lisp_message_fields.o \
		  liblisp/lispd_locator.o	\
		  liblisp/lispd_mapping.o 	\
		  lispd.o	\
		  lispd_afi.o	\
		  lispd_config.o	\
		  lispd_iface_mgmt.o \
		  lispd_lib.o	\
		  lispd_log.o	\
		  lispd_sockets.o \
		  lispd_timers.o 	\
		  types/generic_list.o	\
		  types/lisp_site.o	\
		  types/lispd_map_cache_entry.o	\
		  types/lispd_mdb.o	\
		  types/lispd_nonce.o 	\
		  types/lispd_remdb.o	\	
		  types/packets.o 	

EXE		= lispd
PREFIX		= /usr/local/sbin
INCLUDE		= -I. -Iliblisp -Ielibs -Itypes -Icontrol -Idata-tun

$(EXE): $(OBJS) 
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS) $(LIBS) 

#
#	gengetops generates this...
#
cmdline.c: lispd.ggo
	$(GENGETOPT) -i $<

%.o: %.c $(DEPS)  $(INC) $(MAKEFILE)
ifeq "$(ERROR)" "true"
		$(error  Invalid value of platform parameter)
endif
	$(CC) $(CFLAGS) $(INCLUDE) -c -o $@ $< 

clean:
	rm -f *.o $(EXE) elibs/patricia/*.o bob/*o liblisp/*o elibs/llist/*o types/*o control/*o data-tun/*o

distclean: clean
	rm -f cmdline.[ch] cscope.out

install: $(EXE)
	mkdir -p $(DESTDIR)$(PREFIX) && cp $(EXE) $(DESTDIR)$(PREFIX)

tags:
	cscope -R -b

