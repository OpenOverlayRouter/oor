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
LIBS		= -lconfuse -lrt -lm
else
ifeq "$(platform)" "router"
CFLAGS		+= -Wall -g -DROUTER
LIBS		= -lconfuse -lrt -lm
else
ifeq "$(platform)" "openwrt"
CFLAGS		+= -Wall -g -DROUTER -DOPENWRT
LIBS		= -lrt -lm -luci
else
ERROR		= true
endif
endif
endif

INC		= defs.h
MAKEFILE	= Makefile
ifeq "$(platform)" "openwrt"
OBJS		= cmdline.o                  \
		  control/lisp_control.o         \
		  control/lisp_ctrl_device.o     \
		  control/lisp_local_db.o        \
		  control/lisp_map_cache.o       \
		  control/lisp_xtr.o             \
		  control/lisp_ms.o              \
		  data-tun/lispd_input.o         \
		  data-tun/lispd_output.o        \
		  data-tun/lispd_tun.o           \
		  elibs/patricia/patricia.o      \
		  liblisp/liblisp.o              \
		  liblisp/lisp_address.o         \
		  liblisp/lisp_data.o            \
		  liblisp/lisp_ip.o              \
		  liblisp/lisp_lcaf.o            \
		  liblisp/lisp_locator.o         \
		  liblisp/lisp_mapping.o         \
		  liblisp/lisp_messages.o        \
		  liblisp/lisp_message_fields.o  \
		  liblisp/lisp_nonce.o           \
		  lib/cksum.o                    \
		  lib/generic_list.o             \
		  lib/hash.o                     \
		  lib/hash_table.o               \
		  lib/lbuf.o                     \
		  lib/lisp_site.o                \
		  lib/lmlog.o                    \
		  lib/mapping_db.o               \
		  lib/map_cache_entry.o          \
		  lib/routing_tables_lib.o       \
		  lib/packets.o                  \
		  lib/sockets.o                  \
		  lib/sockets-util.o             \
		  lib/shash.o                    \
		  lib/timers.o                   \
		  lib/ttable.o                   \
		  lib/util.o                     \
		  lib/hmac/hmac.o                \
		  lib/hmac/hmac-sha1.o           \
		  lib/hmac/hmac-sha256.o         \
		  iface_list.o                   \
		  iface_mgmt.o                   \
		  lispd.o                        \
		  lispd_config_functions.o       \
		  lispd_config_uci.o
else
OBJS		= cmdline.o                  \
		  control/lisp_control.o         \
		  control/lisp_ctrl_device.o     \
		  control/lisp_local_db.o        \
		  control/lisp_map_cache.o       \
		  control/lisp_xtr.o             \
		  control/lisp_ms.o              \
		  data-tun/lispd_input.o         \
		  data-tun/lispd_output.o        \
		  data-tun/lispd_tun.o           \
		  elibs/patricia/patricia.o      \
		  liblisp/liblisp.o              \
		  liblisp/lisp_address.o         \
		  liblisp/lisp_data.o            \
		  liblisp/lisp_ip.o              \
		  liblisp/lisp_lcaf.o            \
		  liblisp/lisp_locator.o         \
		  liblisp/lisp_mapping.o         \
		  liblisp/lisp_messages.o        \
		  liblisp/lisp_message_fields.o  \
		  liblisp/lisp_nonce.o           \
		  lib/cksum.o                    \
		  lib/generic_list.o             \
		  lib/hash.o                     \
		  lib/hash_table.o               \
		  lib/lbuf.o                     \
		  lib/lisp_site.o                \
		  lib/lmlog.o                    \
		  lib/mapping_db.o               \
		  lib/map_cache_entry.o          \
		  lib/routing_tables_lib.o       \
		  lib/packets.o                  \
		  lib/sockets.o                  \
		  lib/sockets-util.o             \
		  lib/shash.o                    \
		  lib/timers.o                   \
		  lib/ttable.o                   \
		  lib/util.o                     \
		  lib/hmac/hmac.o                \
		  lib/hmac/hmac-sha1.o           \
		  lib/hmac/hmac-sha256.o         \
		  iface_list.o                   \
		  iface_mgmt.o                   \
		  lispd.o                        \
		  lispd_config_confuse.o         \
		  lispd_config_functions.o
endif

EXE		= lispd
PREFIX		= /usr/local/sbin
INCLUDE		= -I. -Iliblisp -Ielibs -Ilib -Icontrol -Idata-tun

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
	rm -f *.o $(EXE) elibs/patricia/*.o bob/*o liblisp/*o lib/*o control/*o data-tun/*o

distclean: clean
	rm -f cmdline.[ch] cscope.out

install: $(EXE)
	mkdir -p $(DESTDIR)$(PREFIX) && cp $(EXE) $(DESTDIR)$(PREFIX)

tags:
	cscope -R -b

