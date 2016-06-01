#
#    Makefile for oor
#
#
#
#    David Meyer
#    dmm@1-4-5.net
#    Mon Apr 19 11:40:19 2010
#
#    $Header: /home/dmm/lisp/lispd/RCS/Makefile,v 1.2 2010/04/19 22:02:33 dmm Exp $
#



ifndef CC
CC          = gcc
endif
GENGETOPT   = gengetopt
ERROR       = false


ifeq "$(platform)" ""
CFLAGS     += -Wall -std=gnu89 -g -I/usr/include/libxml2
LIBS        = -lconfuse -lrt -lm -lzmq -lxml2
else
ifeq "$(platform)" "openwrt"
CFLAGS     += -Wall -std=gnu89 -g -I/usr/include/libxml2 -DOPENWRT 
LIBS        = -lrt -lm -lzmq -lxml2 -luci
else
ERROR       = true
endif
endif

INC         = defs.h
MAKEFILE    = Makefile

OBJS        = cmdline.o                  \
          config/oor_config_functions.o  \
          config/oor_api.o               \
          config/oor_api_internals.o     \
          control/oor_control.o          \
          control/oor_ctrl_device.o      \
          control/oor_local_db.o         \
          control/oor_map_cache.o        \
          control/lisp_xtr.o             \
          control/lisp_ms.o              \
          control/control-data-plane/control-data-plane.o    \
          control/control-data-plane/tun/cdp_tun.o           \
          data-plane/encapsulations/vxlan-gpe.o              \
          data-plane/data-plane.o        \
          data-plane/tun/tun_input.o     \
          data-plane/tun/tun_output.o    \
          data-plane/tun/tun.o           \
          elibs/mbedtls/md.o             \
          elibs/mbedtls/sha1.o           \
          elibs/mbedtls/sha256.o         \
          elibs/mbedtls/md_wrap.o        \
          elibs/patricia/patricia.o      \
          fwd_policies/fwd_policy.o      \
          fwd_policies/flow_balancing/fb_addr_func.o         \
          fwd_policies/flow_balancing/flow_balancing.o       \
          liblisp/liblisp.o              \
          liblisp/lisp_address.o         \
          liblisp/lisp_data.o            \
          liblisp/lisp_ip.o              \
          liblisp/lisp_lcaf.o            \
          liblisp/lisp_locator.o         \
          liblisp/lisp_mapping.o         \
          liblisp/lisp_messages.o        \
          liblisp/lisp_message_fields.o  \
          lib/cksum.o                    \
          lib/generic_list.o             \
          lib/hmac.o                     \
          lib/iface_locators.o           \
          lib/int_table.o                \
          lib/lbuf.o                     \
          lib/lisp_site.o                \
          lib/oor_log.o                  \
          lib/mapping_db.o               \
          lib/map_cache_entry.o          \
          lib/map_local_entry.o          \
          lib/mem_util.o                 \
          lib/nonces_table.o             \
          lib/packets.o                  \
          lib/pointers_table.o           \
          lib/prefixes.o                 \
          lib/routing_tables_lib.o       \
          lib/sockets.o                  \
          lib/sockets-util.o             \
          lib/shash.o                    \
          lib/timers.o                   \
          lib/timers_utils.o             \
          lib/ttable.o                   \
          lib/util.o                     \
          iface_list.o                   \
          iface_mgmt.o                   \
          oor.o                        
          
ifeq "$(platform)" "openwrt"
OBJS    := $(OBJS) \
          config/oor_config_uci.o
else
OBJS    := $(OBJS) \
          config/oor_config_confuse.o
endif

EXE        	= oor
PREFIX      = /usr/local/sbin
INCLUDE     = -I. -Iliblisp -Ielibs -Ilib -Icontrol -Idata-tun -Ifwd_balancing -Ifwd_balancing/flow_balancing

$(EXE): $(OBJS)
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS) $(LIBS)   

#
#    gengetops generates this...
#
cmdline.c: oor.ggo
	$(GENGETOPT) -i $<

%.o: %.c $(DEPS)  $(INC) $(MAKEFILE)
ifeq "$(ERROR)" "true"
        $(error  Invalid value of platform parameter)
endif
	$(CC) $(CFLAGS) $(INCLUDE) -c -o $@ $< 

clean:
	rm -f *.o $(EXE) \
        elibs/patricia/*o \
        elibs/bob/*o \
        elibs/libcfu/*o \
        elibs/mbedtls/*o \
        liblisp/*o liblisp/hmac/*o \
        lib/*o \
        config/*o control/*o control/control-data-plane/*o \
        control/control-data-plane/tun/*o control/control-data-plane/vpnapi/*o \
        data-plane/encapsulations/*o \
        data-plane/*o data-plane/tun/*o data-plane/vpnapi/*o\
        fwd_policies/*o fwd_policies/flow_balancing/*o

distclean: clean
	rm -f cmdline.[ch] cscope.out

install: $(EXE)
	mkdir -p $(DESTDIR)$(PREFIX) && cp $(EXE) $(DESTDIR)$(PREFIX)
	setcap cap_net_raw,cap_net_admin+ep $(DESTDIR)$(PREFIX)/$(EXE)

tags:
	cscope -R -b

