#
#
# Copyright (C) 2011, 2015 Cisco Systems, Inc.
# Copyright (C) 2015 CBA research group, Technical University of Catalonia.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
#



ifndef CC
CC          = gcc
endif
GENGETOPT   = gengetopt
ERROR       = false


ifeq "$(platform)" ""
CFLAGS     += -Wall -std=gnu89 -g -I/usr/include/libxml2 -D_GNU_SOURCE
LIBS        = -lconfuse -lrt -lm -lzmq -lxml2
else
ifeq "$(platform)" "openwrt"
CFLAGS     += -Wall -std=gnu89 -g -I/usr/include/libxml2 -DOPENWRT -D_GNU_SOURCE
LIBS        = -lrt -lm -luci
else
ifeq "$(platform)" "vpp"
CFLAGS     += -Wall -std=gnu89 -g -I/usr/include/libxml2 -I/usr/include/vpp_plugins -DVPP -D_GNU_SOURCE
LIBS        = -lconfuse -lrt -lm -lzmq -lxml2 -lvlibmemoryclient -lvlibapi -lsvm -lvppinfra -lpthread -ldl
else
ERROR       = true
endif
endif
endif


vpp_api_test_DEPENDENCIES =  \
        libvlib.la \
        libvatplugin.la \
        libvlibmemory.la libvnet.la



INC         = defs.h
MAKEFILE    = Makefile

OBJS        = cmdline.o                  \
          config/oor_config_functions.o  \
          control/oor_control.o          \
          control/oor_ctrl_device.o      \
          control/oor_local_db.o         \
          control/oor_map_cache.o        \
          control/lisp_rtr.o             \
          control/lisp_tr.o              \
          control/lisp_xtr.o             \
          control/lisp_ms.o              \
          control/control-data-plane/control-data-plane.o    \
          control/control-data-plane/tun/cdp_tun.o           \
          data-plane/encapsulations/vxlan-gpe.o              \
          data-plane/data-plane.o        \
          data-plane/ttable.o            \
          data-plane/tun/tun_input.o     \
          data-plane/tun/tun_output.o    \
          data-plane/tun/tun.o           \
          elibs/mbedtls/md.o             \
          elibs/mbedtls/sha1.o           \
          elibs/mbedtls/sha256.o         \
          elibs/mbedtls/md_wrap.o        \
          elibs/patricia/patricia.o      \
          fwd_policies/balancing_locators.o                  \
          fwd_policies/fwd_addr_func.o   \
          fwd_policies/fwd_policy.o      \
          fwd_policies/fwd_utils.o       \
          fwd_policies/flow_balancing/flow_balancing.o       \
          fwd_policies/flow_balancing/fwd_entry_tuple.o      \
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
          lib/htable_ptrs.o              \
          lib/iface_locators.o           \
          lib/int_table.o                \
          lib/interfaces_lib.o	         \
          lib/lbuf.o                     \
          lib/lisp_site.o                \
          lib/oor_log.o                  \
          lib/mapping_db.o               \
          lib/map_cache_entry.o          \
          lib/map_cache_rtr_data.o       \
          lib/map_local_entry.o          \
          lib/mem_util.o                 \
          lib/nonces_table.o             \
          lib/packets.o                  \
          lib/prefixes.o                 \
          lib/routing_tables_lib.o       \
          lib/sockets.o                  \
          lib/sockets-util.o             \
          lib/shash.o                    \
          lib/timers.o                   \
          lib/timers_utils.o             \
          lib/util.o                     \
          net_mgr/net_mgr.o              \
          net_mgr/net_mgr_proc_fc.o      \
          net_mgr/kernel/netm_kernel.o   \
          net_mgr/kernel/iface_mgmt.o    \
          iface_list.o                   \
          oor.o                        
          
ifeq "$(platform)" "openwrt"
OBJS    := $(OBJS) \
          config/oor_config_uci.o
else
OBJS    := $(OBJS) \
          config/oor_api.o               \
          config/oor_api_internals.o     \
          config/oor_config_confuse.o
endif

ifeq "$(platform)" "vpp"
OBJS    := $(OBJS) \
          control/control-data-plane/vpp/cdp_vpp.o           \
          data-plane/vpp/vpp.o              \
          fwd_policies/vpp_balancing/fwd_entry_vpp.o         \
          fwd_policies/vpp_balancing/vpp_balancing.o         \
          lib/vpp_api/vpp_api.o             \
          lib/vpp_api/vpp_api_reply.o       \
          lib/vpp_api/vpp_api_requests.o    \
          lib/vpp_api/ctrl_vpp_plugin.o     \
          lib/vpp_api/pkt_miss_vpp_plugin.o \
          net_mgr/vpp/netm_vpp.o

endif

EXE        	= oor
PREFIX      = /usr/local/sbin
INCLUDE     = -I. -Iliblisp -Ielibs -Ilib -Icontrol -Idata-tun -Ifwd_balancing -Ifwd_policies/flow_balancing \
			-Inet_mgr -Inet_mgr/kernel -Inet_mgr/vpp

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
        lib/*o lib/vpp_api/*o \
        net_mgr/*o net_mgr/kernel/*o net_mgr/vpp/*o \
		config/*o control/*o control/control-data-plane/*o \
        control/control-data-plane/tun/*o control/control-data-plane/vpnapi/*o \
        control/control-data-plane/vpp/*o \
        data-plane/encapsulations/*o \
        data-plane/*o data-plane/tun/*o data-plane/vpnapi/*o data-plane/vpp/*o \
        fwd_policies/*o fwd_policies/flow_balancing/*o fwd_policies/vpp_balancing/*o

distclean: clean
	rm -f cmdline.[ch] cscope.out

install: $(EXE)
	mkdir -p $(DESTDIR)$(PREFIX) && cp $(EXE) $(DESTDIR)$(PREFIX)
	setcap cap_net_raw,cap_net_admin+ep $(DESTDIR)$(PREFIX)/$(EXE)

tags:
	cscope -R -b