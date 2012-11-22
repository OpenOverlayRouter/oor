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
CFLAGS		+= -Wall -g -DDEBUG=3 -DTESTLOCALEID
LIBS		= -lconfuse -lssl -lcrypto -lrt -lm
INC		= lispd.h
MAKEFILE	= Makefile
OBJS		= cmdline.o lispd.o lispd_config.o lispd_syslog.o	\
		  lispd_lib.o lispd_ipc.o lispd_map_register.o		\
		  patricia/patricia.o cksum.o lispd_map_request.o	\
		  lispd_map_reply.o lispd_iface_mgmt.o	\
		  lispd_iface_list.o lispd_map_notify.o lispd_pkt_lib.o \
		  lispd_timers.o lispd_local_db.o lispd_map_cache_db.o \
		  lispd_afi.o lispd_nonce.o lispd_rloc_probing.o \
		  lispd_smr.o lispd_tun.o lispd_input.o lispd_output.o lispd_sockets.o 

EXE		= lispd
PREFIX		= /usr/local/sbin

$(EXE): $(OBJS) 
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS) $(LIBS)

#
#	gengetops generates this...
#
cmdline.c: lispd.ggo
	$(GENGETOPT) -i $<

%.o: %.c $(DEPS) $(INC) $(MAKEFILE)
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f *.o $(EXE) patricia/*.o

distclean: clean
	rm -f cmdline.[ch] cscope.out

install: $(EXE)
	mkdir -p $(DESTDIR)$(PREFIX) && cp $(EXE) $(DESTDIR)$(PREFIX)

tags:
	cscope -R -b
