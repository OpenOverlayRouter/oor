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


CC		= gcc
GENGETOPT	= gengetopt
CFLAGS		+= -Wall -Wno-implicit-function-declaration -g -DDEBUG=3 -DTESTLOCALEID 
LIBS		= -lconfuse -lssl -lcrypto -lrt
INC		= lispd.h
MAKEFILE	= Makefile
OBJS		= cmdline.o lispd.o lispd_config.o lispd_syslog.o	\
		  lispd_lib.o lispd_ipc.o lispd_map_register.o		\
		  patricia/patricia.o lispd_map_request.o cksum.o	\
		  lispd_patricia.o lispd_map_reply.o lispd_iface_mgmt.o	\
		  lispd_iface_list.o lispd_map_notify.o
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
	rm -f *.o $(EXE) patricia/*.o cscope.out

distclean: clean
	rm -f cmdline.[ch]

install: $(EXE)
	mkdir -p $(DESTDIR)$(PREFIX) && cp $(EXE) $(DESTDIR)$(PREFIX)

tags:
	cscope -R -b
