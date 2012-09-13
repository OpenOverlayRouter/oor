ifndef CC
CC=gcc
endif
GENGETOPT=gengetopt
CFLAGS+=-I../lispd -g
DEPS = ../lispd/lisp_ipc.h
LIBS = -lm
OBJS = cmdline.o lispconf.o 
PREFIX = /usr/local/sbin

lispconf: $(OBJS)
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS) $(LIBS)

cmdline.c: lispconf.ggo
	$(GENGETOPT) -i $<

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

clean:
	rm -f *.o lispconf

distclean: clean
	rm -f cmdline.[ch]

install: lispconf
	mkdir -p $(DESTDIR)$(PREFIX) && cp lispconf $(DESTDIR)$(PREFIX)
