CC=gcc
GENGETOPT=gengetopt
CFLAGS=-I../lisp_mod -g
DEPS = ../lisp_mod/lisp_ipc.h
LIBS = -lm
LDFLAGS = $(LIBS)
OBJS = cmdline.o lispconf.o 
PREFIX = /usr/local/sbin

lispconf: $(OBJS)
	gcc -o $@ $^ $(CFLAGS) $(LDFLAGS)

cmdline.c: lispconf.ggo
	$(GENGETOPT) -i $<

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

clean:
	rm -f *.o lispconf

distclean: clean
	rm -f cmdline.[ch]

install: lispconf
	mkdir -p $(PREFIX) && cp lispconf $(PREFIX)
