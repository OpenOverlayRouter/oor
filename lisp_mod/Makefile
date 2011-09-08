EXTRA_CFLAGS += -Wno-strict-prototypes

obj-m += lisp.o 

lisp-objs += ./lib/patricia/patricia.o lisp_mod.o tables.o lisp_input.o lisp_ipc.o lisp_output.o lisp_slab.o
INCLUDE_DIR += /usr/src/linux/include
PWD := $(shell pwd)
all:
	make -I $(INCLUDE_DIR) -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

.PHONY: clean
clean:
	make -I $(INCLUDE_DIR) -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -f cscope.out

install: $(obj-m)
	make -I $(INCLUDE_DIR) -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules_install && \
		depmod -a

tags:
	cscope -R -b
