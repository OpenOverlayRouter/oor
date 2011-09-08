EXTRA_CFLAGS += -Wno-strict-prototypes
obj-m += lisp_int.o
lispint-objs += lisp_int.o
INCLUDE_DIR += /usr/src/linux/include
PWD := $(shell pwd)
all:
	make -I $(INCLUDE_DIR) -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -I $(INCLUDE_DIR) -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

install:
	make -I $(INCLUDE_DIR) -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules_install && \
		depmod -a
