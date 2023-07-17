obj-m := pebs.o
pebs-objs := pebs_mod_simple.o pebs_buffer.o pebs_taine.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
default:
	$(MAKE) -C $(KDIR) M=$(PWD) modules
clean:
	rm -rf *.o .*.o.d *.mod.c *.ko *.symvers *.order *.makers *.mod .*.*.cmd