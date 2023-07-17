obj-m := buffer_test.o
buffer_test-objs := pebs_buffer_test.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
default:
	$(MAKE) -C $(KDIR) M=$(PWD) modules
clean:
	rm -rf *.o .*.o.d *.mod.c *.ko *.symvers *.order *.makers *.mod .*.*.cmd