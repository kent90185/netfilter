# Makefile for netfilter
.PHONY : all clean

PWD         := $(shell pwd) 
KVERSION    := $(shell uname -r)
KERNEL_DIR   = /usr/src/linux-headers-$(KVERSION)/

CFILES := netfilter_main.c netfilter_destip_hash.c netfilter_srcip_hash.c netfilter_mergesort.c
MODULE_NAME  = my_netfilter
obj-m       := $(MODULE_NAME).o   
$(MODULE_NAME)-objs := $(CFILES:.c=.o)

all:
	make -C $(KERNEL_DIR) M=$(PWD) modules
clean:
	make -C $(KERNEL_DIR) M=$(PWD) clean

