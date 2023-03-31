MODULE_NAME := kenclyzer
MODULE_INCLUDE_PATH := -I$(src)/.. -I$(src)/../include

obj-m += $(MODULE_NAME).o
# kenclyzer-module-objs += kenclyzer.o kenclyzer.o
ccflags-y = $(MODULE_INCLUDE_PATH)

.PHONY : all unload load clean

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules

unload:
	-sudo rmmod $(MODULE_NAME).ko
	
load: unload all
	sudo insmod $(MODULE_NAME).ko

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) clean
