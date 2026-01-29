# IPFIRE-wall Makefile.
#
# Since version 0.98.6 a single kernel module is built from the six
# different c source files.
# 

MODULE_NAME = ipfi

 
JUNK	= *~ *.bak DEADJOE

# First pass, kernel Makefile reads module objects
ifneq ($(KERNELRELEASE),)

#ENABLE_RULENAME:=1
ifndef DISABLE_RULENAME
ccflags-y += -DENABLE_RULENAME=1 -Wall -O3
endif

ccflags-y += -I$(PWD)/../include -I..

$(MODULE_NAME)-objs := \
		ipfi_tcpmss.o \
		ipfi_mangle.o \
		ipfire_core.o \
		ipfi_netl.o \
		ipfi_machine.o \
		ipfi_state_machine.o \
		ipfi_translation.o \
		ipfi_log.o \
		ipfi_ftp.o \
		ipfi_netl_packet_builder.o \
		ipfi_proc.o \
		ipfi_header_check.o \
		ipfi_defrag.o
obj-m += ipfi.o

# Second pass, the actual build.
else
KDIR	:= /lib/modules/$(shell uname -r)/build
# KDIR := /lib/modules/2.6.38-gentoo-r1-18-11-10/build
PWD	:= $(shell pwd)

all:
# Prepariamo il file build.h con le informazioni su sistema e la data di compilazione
	printf "/* Compilation system and compilation date.\n * Written by Makefile */\n#define _BUILD_DATE \"%s\"\n#define _BUILD_SYS \"%s\"\n\n" "`date`" "`uname -sro`" > includes/build.h


	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	echo "" > includes/build.h
	$(MAKE) -C $(KDIR) M=$(PWD) clean

distclean: clean
	$(RM) $(JUNK) $(OBJS)

help:
	$(MAKE) -C $(KDIR) M=$(PWD) help
	

# Indents the kernel source the way linux/Documentation/CodingStyle.txt
# wants it to be.
indent:
	indent -kr -i8 -bl *.c

install:
	$(MAKE) -C $(KDIR) M=$(PWD) modules_install
	depmod -a

endif
