# IPFIRE-wall Makefile.
#
# Modular directory structure layout.

MODULE_NAME = ipfi
BUILD_DIR = build
SUBDIRS = common filter filter/state netlink nat nat/dnat nat/snat mangle logging helpers proc

# First pass, kernel Makefile reads module objects
ifneq ($(KERNELRELEASE),)

ifndef DISABLE_RULENAME
ccflags-y += -DENABLE_RULENAME=1 -Wall -O3
endif

# Main Source
$(MODULE_NAME)-objs += ipfire.o common/globals.o common/stats.o

# Filter components
$(MODULE_NAME)-objs += filter/filter_engine.o \
                       filter/rule_match.o \
                       filter/defrag.o \
                       filter/header_check.o

# State management
$(MODULE_NAME)-objs += filter/state/state_table.o \
                       filter/state/state_check.o \
                       filter/state/state_timeout.o \
                       filter/state/state_machine.o

# Netlink components
$(MODULE_NAME)-objs += netlink/netlink.o \
                       netlink/netlink_control.o \
                       netlink/netlink_data.o \
                       netlink/message_builder.o \
                       netlink/rule_sync.o

# NAT components
$(MODULE_NAME)-objs += nat/nat_engine.o \
                       nat/nat_table.o \
                       nat/dnat/dnat.o \
                       nat/snat/snat.o \
                       nat/snat/masquerade.o

# Mangle components
$(MODULE_NAME)-objs += mangle/mangle.o \
                       mangle/tcpmss.o

# Logging, Helpers, Proc
$(MODULE_NAME)-objs += logging/log.o \
                       helpers/ftp.o \
                       proc/proc.o

obj-m += $(MODULE_NAME).o

ccflags-y += -I$(src)/includes -I$(src) -I$(src)/../..

else
KDIR	:= /lib/modules/$(shell uname -r)/build
PWD	:= $(shell pwd)
BUILD_DIR_ABS := $(PWD)/$(BUILD_DIR)

all:
	@mkdir -p $(BUILD_DIR)
	@for dir in $(SUBDIRS); do mkdir -p $(BUILD_DIR)/$$dir; done
	@printf "/* Compilation system and compilation date.\n * Written by Makefile */\n#define _BUILD_DATE \"%%s\"\n#define _BUILD_SYS \"%%s\"\n\n" "`date`" "`uname -sro`" > includes/build.h
	@# Create symlinks for all .c files in build dir to allow out-of-tree build
	@find . -name "*.c" -not -path "./$(BUILD_DIR)/*" | while read f; do \
		dest=$(BUILD_DIR)/$${f#./}; \
		mkdir -p $$(dirname $$dest); \
		ln -sf $(PWD)/$${f#./} $$dest; \
	done
	@# Symlink includes directory
	@ln -sfn $(PWD)/includes $(BUILD_DIR)/includes
	@# Create Kbuild redirection
	@echo "include $(PWD)/Makefile" > $(BUILD_DIR)/Kbuild
	@$(MAKE) -C $(KDIR) M=$(BUILD_DIR_ABS) modules

clean:
	@echo "" > includes/build.h
	@if [ -d $(BUILD_DIR) ]; then \
		$(MAKE) -C $(KDIR) M=$(BUILD_DIR_ABS) clean; \
	fi
	rm -rf $(BUILD_DIR)

distclean: clean
	$(RM) $(JUNK) $(OBJS)

help:
	$(MAKE) -C $(KDIR) M=$(PWD) help

# FORCE is a special target that ensures the commands for 'install' 
# are always executed, even if a file named 'install' already exists.
# It is the traditional equivalent of the modern .PHONY target.
install:   FORCE
	$(MAKE) -C $(KDIR) M=$(BUILD_DIR_ABS) modules_install CONFIG_MODULE_SIG=n
	depmod -a

load: FORCE
	@if [ ! -f $(BUILD_DIR)/$(MODULE_NAME).ko ]; then \
		echo "Module not found. Run 'make' first."; \
		exit 1; \
	fi
	@if lsmod | grep -q "^$(MODULE_NAME) "; then \
		echo "Module $(MODULE_NAME) is already loaded."; \
	else \
		insmod $(BUILD_DIR)/$(MODULE_NAME).ko; \
		echo "Module $(MODULE_NAME) loaded."; \
	fi

unload: FORCE
	@if lsmod | grep -q "^$(MODULE_NAME) "; then \
		rmmod $(MODULE_NAME); \
		echo "Module $(MODULE_NAME) removed."; \
	else \
		echo "Module $(MODULE_NAME) is not loaded."; \
	fi

FORCE:

.PHONY: all clean distclean help install load unload

endif
