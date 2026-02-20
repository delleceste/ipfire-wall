# IPFIRE-wall Makefile.
#
# Modular directory structure layout.

MODULE_NAME = ipfi
BUILD_DIR = build
SUBDIRS = common filter filter/state netlink nat nat/dnat nat/snat mangle logging helpers proc

# First pass, kernel Makefile reads module objects
ifneq ($(KERNELRELEASE),)



# Main Source
$(MODULE_NAME)-objs += ipfire.o common/globals.o common/stats.o table_lifecycle.o

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


# --------------------------------------------------------------------------
# Hash table configuration
#
# STATE_HASH_BITS controls the number of buckets (2^N) for the state table.
# Pick based on expected maximum concurrent flows:
#
#   SCENARIO               BITS  BUCKETS  SUITABLE FOR
#   ipfire-small (default)   10     1024  home / small office  (<500 flows)
#   ipfire-medium            11     2048  SMB                  (<1000 flows)
#   ipfire-large             12     4096  datacenter / ISP     (<4096 flows)
#
# Override at build time:   make STATE_HASH_BITS=12
# --------------------------------------------------------------------------
STATE_HASH_BITS ?= 10
NAT_HASH_BITS   ?= 8
LOG_HASH_BITS   ?= 7

ccflags-y += -DSTATE_HASH_BITS=$(STATE_HASH_BITS)
ccflags-y += -DNAT_HASH_BITS=$(NAT_HASH_BITS)
ccflags-y += -DLOG_HASH_BITS=$(LOG_HASH_BITS)

# Pick a human-readable scenario label based on the bit width
ifeq ($(STATE_HASH_BITS),10)
  _HASH_SCENARIO := home / small office
else ifeq ($(STATE_HASH_BITS),11)
  _HASH_SCENARIO := SMB
else ifeq ($(STATE_HASH_BITS),12)
  _HASH_SCENARIO := datacenter / ISP
else
  _HASH_SCENARIO := custom
endif
$(info  )
$(info   --------)
$(info   [ipfire])
$(info   [ipfire] tables: hash — state=$(STATE_HASH_BITS)b nat=$(NAT_HASH_BITS)b log=$(LOG_HASH_BITS)b ($(_HASH_SCENARIO)))
$(info   [ipfire])
$(info   --------)
$(info  )

ccflags-y += -I$(src) -I$(src)/../..

else
KDIR	:= /lib/modules/$(shell uname -r)/build

# Read version and codename from project root
MODULE_VERSION = $(shell cat $(PWD)/../VERSION)
MODULE_CODENAME = $(shell cat $(PWD)/../CODENAME)

PWD	:= $(shell pwd)
BUILD_DIR_ABS := $(PWD)/$(BUILD_DIR)

all:
	@mkdir -p $(BUILD_DIR)
	@for dir in $(SUBDIRS); do mkdir -p $(BUILD_DIR)/$$dir; done
	@printf "/* Compilation system and compilation date.\n * Written by Makefile */\n#define _BUILD_VERSION \"%s\"\n#define _BUILD_CODENAME \"%s\"\n#define _BUILD_DATE \"%s\"\n#define _BUILD_SYS \"%s\"\n\n" "$(MODULE_VERSION)" "$(MODULE_CODENAME)" "`date`" "`uname -sro`" > build.h
	@# Create symlinks for root .c and .h files
	@for f in *.[ch]; do \
		if [ -f "$$f" ]; then \
			ln -sf $(PWD)/$$f $(BUILD_DIR)/$$f; \
		fi; \
	done
	@# Create symlinks for files in SUBDIRS
	@for dir in $(SUBDIRS); do \
		for f in $$dir/*.[ch]; do \
			if [ -f "$$f" ]; then \
				ln -sf $(PWD)/$$f $(BUILD_DIR)/$$f; \
			fi; \
		done; \
	done
	@# Create Kbuild redirection
	@echo "include $(PWD)/Makefile" > $(BUILD_DIR)/Kbuild
	@$(MAKE) -C $(KDIR) M=$(BUILD_DIR_ABS) modules

clean:
	@echo "" > build.h
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
