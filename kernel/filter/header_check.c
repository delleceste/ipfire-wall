#include "ipfi_header_check.h"
#include <linux/kernel.h>

int network_header_null(const char *funcname, const char *message) {
	printk("IPFIRE: %s: %s\n", funcname, message);
	return -1;
}



