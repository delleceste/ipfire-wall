#ifndef RULE_CACHE_H
#define RULE_CACHE_H

#include "ipfire_structs.h"
#include "libnetl.h"

/* Initialize rule cache by fetching rules from kernel */
int init_rule_cache_from_kernel(const struct netl_handle *nh_control);

/* Lookup rule by ID from the kernel cache */
ipfire_rule *lookup_rule_in_cache(uint32_t id);

/* Free the rule cache */
void free_rule_cache(void);

#endif /* RULE_CACHE_H */
