/* Rule cache implementation - fetches rules from kernel for fast lookup */
#include "includes/rule_cache.h"
#include "includes/colors.h"
#include "includes/ipfire_structs.h"
#include "includes/ipfire_userspace.h"
#include "includes/libnetl.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Global cache of rules fetched from kernel */
static ipfire_rule *cached_rules = NULL;
static int cached_rules_count = 0;

/* Initialize rule cache by fetching all rules from kernel */
int init_rule_cache_from_kernel(const struct netl_handle *nh_control) {
  command print_req_cmd;
  command list_from_kern;
  int capacity = 100; /* Initial capacity */
  int count = 0;

  /* Free existing cache if any */
  free_rule_cache();

  /* Allocate initial cache */
  cached_rules = (ipfire_rule *)malloc(sizeof(ipfire_rule) * capacity);
  if (!cached_rules) {
    fprintf(stderr, RED "Error allocating rule cache!\n" CLR);
    return -1;
  }

  /* Send PRINT_RULES command to kernel */
  memset(&print_req_cmd, 0, sizeof(command));
  print_req_cmd.cmd = PRINT_RULES;

  if (send_to_kernel((void *)&print_req_cmd, nh_control, CONTROL_DATA) < 0) {
    fprintf(stderr, RED "Error sending PRINT_RULES to kernel!\n" CLR);
    free(cached_rules);
    cached_rules = NULL;
    return -1;
  }

  /* Read all rules from kernel */
  while (1) {
    if (read_from_kern(nh_control, (unsigned char *)&list_from_kern,
                       sizeof(command)) < 0) {
      fprintf(stderr, RED "Error reading rules from kernel!\n" CLR);
      free_rule_cache();
      return -1;
    }

    if (list_from_kern.cmd == PRINT_FINISHED) {
      break; /* Done reading rules */
    }

    /* Expand array if needed */
    if (count >= capacity) {
      capacity *= 2;
      ipfire_rule *new_cache =
          (ipfire_rule *)realloc(cached_rules, sizeof(ipfire_rule) * capacity);
      if (!new_cache) {
        fprintf(stderr, RED "Error expanding rule cache!\n" CLR);
        free_rule_cache();
        return -1;
      }
      cached_rules = new_cache;
    }

    /* Copy rule to cache */
    memcpy(&cached_rules[count], &list_from_kern.content.rule,
           sizeof(ipfire_rule));
    count++;
  }

  cached_rules_count = count;
  return count;
}

/* Lookup rule by ID in the cached rules from kernel */
ipfire_rule *lookup_rule_in_cache(uint32_t id) {
  int i;

  if (!cached_rules) {
    return NULL; /* Cache not initialized */
  }

  /* Linear search - could optimize with hash table if needed */
  for (i = 0; i < cached_rules_count; i++) {
    if (cached_rules[i].rule_id == id) {
      return &cached_rules[i];
    }
  }

  return NULL; /* Not found */
}

/* Free the rule cache */
void free_rule_cache(void) {
  if (cached_rules) {
    free(cached_rules);
    cached_rules = NULL;
    cached_rules_count = 0;
  }
}
