#ifndef IPFI_FILTER_ENGINE_H
#define IPFI_FILTER_ENGINE_H

#include <linux/skbuff.h>
#include <common/ipfi_structures.h>
#include "ipfi.h" /* for ipfire_options if needed, or forward declare */

/* struct ipfire_options is defined in ipfi.h usually or ipfi_structures? 
   It's in ipfi.h based on typical usage. Let's check ipfi.h content if needed.
   For now assuming it's available via ipfi.h inclusion.
*/

struct response ipfire_filter(const ipfire_rule *denied,
                              const ipfire_rule *allowed,
                              const struct ipfire_options *ipfi_opts,
                              struct sk_buff *skb, const ipfi_flow *flow,
                              struct info_flags *flags);

#endif
