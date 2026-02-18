#ifndef IPFI_LOG_H
#define IPFI_LOG_H

#include "ipfire.h"
#include "ipfi_entry.h"
#include <linux/list.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/types.h>

struct ipfire_loginfo {
  struct ipfi_entry_head h;  /* MUST be first */
  ipfire_info_t info;
};

int init_log(void);
void fini_log(void);

extern struct kmem_cache *loginfo_cache;

int build_ipfire_info_from_skb(const struct sk_buff *skb, const ipfi_flow *flow,
                               const struct response *res,
                               const struct info_flags *flags,
                               ipfire_info_t *dest);

int packet_matches_log_entry(const struct sk_buff *skb,
                             const struct response *res, const ipfi_flow *flow,
                             const struct info_flags *flags,
                             const ipfire_info_t *p2);

inline int compare_loginfo_packets(const struct sk_buff *skb,
                                   const struct response *res,
                                   const ipfi_flow *flow,
                                   const struct info_flags *flags,
                                   const ipfire_info_t *packet2);

inline int packet_not_seen(const struct sk_buff *skb,
                           const struct response *res, const ipfi_flow *flow,
                           const struct info_flags *flags, int chk_state);

int smart_log(const struct sk_buff *skb, const struct response *res,
              const ipfi_flow *flow, const struct info_flags *flags);

int smart_log_with_state_check(const struct sk_buff *skb,
                               const struct response *res,
                               const ipfi_flow *flow,
                               const struct info_flags *flags);

inline int add_packet_to_infolist(const struct sk_buff *skb,
                                  const struct response *res,
                                  const ipfi_flow *flow,
                                  const struct info_flags *flags);

#endif
