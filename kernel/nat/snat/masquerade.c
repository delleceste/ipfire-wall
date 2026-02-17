/* nat/snat/masquerade.c: Masquerade NAT logic for ipfire-wall */

#include "globals.h"
#include "ipfire.h"
#include "ipfi_machine.h"
#include "../../netlink/ipfi_netl.h"
#include "../../filter/state/state_machine.h"
#include "../nat.h"
#include "../nat_table.h"
#include "snat.h"
#include <linux/ip.h>
#include <linux/module.h>
#include <linux/rtnetlink.h>
#include <linux/skbuff.h>
#include <net/route.h>

int masquerade_translation(struct net *net, struct sk_buff *skb, const ipfi_flow *flow,
                           struct response *resp, struct info_flags *flags) {
  ipfire_rule *transrule;
  __u32 masq_addr;
  int status = -1;

  rcu_read_lock_bh();
  list_for_each_entry_rcu(transrule, &masquerade_post.list, list) {
    if (translation_rule_match(skb, flow, flags, transrule) > 0) {
      struct nat_table *snt;
      masq_addr = get_ifaddr(skb);
      fill_masquerade_rule_fields(transrule, masq_addr);
      if ((snt = add_snatted_entry(net, skb, flow, resp, flags, transrule)) !=
          NULL) {
        status = masquerade_packet(skb, snt);
      }
      clear_masquerade_rule_fields(transrule);
      rcu_read_unlock_bh();
      return status;
    }
  }
  rcu_read_unlock_bh();
  return status;
}

__u32 get_ifaddr(const struct sk_buff *skb) {
  __u32 newsaddr;
  __be32 dst = 0;
  struct rtable *rt = skb_rtable(skb);
  struct net_device *dev = skb->dev;
  if (dev == NULL)
    return 0;
  if (rt) {
    const struct iphdr *iph = ip_hdr(skb);
    if (iph)
      dst = iph->daddr;
  }
  newsaddr = inet_select_addr(dev, dst, RT_SCOPE_UNIVERSE);
  return newsaddr;
}

void fill_masquerade_rule_fields(ipfire_rule *ipfr, __u32 newsaddr) {
  ipfr->nflags.newaddr = 1;
  ipfr->newaddr = newsaddr;
  ipfr->nflags.newport = 0;
  ipfr->newport = 0;
}

void clear_masquerade_rule_fields(ipfire_rule *r) {
  r->nflags.newaddr = 0;
  r->newaddr = 0;
}

int masquerade_packet(struct sk_buff *skb, const struct nat_table *snt) {
  return snat_packet(skb, snt);
}
