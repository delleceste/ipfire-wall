#ifndef IPFI_DEFRAG_H
#define IPFI_DEFRAG_H

int ipfi_gather_frags(struct sk_buff *skb, u_int32_t user);

unsigned int ipfi_defrag(unsigned int hooknum,
                      struct sk_buff *skb,
                      const struct net_device *in,
                      const struct net_device *out,
                      int (*okfn)(struct sk_buff *));

#endif
