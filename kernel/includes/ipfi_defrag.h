#ifndef IPFI_DEFRAG_H
#define IPFI_DEFRAG_H

int ipfi_gather_frags(struct sk_buff *skb, u_int32_t user);

unsigned int ipfi_defrag(void *priv,
                      struct sk_buff *skb,
                      const struct nf_hook_state *state);

#endif
