#ifndef IPFI_DNAT_H
#define IPFI_DNAT_H

#include "../nat_table.h"

/* ---- DNAT-specific logic (dnat.c) ---- */

int dnat_translation(struct sk_buff *skb, const ipfi_flow *flow,
                     struct response *resp, struct info_flags *flags);

struct nat_table *add_dnatted_entry(const struct sk_buff *skb,
                                    const ipfi_flow *flow,
                                    struct response *resp,
                                    struct info_flags *flags,
                                    const ipfire_rule *dnat_rule);

int dest_translate(struct sk_buff *skb, const struct nat_table *dnt);

int de_dnat(struct sk_buff *skb, const struct nat_table *dnatt);
int de_dnat_table_match(const struct nat_table *dnt, const struct sk_buff *skb);
int de_dnat_translation(struct sk_buff *skb, const ipfi_flow *flow,
                        struct response *resp, struct info_flags *flags);

int pre_de_dnat_translate(struct sk_buff *skb, const struct nat_table *dnt);
int pre_denat_table_match(const struct nat_table *dnt,
                          const struct sk_buff *skb);
int pre_de_dnat(struct sk_buff *skb, const ipfi_flow *flow,
                struct response *resp, struct info_flags *flags);

int get_orig_from_dnat_entry(const struct nat_table *dnt,
                             const net_quadruplet *n4, struct sockaddr_in *sin);

int lookup_dnat_table_and_getorigdst(const net_quadruplet *n4,
                                     struct sockaddr_in *sin);

int get_original_dest(struct sock *sk, int optval, void __user *user, int *len);

#endif /* IPFI_DNAT_H */
