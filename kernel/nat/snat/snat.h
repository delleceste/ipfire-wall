#ifndef IPFI_SNAT_H
#define IPFI_SNAT_H

#include "../nat_table.h"

/* ---- SNAT-specific logic (snat.c) ---- */

int snat_translation(struct sk_buff *skb, const ipfi_flow *flow,
                     struct response *resp, struct info_flags *flags);

struct nat_table *add_snatted_entry(const struct sk_buff *skb,
                                    const ipfi_flow *flow,
                                    struct response *resp,
                                    struct info_flags *flags,
                                    const ipfire_rule *snat_rule);

int snat_packet(struct sk_buff *skb, const struct nat_table *snt);

int de_snat(struct sk_buff *skb, struct nat_table *snt);
int de_snat_table_match(struct nat_table *snt, struct sk_buff *skb);
int pre_de_snat(struct sk_buff *skb, const ipfi_flow *flow,
                struct response *resp, struct info_flags *flags);

int snat_dynamic_translate(struct sk_buff *skb, struct nat_table *dnt);
int snat_dynamic_table_match(const struct nat_table *dnt,
                             const struct sk_buff *skb);
int post_snat_dynamic(struct sk_buff *skb, const ipfi_flow *flow,
                      struct response *resp, struct info_flags *flags);

/* Masquerade */
int masquerade_translation(struct sk_buff *skb, const ipfi_flow *flow,
                           struct response *resp, struct info_flags *flags);
int masquerade_packet(struct sk_buff *skb, const struct nat_table *snt);
void fill_masquerade_rule_fields(ipfire_rule *ipfr, __u32 newsaddr);
void clear_masquerade_rule_fields(ipfire_rule *);

#endif /* IPFI_SNAT_H */
