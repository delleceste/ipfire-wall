#ifndef IPFI_NAT_H
#define IPFI_NAT_H

#include <common/ipfi_structures.h>
#include <linux/refcount.h>
#include <linux/slab.h>
#include <linux/timer.h>
#include <linux/workqueue.h>

#define SO_IPFI_GETORIG_DST 200 /* a number */

#define SNAT_ENTRY 0
#define DNAT_ENTRY 1

#define DNAT_HASH_BITS 10
#define SNAT_HASH_BITS 10

typedef struct {
  __u32 saddr, daddr;
  __u16 sport, dport;
  /* 0 is not valid */
  short int valid;
} net_quadruplet;

#define IPFI_NAT_REMOVED 0

struct pkt_manip_info {
  __u8 sa : 1, sp : 1, da : 1, dp : 1,
      direction : 4; /* 4 bits as in ipfire_rule */
};

extern struct workqueue_struct *ipfire_wq;

/* Common functions */
int init_translation(void);
void fini_translation(void);

net_quadruplet get_quad_from_skb(const struct sk_buff *skb);

/* given source and destination addresses and ports, this function sets them
 * in socket buffer passed as parameter. In case of TCP or UDP protocols,
 * returns 1, 0 for ICMP, -1 in case of errors
 */
int manip_skb(struct sk_buff *skb, __u32 saddr, __u16 sport, __u32 daddr,
              __u16 dport, struct pkt_manip_info pf);

/* checks ip and transport checksums, returning 0  if correct,
 * a negative value picked from enum checksum_errors (ipfi.h) otherwise */
int check_checksums(const struct sk_buff *skb);

/* prints the checksum error message according to the checksum_errore enum
 * defined in ipfi.h and returns -1. Introducted in 0.99.2
 */
int csum_error_message(const char *origin, int enum_code);

/* skb contains the fields taken from sk_buff, r is the translation rule.
 * In this function, the skb must match the rule provided by user for
 * DNAT or SNAT (or MASQUERADE). 1 is returned on success
 */
int translation_rule_match(const struct sk_buff *skb, const ipfi_flow *flow,
                           const struct info_flags *flags,
                           const ipfire_rule *r);

/* returns 1 if network address is a private one conforming
 * to rfc 1918, 0 otherwise */
inline int private_address(__u32 addr);

/* returns 1 if packet comes from a public host and
 * gets redirected to an internal host. */
int public_to_private_address(const struct sk_buff *skb,
                              const ipfire_rule *transrule);

/* copies address in *address, looking for devices with name
 * equal to device name in skb. Returns 1 or -1 in case of failure  */
__u32 get_ifaddr(const struct sk_buff *skb, const struct net_device *dev);

#endif /* IPFI_NAT_H */
