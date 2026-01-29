#ifndef IPFI_TCPMSS_H
#define IPFI_TCPMSS_H

#include "ipfi.h"
#include <linux/types.h>
#include <linux/skbuff.h>

u_int32_t get_net_mtu(__u32 address);

int tcpmss_mangle_packet(struct sk_buff *skb,  short unsigned int option, __u16 mss, ipfire_info_t *info);

int packet_suitable_for_mss_change(const ipfire_info_t *);

int optlen(const u_int8_t *opt, unsigned int offset);

#endif
