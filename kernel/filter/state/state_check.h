#ifndef IPFI_STATE_CHECK_H
#define IPFI_STATE_CHECK_H

#include <linux/skbuff.h>
#include <common/ipfi_structures.h>
#include "state_table.h"

struct response check_state(struct sk_buff *skb, const ipfi_flow *flow, __u8 *ftp_state);

#endif
