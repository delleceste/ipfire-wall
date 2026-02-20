#ifndef IPFI_STATE_MACHINE_H
#define IPFI_STATE_MACHINE_H

#include <linux/skbuff.h>
#include "state_table.h"

int state_machine(const struct sk_buff *skb, int current_state, short reverse);
/* Sets the state inside the state structure. */
int set_state(const struct sk_buff* skb, struct state_table *entry, short reverse);

#endif
