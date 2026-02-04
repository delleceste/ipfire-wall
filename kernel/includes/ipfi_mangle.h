#ifndef IPFI_MANGLE_H
#define IPFI_MANGLE_H

#include "ipfi.h"

/**
 * mangle_skb() - Apply packet manipulations based on firewall rule settings
 * @pm: packet manipulation structure from the firewall rule
 * @skb: socket buffer to modify
 * @flow: flow information (direction, interfaces)
 * @reverse: flag indicating if this is a reverse-direction packet
 *
 * Returns: <0 on error, 0 if no manipulation needed/applied, >0 if manipulation succeeded
 */
int mangle_skb(const struct packet_manip* pm, struct sk_buff *skb, 
               const ipfi_flow *flow, short reverse);

/** @return != 0 if some field is set inside packet_manip *pm, 0 otherwise 
 *  @param pm pointer to struct packet_manip to evaluate.
 *
 *  The function simply memcmps pm with a zero filled struct packet_manip, to see if
 *  some field of the structure pm has been set. 
 */
int some_manip_enabled(const struct packet_manip *pm);

#endif

