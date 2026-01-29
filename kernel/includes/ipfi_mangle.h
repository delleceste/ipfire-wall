#ifndef IPFI_MANGLE_H
#define IPFI_MANGLE_H

#include "ipfi.h"

/** given a rule and a socket buffer, this function determines if the rule 
 *  wants to manipulate the packet.
 *  If yes, mangle_skb() calls the adequate mangle function, depending on the manip option(s)
 *  specified inside struct packet_manip of the rule.
 *
 * @param pm pointer to the packet manipulation structure. 
 * @param skb socket buffer to modify in case mangle is needed.
 * @param info ipfire_info_t to update with mangle information, if needed. This is done
 * in order to allow the userspace console to reveal if some packet mangling has been performed.
 * @return < 0 if an error occurred somewhere, 0 in case of success.
 */
int mangle_skb(const struct packet_manip* pm, struct sk_buff *skb, ipfire_info_t *info);

/** @return != 0 if some field is set inside packet_manip *pm, 0 otherwise 
 *  @param pm pointer to struct packet_manip to evaluate.
 *
 *  The function simply memcmps pm with a zero filled struct packet_manip, to see if
 *  some field of the structure pm has been set. 
 */
int some_manip_enabled(const struct packet_manip *pm);

#endif

