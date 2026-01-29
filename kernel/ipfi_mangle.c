#include "includes/ipfi_mangle.h"
#include "includes/ipfi_tcpmss.h"

/* given a rule and a socket buffer, this function determines if the rule 
 *  wants to manipulate the packet.
 *  If yes, mangle_skb() calls the adequate mangle function, depending on the manip option(s)
 *  specified inside struct packet_manip of the rule.
 *
 * param pm: pointer to the packet manipulation structure.
 * skb:     socket buffer to modify in case mangle is needed.
 * info:    ipfire_info_t to update with mangle information, if needed. This is done
 *          in order to allow the userspace console to reveal if some packet mangling has been performed.
 * mangle_skb() returns < 0 in case of error, 0 if mangle not needed
 * (or not appliable - for instance changing mss is suitable only for tcp syn packets -)
 * > 0 if mangle is applied.
 */

int mangle_skb(const struct packet_manip* pm, struct sk_buff *skb, ipfire_info_t *info)
{
  int ret = 0;
  /* Maximum segment size */
  if(pm->mss.enabled && packet_suitable_for_mss_change(info) > 0)
    ret = tcpmss_mangle_packet(skb, pm->mss.option, pm->mss.mss, info);
  return ret;
}

int some_manip_enabled(const struct packet_manip *pm)
{
  struct packet_manip zero_manip;
  memset(&zero_manip, 0, sizeof(zero_manip));
  /* memcmp returns 0 if the two memory areas match */
  return memcmp(pm, &zero_manip, sizeof(struct packet_manip));
}


