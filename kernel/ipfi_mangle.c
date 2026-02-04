#include "includes/ipfi_mangle.h"
#include "includes/ipfi_tcpmss.h"

/**
 * mangle_skb() - Apply packet manipulations based on firewall rule settings
 * @pm: packet manipulation structure from the firewall rule
 * @skb: socket buffer to modify
 * @flow: flow information (direction, interfaces)
 * @reverse: flag indicating if this is a reverse-direction packet
 *
 * This function examines the packet_manip structure from a firewall rule
 * and applies any enabled manipulations. Currently supports:
 * - TCP MSS clamping (for PMTU discovery)
 *
 * Returns: <0 on error, 0 if no manipulation needed/applied, >0 if manipulation succeeded
 */
int mangle_skb(const struct packet_manip* pm, struct sk_buff *skb, 
               const ipfi_flow *flow, short reverse)
{
  int ret = 0;
  
  /* TCP Maximum Segment Size manipulation 
   * Only applied if:
   * 1. MSS mangling is enabled in the rule (pm->mss.enabled)
   * 2. Packet is suitable (TCP SYN or SYN/ACK)
   */
  if(pm->mss.enabled && packet_suitable_for_mss_change(skb, flow, reverse) > 0)
    ret = tcpmss_mangle_packet(skb, pm->mss.option, pm->mss.mss);
    
  return ret;
}

int some_manip_enabled(const struct packet_manip *pm)
{
  struct packet_manip zero_manip;
  memset(&zero_manip, 0, sizeof(zero_manip));
  /* memcmp returns 0 if the two memory areas match */
  return memcmp(pm, &zero_manip, sizeof(struct packet_manip));
}


