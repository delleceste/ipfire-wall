/* filter/state/state_timeout.c: Timeout and timer management for ipfire-wall */

#include "ipfi_machine.h"
#include "ipfire.h"
#include <linux/bitops.h>
#include <linux/ip.h>
#include <linux/jiffies.h>
#include <linux/timer.h>

unsigned int syn_lifetime = 2 * 60;
unsigned int synack_lifetime = 60;
unsigned int est_lifetime =
    5 * 24 * 60 * 60; /* 5 days - matches Linux conntrack (and original IPFIRE
                         implementation) */
unsigned int close_wait_lifetime = 60;
unsigned int fin_wait_lifetime = 2 * 60;
unsigned int last_ack_lifetime = 30;
unsigned int time_wait_lifetime = 2 * 60;
unsigned int close_lifetime = 10;
unsigned int udp_new_lifetime = 30;
unsigned int udp_lifetime = 180;
unsigned int icmp_lifetime =
    30; /* ICMP echo request/reply - matches Linux conntrack */
unsigned int igmp_lifetime = 60; /* IGMP membership reports */
unsigned int gre_lifetime = 180; /* GRE tunnels - longer for keepalive */
unsigned int pim_lifetime = 60;  /* PIM multicast routing */
unsigned int l3generic_proto_lifetime = 60; /* Other L3 protocols */

inline unsigned int get_timeout_by_state(int protocol, int state) {
  unsigned int timeout = close_lifetime;

  if (protocol == IPPROTO_TCP) {
    switch (state) {
    case ESTABLISHED:
    case GUESS_ESTABLISHED:
      timeout = est_lifetime;
      break;
    case SYN_RECV:
    case GUESS_SYN_RECV:
      timeout = synack_lifetime;
      break;
    case SYN_SENT:
    case FTP_NEW:
      timeout = syn_lifetime;
      break;
    case CLOSE_WAIT:
      timeout = close_wait_lifetime;
      break;
    case IPFI_TIME_WAIT:
      timeout = time_wait_lifetime;
      break;
    case LAST_ACK:
      timeout = last_ack_lifetime;
      break;
    case FIN_WAIT:
      timeout = fin_wait_lifetime;
      break;
    case CLOSED:
    case GUESS_CLOSING:
    default:
      timeout = close_lifetime;
      break;
    }
  } else if (protocol == IPPROTO_UDP) {
    switch (state) {
    case UDP_ESTAB:
      timeout = udp_lifetime;
      break;
    case UDP_NEW:
    default:
      timeout = udp_new_lifetime;
      break;
    }
  } else if (protocol == IPPROTO_ICMP) {
    timeout = icmp_lifetime;
  } else if (protocol == IPPROTO_IGMP) {
    timeout = igmp_lifetime;
  } else if (protocol == IPPROTO_GRE) {
    timeout = gre_lifetime;
  } else if (protocol == IPPROTO_PIM) {
    timeout = pim_lifetime;
  } else if (protocol == IPPROTO_IPFI_LOG) {
    /* Loginfo entries: flat timeout, state is ignored */
    timeout = loginfo_lifetime;
  } else {
    timeout = l3generic_proto_lifetime;
  }
  return timeout;
}
