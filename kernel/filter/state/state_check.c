/* filter/state/state_check.c: State checking logic for ipfire-wall */

#include "../../helpers/icmp_nat.h"
#include "globals.h"
#include "helpers/ftp.h"
#include "ipfi_machine.h"
#include "ipfire.h"
#include "state_machine.h"
#include <linux/icmp.h>
#include <linux/ip.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/udp.h>

/*
 * accept_state_match - shared helper to populate the return response once a
 * state table entry has been matched.
 */
static struct response accept_state_match(struct sk_buff *skb,
                                          struct state_table *table_entry,
                                          const struct iphdr *iph,
                                          short reverse, __u8 *ftp_state) {
  struct response ret = {};
  struct state_table *new_ftp_entry = NULL;

  ret.verdict = IPFI_ACCEPT;
  ret.notify = table_entry->notify;
  ret.st.reverse = reverse > 0 ? 1U : 0;
  ret.st.reverse_relaxed = reverse > 1 ? 1U : 0;
  ret.st.state = set_state(skb, table_entry, reverse);
  ret.state = 1U;

  if ((table_entry->ftp == FTP_LOOK_FOR) &&
      (table_entry->protocol == IPPROTO_TCP)) {
    new_ftp_entry = ftp_support(table_entry, skb);
    if (new_ftp_entry != NULL) {
      IPFI_PRINTK("IPFIRE FTP: new expectation: saddr=%pI4 daddr=%pI4 "
                  "sport=%u dport=%u\n",
                  &new_ftp_entry->saddr, &new_ftp_entry->daddr,
                  ntohs(new_ftp_entry->sport), ntohs(new_ftp_entry->dport));
      if (lookup_state_table_n_update_timer(new_ftp_entry) == 0) {
        if (add_ftp_dynamic_rule(new_ftp_entry) < 0) {
          kfree(new_ftp_entry);
          new_ftp_entry = NULL;
        } else {
          IPFI_PRINTK("IPFIRE FTP: expectation added to hash table OK\n");
        }
      } else {
        IPFI_PRINTK("IPFIRE FTP: expectation already present, timer updated\n");
      }
      if (new_ftp_entry)
        state_put(new_ftp_entry);
    }
  } else if (table_entry->ftp == FTP_DEFINED) {
    IPFI_PRINTK("IPFIRE FTP: FTP_DEFINED: rehashing saddr=%pI4 daddr=%pI4 "
                "dport=%u to ESTABLISHED\n",
                &table_entry->saddr, &table_entry->daddr,
                ntohs(table_entry->dport));
    struct tcphdr *th = (struct tcphdr *)((void *)iph + iph->ihl * 4);
    /* Rehash the entry into the correct 5-tuple bucket so that the SYN/ACK
     * reply and all subsequent data packets are found by the normal O(1)
     * hash path without needing the secondary FTP lookup. */
    rehash_ftp_expectation(table_entry, th->source);
  }
  update_timer_of_state_entry(table_entry);
  ret.rule_id = table_entry->rule_id;
  ret.nolog = table_entry->nolog;
  if (ftp_state)
    *ftp_state = table_entry->ftp;
  return ret;
}

struct response check_state(struct sk_buff *skb, const ipfi_flow *flow,
                            __u8 *ftp_state) {
  struct state_table *table_entry = NULL;
  struct response ret = {
      .verdict = IPFI_IMPLICIT,
  };
  short reverse = 0;
  struct iphdr *iph = ip_hdr(skb);

  /*
   * Hash-mode: O(1) average lookup.
   *
   * get_state_hash() is symmetric (canonicalises address order), so a
   * single probe covers both the direct and reverse 5-tuple.
   * skb_matches_state_table() then does the exact direction check.
   *
   * For port-less protocols (ICMP, GRE, ...) sport/dport are 0 which is
   * consistent with how fill_net_table_fields() stores them.
   */
  __u16 sport = 0, dport = 0;

  switch (iph->protocol) {
  case IPPROTO_TCP: {
    struct tcphdr *th = (struct tcphdr *)((void *)iph + iph->ihl * 4);
    sport = th->source;
    dport = th->dest;
    break;
  }
  case IPPROTO_UDP: {
    struct udphdr *uh = (struct udphdr *)((void *)iph + iph->ihl * 4);
    sport = uh->source;
    dport = uh->dest;
    break;
  }
  default:
    break;
  }

  __u32 key =
      get_state_hash(iph->saddr, iph->daddr, sport, dport, iph->protocol);

  rcu_read_lock_bh();

  /* Secondary lookup: FTP Passive Data Connections
   * Must run under rcu_read_lock_bh() since it uses hlist_for_each_entry_rcu.
   * The expectation entry stores dport = server data port (from the 227
   * response). The outgoing data SYN has dport = server data port, so probe
   * with that. The sport=0 wildcard is handled inside direct_state_match for
   * FTP_DEFINED entries. */
  if (iph->protocol == IPPROTO_TCP) {
    table_entry = lookup_ftp_expectation(skb, iph, dport, &reverse, flow);
    if (table_entry) {
      ret = accept_state_match(skb, table_entry, iph, reverse, ftp_state);
      rcu_read_unlock_bh();
      return ret;
    }
  }

  hash_for_each_possible_rcu(state_hashtable, table_entry, h.hnode, key) {
    if (skb_matches_state_table(skb, table_entry, &reverse, flow) > 0) {
      ret = accept_state_match(skb, table_entry, iph, reverse, ftp_state);
      rcu_read_unlock_bh();
      return ret;
    }
  }

  /*
   * ICMP error secondary lookup.
   *
   * When an ICMP "Port Unreachable" / "Time Exceeded" / "Parameter Problem"
   * arrives, icmp_nat_process() has already run in PRE_ROUTING and may have
   * modified the inner packet IP addresses (e.g. inner dst changed from the
   * DNAT target C back to the firewall public IP B).
   *
   * The state entry for the original TCP/UDP connection was recorded with the
   * post-DNAT addresses (saddr=A, daddr=C), so the first hash probe above
   * (keyed on outer ICMP addresses, which produce a different bucket) may
   * have missed it.
   *
   * To handle this: if the outer packet is an ICMP error, do a second pass
   * across ALL state entries. match_icmp_error_payload() checks the raw inner
   * payload against each entry's stored 5-tuple; because it reads inner_iph
   * directly from the skb it can compare against whatever the state entry
   * remembers.
   *
   * This is a linear scan, but ICMP errors are rare control-plane traffic, so
   * the cost is acceptable.
   */
  if (iph->protocol == IPPROTO_ICMP) {
    struct icmphdr *icmph = (struct icmphdr *)((void *)iph + iph->ihl * 4);
    if (icmph->type == ICMP_DEST_UNREACH || icmph->type == ICMP_TIME_EXCEEDED ||
        icmph->type == ICMP_PARAMETERPROB) {

      unsigned int bkt;
      hash_for_each_rcu(state_hashtable, bkt, table_entry, h.hnode) {
        reverse = -1;
        if (match_icmp_error_payload(skb, table_entry, &reverse) > 0) {
          ret = accept_state_match(skb, table_entry, iph, reverse, ftp_state);
          rcu_read_unlock_bh();
          return ret;
        }
      }
    }
  }

  rcu_read_unlock_bh();
  return ret;
}
