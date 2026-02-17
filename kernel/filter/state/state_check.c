/* filter/state/state_check.c: State checking logic for ipfire-wall */

#include "globals.h"
#include "ipfire.h"
#include "helpers/ftp.h"
#include "ipfi_machine.h"
#include "state_machine.h"
#include <linux/ip.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/udp.h>

struct response check_state(struct sk_buff *skb, const ipfi_flow *flow,
                            __u8 *ftp_state) {
  struct state_table *table_entry = NULL, *new_ftp_entry = NULL;
  struct response ret = {
      .verdict = IPFI_IMPLICIT,
  };
  short reverse = 0;
  struct iphdr *iph = ip_hdr(skb);
  /* TODO: restore hash
  __u16 sport = 0, dport = 0;
  */
  /* TODO: restore hash
  key = get_state_hash(iph->saddr, iph->daddr, sport, dport, iph->protocol);
  */
  rcu_read_lock_bh();

  /* TODO: restore hash
  hash_for_each_possible_rcu(state_hashtable, table_entry, hnode, key) {
  */
  list_for_each_entry_rcu(table_entry, &state_list, h.lnode) {
    if (skb_matches_state_table(skb, table_entry, &reverse, flow) > 0) {
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
            if (lookup_state_table_n_update_timer(new_ftp_entry) == 0) {
              if (add_ftp_dynamic_rule(new_ftp_entry) < 0) {
                kfree(new_ftp_entry);
                new_ftp_entry = NULL;
              }
            }
            if (new_ftp_entry)
              state_put(new_ftp_entry);
        }
      } else if (table_entry->ftp == FTP_DEFINED) {
        table_entry->ftp = FTP_ESTABLISHED;
        struct tcphdr *th = (struct tcphdr *)((void *)iph + iph->ihl * 4);
        table_entry->sport = th->source;
      }
      update_timer_of_state_entry(table_entry);
    
      ret.rule_id = table_entry->rule_id;
      ret.nolog = table_entry->nolog; /* propagate nolog flag */
      if (ftp_state)
        *ftp_state = table_entry->ftp;
      rcu_read_unlock_bh();
      return ret;
    }
  }
  rcu_read_unlock_bh();
  return ret;
}
