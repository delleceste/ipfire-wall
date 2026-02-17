/* nat/dnat/dnat_table.c: DNAT table management for ipfire-wall */

#include "globals.h"
#include "ipfi.h"
#include "ipfi_machine.h"
#include "../../filter/state/state_machine.h"
#include "../nat.h"
#include "dnat.h"
#include <linux/jhash.h>
#include <linux/jhash.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/timer.h>
#include <linux/bitops.h>

u32 get_dnat_hash(__u32 old_saddr, __u16 old_sport, __u32 new_daddr,
                  __u16 new_dport, __u8 proto) {
  __u32 a1 = old_saddr, a2 = new_daddr;
  __u16 p1 = old_sport, p2 = new_dport;
  if (a1 > a2 || (a1 == a2 && p1 > p2)) {
    swap(a1, a2);
    swap(p1, p2);
  }
  if (proto == IPPROTO_ICMP)
    return jhash_3words(a1, a2, 0, proto);

  return jhash_3words(a1, a2, ((u32)p1 << 16) | p2, proto);
}

int fill_entry_net_fields(struct dnatted_table *dnentry,
                          const struct sk_buff *skb, const ipfi_flow *flow,
                          const struct response *resp,
                          const struct info_flags *flags,
                          const ipfire_rule *dnat_rule) {
  struct iphdr *iph = ip_hdr(skb);
  memset(dnentry, 0, sizeof(struct dnatted_table));
  dnentry->external = flags->external;
  dnentry->protocol = iph->protocol;
  dnentry->old_saddr = iph->saddr;
  dnentry->old_daddr = iph->daddr;
  dnentry->new_daddr = iph->daddr;
  if (flow->in)
    strncpy(dnentry->in_devname, flow->in->name, IFNAMSIZ);
  if (flow->out)
    strncpy(dnentry->out_devname, flow->out->name, IFNAMSIZ);
  if (iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP) {
    struct tcphdr *th = (struct tcphdr *)((void *)iph + iph->ihl * 4);
    dnentry->old_sport = th->source;
    dnentry->old_dport = th->dest;
    dnentry->new_dport = dnentry->old_dport;
  } else if (iph->protocol == IPPROTO_ICMP) {
    dnentry->old_sport = 0;
    dnentry->old_dport = 0;
    dnentry->new_dport = 0;
  }
  dnentry->direction = flags->direction;
  dnentry->rule_id = resp->rule_id;
  dnentry->position = dnatted_entry_counter;
  if (dnat_rule->nflags.newaddr)
    dnentry->new_daddr = dnat_rule->newaddr;
  if (dnat_rule->nflags.newport)
    dnentry->new_dport = dnat_rule->newport;
  return 0;
}

int lookup_dnatted_table_n_update_timer(
    const struct dnatted_table *dne, const struct sk_buff *skb,
    const ipfi_flow *flow, struct response *resp, struct info_flags *flags) {
  struct dnatted_table *dntmp;
  /* TODO: restore hash
  u32 hash = get_dnat_hash(dne->old_saddr, dne->old_sport, dne->new_daddr,
                           dne->new_dport, dne->protocol);
  */
  rcu_read_lock_bh();
  /* TODO: restore hash
  hash_for_each_possible_rcu(dnat_hashtable, dntmp, hnode, hash) {
  */
  list_for_each_entry_rcu(dntmp, &dnat_list, lnode) {
    if (compare_entries(dntmp, dne) == 1) {
      dntmp->state = state_machine(skb, dntmp->state, 0);
      update_dnat_timer(dntmp);
      rcu_read_unlock_bh();
      return 1;
    }
  }
  rcu_read_unlock_bh();
  return 0;
}

static int forward_dnat_match(const struct dnatted_table *dnt,
                              const struct sk_buff *skb) {
  struct iphdr *iph = ip_hdr(skb);
  net_quadruplet nq = get_quad_from_skb(skb);
  if (!nq.valid)
    return -1;
  if (iph->protocol != dnt->protocol)
    return -1;
  if (iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP) {
    if (iph->saddr == dnt->old_saddr && nq.sport == dnt->old_sport &&
        iph->daddr == dnt->old_daddr && nq.dport == dnt->old_dport)
      return 1;
  } else {
    if (iph->saddr == dnt->old_saddr && iph->daddr == dnt->old_daddr)
      return 1;
  }
  return -1;
}

struct dnatted_table *lookup_dnat_forward(const struct sk_buff *skb,
                                          const ipfi_flow *flow,
                                          struct response *resp,
                                          struct info_flags *flags) {
  struct dnatted_table *dntmp;
  /* TODO: restore hash
  int bkt;
  */

  /* Optimization: check moved to caller (ipfi_pre/post_process) */

  rcu_read_lock_bh();
  /* TODO: restore hash
  hash_for_each_rcu(dnat_hashtable, bkt, dntmp, hnode) {
  */
  list_for_each_entry_rcu(dntmp, &dnat_list, lnode) {
    if (forward_dnat_match(dntmp, skb) > 0) {
      dntmp->state = state_machine(skb, dntmp->state, 0);
      update_dnat_timer(dntmp);
      rcu_read_unlock_bh();
      return dntmp;
    }
  }
  rcu_read_unlock_bh();
  return NULL;
}

int compare_entries(const struct dnatted_table *dne1,
                    const struct dnatted_table *dne2) {
  return ((dne1->protocol == dne2->protocol) &&
          (dne1->old_saddr == dne2->old_saddr) &&
          (dne1->old_daddr == dne2->old_daddr) &&
          (dne1->old_dport == dne2->old_dport) &&
          (dne1->old_sport == dne2->old_sport) &&
          (dne1->new_daddr == dne2->new_daddr) &&
          (dne1->new_dport == dne2->new_dport) &&
          (dne1->direction == dne2->direction));
}

void update_dnat_timer(struct dnatted_table *dnt) {
  unsigned int timeout;

  if (unlikely(test_bit(IPFI_NAT_REMOVED, &dnt->status)))
      return;

  timeout = get_timeout_by_state(dnt->protocol, dnt->state);
  if (time_after(jiffies, READ_ONCE(dnt->last_timer_update) + (5 * HZ))) {
    if (unlikely(test_bit(IPFI_NAT_REMOVED, &dnt->status)))
        return;

    mod_timer(&dnt->timer_dnattedlist, jiffies + HZ * timeout);
    WRITE_ONCE(dnt->last_timer_update, jiffies);
  }
}

static void free_dnat_work(struct work_struct *work) {
  struct dnatted_table *dnt =
      container_of(work, struct dnatted_table, cleanup_work);

  /* Safe to sync because we are in process context (workqueue worker) */
  timer_delete_sync(&dnt->timer_dnattedlist);

  /* Readers are finished, timer is synced, now we can free after RCU grace. */
  call_rcu(&dnt->dnat_rcuh, free_dnat_entry_rcu_call);
}

void handle_dnatted_entry_timeout(struct timer_list *t) {
  struct dnatted_table *dnt = timer_container_of(dnt, t, timer_dnattedlist);

  spin_lock_bh(&dnat_list_lock);
  list_del_rcu(&dnt->lnode);
  set_bit(IPFI_NAT_REMOVED, &dnt->status);
  dnatted_entry_counter--;
  spin_unlock_bh(&dnat_list_lock);

  dnatted_put(dnt);
}

void fill_timer_dnat_entry(struct dnatted_table *dnt) {
  unsigned timeo = get_timeout_by_state(dnt->protocol, dnt->state);
  INIT_WORK(&dnt->cleanup_work, free_dnat_work);
  timer_setup(&dnt->timer_dnattedlist, handle_dnatted_entry_timeout, 0);
  dnt->timer_dnattedlist.expires = jiffies + HZ * timeo;
  dnt->status = 0;
  dnt->last_timer_update = jiffies;
}

void free_dnat_entry_rcu_call(struct rcu_head *head) {
  struct dnatted_table *dnatt =
      container_of(head, struct dnatted_table, dnat_rcuh);
  kfree(dnatt);
}

int free_dnatted_table(void) {
	struct dnatted_table *dtl, *tmp;
			LIST_HEAD(to_free);
			spin_lock_bh(&dnat_list_lock);
			/*
			 * Move whole list into temporary list in O(1)
			 */
			list_splice_init(&dnat_list, &to_free);
      list_for_each_entry(dtl, &to_free, lnode)
        set_bit(IPFI_NAT_REMOVED, &dtl->status);
			dnatted_entry_counter = 0;
			spin_unlock_bh(&dnat_list_lock);
			/*
			 * Now process detached entries safely
			 */
			list_for_each_entry_safe(dtl, tmp, &to_free, lnode) {
					list_del(&dtl->lnode);
					dnatted_put(dtl);
			}
			return 0;
}
