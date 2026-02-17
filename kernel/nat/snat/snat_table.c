/* nat/snat/snat_table.c: SNAT table management for ipfire-wall */

#include "globals.h"
#include "ipfi.h"
#include "ipfi_machine.h"
#include "../../filter/state/state_machine.h"
#include "../nat.h"
#include "snat.h"
#include <linux/jhash.h>
#include <linux/jhash.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/timer.h>
#include <linux/bitops.h>

u32 get_snat_hash(__u32 new_saddr, __u16 new_sport, __u32 old_daddr,
                  __u16 old_dport, __u8 proto) {
  __u32 a1 = new_saddr, a2 = old_daddr;
  __u16 p1 = new_sport, p2 = old_dport;
  if (a1 > a2 || (a1 == a2 && p1 > p2)) {
    swap(a1, a2);
    swap(p1, p2);
  }
  if (proto == IPPROTO_ICMP)
    return jhash_3words(a1, a2, 0, proto);

  return jhash_3words(a1, a2, ((u32)p1 << 16) | p2, proto);
}

int lookup_snatted_table_n_update_timer(
    const struct snatted_table *sne, const struct sk_buff *skb,
    const ipfi_flow *flow, struct response *resp, struct info_flags *flags) {
  struct snatted_table *sntmp;
  /* TODO: restore hash
  u32 hash = get_snat_hash(sne->new_saddr, sne->new_sport, sne->old_daddr,
                           sne->old_dport, sne->protocol);
  */
  rcu_read_lock_bh();
  /* TODO: restore hash
  hash_for_each_possible_rcu(snat_hashtable, sntmp, hnode, hash) {
  */
  list_for_each_entry_rcu(sntmp, &snat_list, lnode) {
    if (compare_snat_entries(sntmp, sne) == 1) {
      sntmp->state = state_machine(skb, sntmp->state, 0);
      update_snat_timer(sntmp);
      rcu_read_unlock_bh();
      return sntmp;
    }
  }
  rcu_read_unlock_bh();
  return NULL;
}

static int forward_snat_match(const struct snatted_table *snt,
                              const struct sk_buff *skb) {
  struct iphdr *iph = ip_hdr(skb);
  net_quadruplet nq = get_quad_from_skb(skb);
  if (!nq.valid)
    return -1;
  if (iph->protocol != snt->protocol)
    return -1;
  if (iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP) {
    if (iph->saddr == snt->old_saddr && nq.sport == snt->old_sport &&
        iph->daddr == snt->old_daddr && nq.dport == snt->old_dport)
      return 1;
  } else {
    if (iph->saddr == snt->old_saddr && iph->daddr == snt->old_daddr)
      return 1;
  }
  return -1;
}

struct snatted_table *lookup_snat_forward(const struct sk_buff *skb,
                                          const ipfi_flow *flow,
                                          struct response *resp,
                                          struct info_flags *flags) {
  struct snatted_table *sntmp;
  /* TODO: restore hash
  int bkt;
  */

  /* Optimization: check moved to caller */

  rcu_read_lock_bh();
  /* TODO: restore hash
  hash_for_each_rcu(snat_hashtable, bkt, sntmp, hnode) {
  */
  list_for_each_entry_rcu(sntmp, &snat_list, lnode) {
    if (forward_snat_match(sntmp, skb) > 0) {
      sntmp->state = state_machine(skb, sntmp->state, 0);
      update_snat_timer(sntmp);
      rcu_read_unlock_bh();
      return sntmp;
    }
  }
  rcu_read_unlock_bh();
  return NULL;
}

int fill_snat_entry_net_fields(struct snatted_table *snentry,
                               const struct sk_buff *skb, const ipfi_flow *flow,
                               const struct response *resp,
                               const struct info_flags *flags,
                               const ipfire_rule *snat_rule) {
  struct iphdr *iph = ip_hdr(skb);
  memset(snentry, 0, sizeof(struct snatted_table));
  snentry->protocol = iph->protocol;
  snentry->old_saddr = iph->saddr;
  snentry->old_daddr = iph->daddr;
  if (flow->in)
    strncpy(snentry->in_devname, flow->in->name, IFNAMSIZ);
  if (flow->out)
    strncpy(snentry->out_devname, flow->out->name, IFNAMSIZ);
  if (iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP) {
    struct tcphdr *th = (struct tcphdr *)((void *)iph + iph->ihl * 4);
    snentry->old_sport = th->source;
    snentry->old_dport = th->dest;
  }
  snentry->direction = flags->direction;
  snentry->external = flags->external;
  snentry->rule_id = resp->rule_id;
  snentry->position = snatted_entry_counter;
  snentry->new_saddr = iph->saddr;
  snentry->new_sport =
      (iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP)
          ? snentry->old_sport
          : 0;
  if (snat_rule->nflags.newaddr)
    snentry->new_saddr = snat_rule->newaddr;
  if (snat_rule->nflags.newport)
    snentry->new_sport = snat_rule->newport;
  return 0;
}

int compare_snat_entries(const struct snatted_table *sne1,
                         const struct snatted_table *sne2) {
  return ((sne1->protocol == sne2->protocol) &&
          (sne1->old_saddr == sne2->old_saddr) &&
          (sne1->old_daddr == sne2->old_daddr) &&
          (sne1->old_dport == sne2->old_dport) &&
          (sne1->old_sport == sne2->old_sport) &&
          (sne1->new_saddr == sne2->new_saddr) &&
          (sne1->new_sport == sne2->new_sport) &&
          (sne1->direction == sne2->direction));
}

void update_snat_timer(struct snatted_table *snt) {
  unsigned int timeout;

  if (unlikely(test_bit(IPFI_NAT_REMOVED, &snt->status)))
      return;

  timeout = get_timeout_by_state(snt->protocol, snt->state);
  if (time_after(jiffies, READ_ONCE(snt->last_timer_update) + (5 * HZ))) {
    if (unlikely(test_bit(IPFI_NAT_REMOVED, &snt->status)))
        return;
    mod_timer(&snt->timer_snattedlist, jiffies + HZ * timeout);
    WRITE_ONCE(snt->last_timer_update, jiffies);
  }
}

static void free_snat_work(struct work_struct *work) {
  struct snatted_table *snt =
      container_of(work, struct snatted_table, cleanup_work);

  timer_delete_sync(&snt->timer_snattedlist);

  call_rcu(&snt->snat_rcuh, free_snat_entry_rcu_call);
}

void handle_snatted_entry_timeout(struct timer_list *t) {
  struct snatted_table *snt = timer_container_of(snt, t, timer_snattedlist);
  spin_lock_bh(&snat_list_lock);
  list_del_rcu(&snt->lnode);
  set_bit(IPFI_NAT_REMOVED, &snt->status);
  snatted_entry_counter--;
  spin_unlock_bh(&snat_list_lock);
  snatted_put(snt);
}

void fill_timer_snat_entry(struct snatted_table *snt) {
  unsigned timeo = get_timeout_by_state(snt->protocol, snt->state);
  INIT_WORK(&snt->cleanup_work, free_snat_work);
  timer_setup(&snt->timer_snattedlist, handle_snatted_entry_timeout, 0);
  snt->timer_snattedlist.expires = jiffies + HZ * timeo;
  snt->status = 0;
  snt->last_timer_update = jiffies;
}

void free_snat_entry_rcu_call(struct rcu_head *head) {
  struct snatted_table *snatt =
      container_of(head, struct snatted_table, snat_rcuh);
  kfree(snatt);
}

int free_snatted_table(void) {
  struct snatted_table *stl, *tmp;
  LIST_HEAD(to_free);
  int counter = 0;

  /* No explicit synchronize_net() needed here if we rely on proper RCU/refcounting patterns,
     but if it was there for a reason, we can keep or remove it.
     Usually module unload handles sync. */

  spin_lock_bh(&snat_list_lock);
  /* Move whole list into temporary list in O(1) */
  list_splice_init(&snat_list, &to_free);
  list_for_each_entry(stl, &to_free, lnode)
      set_bit(IPFI_NAT_REMOVED, &stl->status);
  /* Determine how many items we are removing */
  /* We can't easily count them without iterating, but we know the total counter */
  counter = snatted_entry_counter;
  snatted_entry_counter = 0;
  spin_unlock_bh(&snat_list_lock);

  /* Now process detached entries safely without holding the lock */
  list_for_each_entry_safe(stl, tmp, &to_free, lnode) {
    list_del(&stl->lnode);
    /* No need to decrement counter here as we zeroed the global one */
    snatted_put(stl);
  }

  return counter;
}
