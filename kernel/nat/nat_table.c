/* nat/nat_table.c: NAT table management for ipfire-wall */

#include "globals.h"
#include "ipfi.h"
#include "ipfi_machine.h"
#include "ipfi_state_machine.h"
#include "ipfi_translation.h"
#include <linux/jhash.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/timer.h>

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

struct dnatted_table *lookup_dnatted_table_n_update_timer(
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
      return dntmp;
    }
  }
  rcu_read_unlock_bh();
  return NULL;
}

struct snatted_table *lookup_snatted_table_n_update_timer(
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

  /* Optimization: if no DNAT entries exist, skip the lookup */
  /* This reads a global int, which is atomic enough for this heuristic check */
  if (dnatted_entry_counter == 0)
    return NULL;

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

  /* Optimization: if no SNAT entries exist, skip the lookup */
  if (snatted_entry_counter == 0)
    return NULL;

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

void update_dnat_timer(struct dnatted_table *dnt) {
  unsigned int timeout = get_timeout_by_state(dnt->protocol, dnt->state);
  if (time_after(jiffies, dnt->last_timer_update + HZ)) {
    mod_timer(&dnt->timer_dnattedlist, jiffies + HZ * timeout);
    dnt->last_timer_update = jiffies;
  }
}

void update_snat_timer(struct snatted_table *snt) {
  unsigned int timeout = get_timeout_by_state(snt->protocol, snt->state);
  if (time_after(jiffies, snt->last_timer_update + HZ)) {
    mod_timer(&snt->timer_snattedlist, jiffies + HZ * timeout);
    snt->last_timer_update = jiffies;
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

static void free_snat_work(struct work_struct *work) {
  struct snatted_table *snt =
      container_of(work, struct snatted_table, cleanup_work);

  timer_delete_sync(&snt->timer_snattedlist);

  call_rcu(&snt->snat_rcuh, free_snat_entry_rcu_call);
}

void handle_dnatted_entry_timeout(struct timer_list *t) {
  struct dnatted_table *dnt = timer_container_of(dnt, t, timer_dnattedlist);

  spin_lock_bh(&dnat_list_lock);
  /* TODO: restore hash
  if (hlist_unhashed(&dnt->hnode)) {
    spin_unlock_bh(&dnat_list_lock);
    return;
  }
  hash_del_rcu(&dnt->hnode);
  */
  list_del_rcu(&dnt->lnode);
  dnatted_entry_counter--;
  spin_unlock_bh(&dnat_list_lock);

  if (ipfire_wq)
    queue_work(ipfire_wq, &dnt->cleanup_work);
}

void handle_snatted_entry_timeout(struct timer_list *t) {
  struct snatted_table *snt = timer_container_of(snt, t, timer_snattedlist);

  spin_lock_bh(&snat_list_lock);
  /* TODO: restore hash
  if (hlist_unhashed(&snt->hnode)) {
    spin_unlock_bh(&snat_list_lock);
    return;
  }
  hash_del_rcu(&snt->hnode);
  */
  list_del_rcu(&snt->lnode);
  snatted_entry_counter--;
  spin_unlock_bh(&snat_list_lock);

  if (ipfire_wq)
    queue_work(ipfire_wq, &snt->cleanup_work);
}

void fill_timer_dnat_entry(struct dnatted_table *dnt) {
  unsigned timeo = get_timeout_by_state(dnt->protocol, dnt->state);
  INIT_WORK(&dnt->cleanup_work, free_dnat_work);
  timer_setup(&dnt->timer_dnattedlist, handle_dnatted_entry_timeout, 0);
  dnt->timer_dnattedlist.expires = jiffies + HZ * timeo;
  dnt->last_timer_update = jiffies;
}

void fill_timer_snat_entry(struct snatted_table *snt) {
  unsigned timeo = get_timeout_by_state(snt->protocol, snt->state);
  INIT_WORK(&snt->cleanup_work, free_snat_work);
  timer_setup(&snt->timer_snattedlist, handle_snatted_entry_timeout, 0);
  snt->timer_snattedlist.expires = jiffies + HZ * timeo;
  snt->last_timer_update = jiffies;
}

void free_dnat_entry_rcu_call(struct rcu_head *head) {
  struct dnatted_table *dnatt =
      container_of(head, struct dnatted_table, dnat_rcuh);
  kfree(dnatt);
}

void free_snat_entry_rcu_call(struct rcu_head *head) {
  struct snatted_table *snatt =
      container_of(head, struct snatted_table, snat_rcuh);
  kfree(snatt);
}

int free_dnatted_table(void) {
  struct dnatted_table *dtl;
  struct dnatted_table *dnttmp;
  int counter = 0;
  spin_lock_bh(&dnat_list_lock);
  /* TODO: restore hash
  hash_for_each_safe(dnat_hashtable, bkt, tmp, dtl, hnode) {
  */
  list_for_each_entry_safe(dtl, dnttmp, &dnat_list, lnode) {
    /* Removal under lock - this ensures we win against the timer handler. */
    /* TODO: restore hash
    hash_del_rcu(&dtl->hnode);
    */
    list_del_rcu(&dtl->lnode);
    dnatted_entry_counter--;
    /* Now queue work to safely timer_delete_sync(dtl->timer_dnattedlist)
     * and call_rcu outside of the spinlock block.
     */
    if (ipfire_wq)
      queue_work(ipfire_wq, &dtl->cleanup_work);
    counter++;
  }
  spin_unlock_bh(&dnat_list_lock);
  return counter;
}

int free_snatted_table(void) {
  struct snatted_table *stl;
  struct snatted_table *snttmp;
  int counter = 0;
  synchronize_net();
  spin_lock_bh(&snat_list_lock);
  /* TODO: restore hash
  hash_for_each_safe(snat_hashtable, bkt, tmp, stl, hnode) {
  */
  list_for_each_entry_safe(stl, snttmp, &snat_list, lnode) {
    /* TODO: restore hash
    hash_del_rcu(&stl->hnode);
    */
    list_del_rcu(&stl->lnode);
    snatted_entry_counter--;
    if (ipfire_wq)
      queue_work(ipfire_wq, &stl->cleanup_work);
    counter++;
  }
  spin_unlock_bh(&snat_list_lock);
  return counter;
}
