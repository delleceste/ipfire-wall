/* ip firewall Giacomo S. */
#include "build.h"
#include "globals.h"
#include "ipfire.h"
#include "filter/defrag.h"
#include "ipfi_machine.h"
#include "netlink/ipfi_netl.h"
#include "proc/proc.h"
#include "mangle/tcpmss.h"
#include "ipfi_machine.h"
#include <linux/init.h>
#include "netlink/message_builder.h"
#include "module_init.h"
#include <linux/list.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <net/net_namespace.h>
#include <net/tcp.h>
#include <net/udp.h>

#define NF_IP_PRE_ROUTING NF_INET_PRE_ROUTING
#define NF_IP_POST_ROUTING NF_INET_POST_ROUTING
#define NF_IP_LOCAL_IN NF_INET_LOCAL_IN
#define NF_IP_LOCAL_OUT NF_INET_LOCAL_OUT
#define NF_IP_FORWARD NF_INET_FORWARD

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Giacomo S. <delleceste@gmail.com>");
MODULE_DESCRIPTION("IPv4 packet filter");

/* Versione di test!
 * (C) Giacomo Strangolino, 2005-2026
 * Filtro di pacchetti con funzionalita' di NAT.
 * Il software in kernel space consta di 6 moduli interdipendenti.
 * Per problemi potete scrivere a Giacomo S.
 * posta elettronica: delleceste@gmail.com
 * Software libero :)
 * Si legga la documentazione per l'uso e l'installazione.
 * I commenti al codice e la documentazione sono in lingua inglese
 * per facilitare la lettura del codice a chi ne avesse bisogno, dal
 * momento che io stesso sono stato aiutato nello svolgimento
 * del progetto da diverse persone sparse in tutto il mondo.
 * Grazie!
 * Giacomo.
 */

/***************************************************************************
 *  Copyright  2005-2026  Giacomo Strangolino.
 *
 *  email:
 *  delleceste@gmail.com
 *
 *  Web Site: 		www.giacomos.it
 *  IPFIRE-wall home: 	www.giacomos.it/ipfire
 *
 ****************************************************************************/

/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 */

/*
 * Thanks to:
 * Alessandro Rubini, Alexander Harsch, Andrea Barberio, Jozsef Kadlecsik, Diego
 * Billi, Luigi Rizzo, Paul `Rusty' Russell, Andrew Gargan, Daniele orlandi,
 * Stephen Hemminger, Kasper Dupont, Peter T. Breuer, Tauno Voipio;
 */

/* Linux kernel 2.6.9 and above were used for test, together with
 * debian GNU/Linux - www.debian.org - and
 * slackware Linux  - www.slackware.org.
 */

char *policy = "drop";

module_param(policy, charp, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
MODULE_PARM_DESC(default_policy, "\"accept\" or \"drop\" policy as default.\n");

static int per_net = 1;
module_param(per_net, int, S_IRUGO);
MODULE_PARM_DESC(
    per_net, "Enable per-network namespace hook registration (default: 0)\n");

int welcome(void);

/* packet counters */
unsigned long long int in_counter = 0;
unsigned long long int out_counter = 0;
unsigned long long int fwd_counter = 0;
unsigned long long int pre_counter = 0;
unsigned long long int post_counter = 0;

time64_t module_load_time;

/* bad checksum counter for packets received */
unsigned badcsum_cnt_rcv = 0;

struct response iph_in_get_response(struct net *net, struct sk_buff *skb, ipfi_flow *flow,
                                    struct info_flags *flags) {
  struct response response = {};
  flags->direction = flow->direction;
  /* invoke engine function passing the appropriate rule lists */
  if (flow->direction == IPFI_INPUT)
    response = ipfire_filter(net, &in_drop, &in_acc, &fwopts, skb, flow, flags);
  else if (flow->direction == IPFI_OUTPUT)
    response = ipfire_filter(net, &out_drop, &out_acc, &fwopts, skb, flow, flags);
  else if (flow->direction == IPFI_FWD)
    response = ipfire_filter(net, &fwd_drop, &fwd_acc, &fwopts, skb, flow, flags);
  else
    IPFI_PRINTK("IPFIRE: iph_in_get_response(): invalid direction!\n");
  return response;
}

struct nf_hook_ops nfh_pre, nfh_in, nfh_out, nfh_fwd, nfh_post, nfh_defrag_pre,
    nfh_defrag_out;

static int register_ipfire_net(struct net *net);
static void unregister_ipfire_net(struct net *net);

static int ipfire_net_init(struct net *net) {
  IPFI_PRINTK("IPFIRE: Initializing for network namespace %px\n", net);
  init_netl(net);
  return register_ipfire_net(net);
}

static void ipfire_net_exit(struct net *net) {
  IPFI_PRINTK("IPFIRE: Cleaning up for network namespace %px\n", net);
  unregister_ipfire_net(net);
  fini_netl(net);
}

static struct pernet_operations ipfire_net_ops = {
    .init = ipfire_net_init,
    .exit = ipfire_net_exit,
};

/*
 * Global Hook Registration
 *
 * We register our netfilter hooks in the initial network namespace (init_net).
 */

#define KERNEL_MODULE_VERSION "1.99.5"
#define BUILD_DATE _BUILD_DATE
#define BUILD_SYS _BUILD_SYS

int welcome(void) {
  struct timespec64 tv_load_time;
  IPFI_PRINTK("IPFIRE-wall MODULE INITIALIZED [%s] built on %s, %s\n",
              KERNEL_MODULE_VERSION, BUILD_DATE, BUILD_SYS);
  IPFI_PRINTK("Giacomo S. <delleceste@gmail.com>\n");

  /* set loading time into kernel stats struct */
  ktime_get_real_ts64(&tv_load_time);
  module_load_time = tv_load_time.tv_sec;
  IPFI_PRINTK("sizeof(command) = %zu, sizeof(ipfire_rule) = %zu, "
              "sizeof(ipfire_info_t) = %zu\n",
              sizeof(command), sizeof(ipfire_rule), sizeof(ipfire_info_t));
  IPFI_PRINTK("sizeof(struct rcu_head) = %zu, sizeof(struct list_head) = %zu\n",
              sizeof(struct rcu_head), sizeof(struct list_head));

  /* Allocate per-CPU counters */
  ipfi_counters = alloc_percpu(struct ipfi_counters);
  if (!ipfi_counters) {
    IPFI_PRINTK("IPFIRE: failed to allocate per-CPU counters\n");
    return -ENOMEM;
  }

  /* Set default policy and write it in kernel stats */
  init_options(&fwopts);
  set_policy(policy);
  init_kernel_stats(&kstats);
  kstats.policy = default_policy;
  kstats.kmod_load_time = module_load_time;
  if (init_procentry(PROCENT, policy) < 0)
    return -1;
  set_procentry_values();

  /* Initialize ruleset lists before any potential notifier event */
  init_ruleset_heads();

  init_translation();
  init_log();

  init_machine(); /* registers netdevice notifier */
  if (per_net) {
    if (register_pernet_subsys(&ipfire_net_ops) < 0) {
      IPFI_PRINTK("IPFIRE: failed to register pernet subsystem\n");
      return -1;
    }
  } else {
    init_netl(&init_net);
    register_ipfire_net(&init_net);
  }
  return 0;
}

static int __init ini(void) { return welcome(); }

static void __exit fini(void) {
  IPFI_PRINTK("IPFIRE-wall unloading:  \n");

  /* SIGNAL EXIT START */
  WRITE_ONCE(we_are_exiting, true);
  /* net/core/dev.c : synchronizes with packet receive processing.
   * calls might_sleep() and
   * synchronize_rcu()
   */
  synchronize_net();

  /* Stop receiving anything from the network
   */
  if (per_net) {
    unregister_pernet_subsys(&ipfire_net_ops);
  } else {
    unregister_ipfire_net(&init_net);
  }
  IPFI_PRINTK("IPFIRE: Unregistered hooks\n");

  /* will call might_sleep() and rcu_barrier() */
  fini_machine();
  /* will call might_sleep() and rcu_barrier() */
  fini_log();
  /* will call might_sleep() and rcu_barrier() */
  fini_translation();

  /* fini_netl(): just calls sock_release on the netlink socket */
  if (!per_net)
    fini_netl(&init_net);
  clean_proc();

  if (ipfire_wq) {
    destroy_workqueue(ipfire_wq);
    ipfire_wq = NULL;
  }

  if (ipfi_counters)
    free_percpu(ipfi_counters);
}

void set_policy(const char *def_policy) {
  if (strncmp(def_policy, "accept", 6) == 0) {
    kstats.policy = default_policy = IPFI_ACCEPT;
    printk("IPFIRE: default policy: ACCEPT packets which do not match any "
           "rule.\n");
  } else {
    kstats.policy = default_policy = IPFI_DROP;
    printk("IPFIRE: default policy: DROP packets not matching rules.\n");
  }
}

void init_options(struct ipfire_options *opts) {
  memset(opts, 0, sizeof(struct ipfire_options));
  /* by default, users are allowed to insert their rules.
   * Administrator, to avoid users' rules, have to start
   * firewall with option noflush and disabling users */
  opts->user_allowed = 1;
}

// enum nf_ip_hook_priorities {
// 	NF_IP_PRI_FIRST = INT_MIN,
// 	NF_IP_PRI_CONNTRACK_DEFRAG = -400,
// 	NF_IP_PRI_RAW = -300,
// 	NF_IP_PRI_SELINUX_FIRST = -225,
// 	NF_IP_PRI_CONNTRACK = -200,
// 	NF_IP_PRI_MANGLE = -150,
// 	NF_IP_PRI_NAT_DST = -100,
// 	NF_IP_PRI_FILTER = 0,
// 	NF_IP_PRI_SECURITY = 50,
// 	NF_IP_PRI_NAT_SRC = 100,
// 	NF_IP_PRI_SELINUX_LAST = 225,
// 	NF_IP_PRI_CONNTRACK_CONFIRM = INT_MAX,
// 	NF_IP_PRI_LAST = INT_MAX,
// };

/*
 * register_ipfire_net - Initialize and register netfilter hooks for a namespace
 *
 * This function sets up the hook structures (nf_hook_ops) that define our
 * packet processing callbacks, then registers them in the given namespace.
 *
 * Returns: 0 on success, negative error code on failure
 */
static int register_ipfire_net(struct net *net) {
  int ret;

  /* Setup hook structures (using global ops for simplicity if they can be
   * shared)
   * Note: In modern kernels, nf_hook_ops can be shared if they are immutable.
   */
  /* PRE_ROUTING: Defragmentation hook (highest priority) */
  nfh_defrag_pre.pf = PF_INET;
  nfh_defrag_pre.hook = ipfi_defrag;
  nfh_defrag_pre.hooknum = NF_INET_PRE_ROUTING;
  nfh_defrag_pre.priority = NF_IP_PRI_CONNTRACK_DEFRAG;

  /* pre routing */
  nfh_pre.pf = PF_INET;
  nfh_pre.hooknum = NF_IP_PRE_ROUTING;
  nfh_pre.priority = NF_IP_PRI_NAT_DST;
  nfh_pre.hook = process;

  /* input */
  nfh_in.pf = PF_INET;
  nfh_in.hooknum = NF_IP_LOCAL_IN;
  nfh_in.priority = NF_IP_PRI_FILTER;
  nfh_in.hook = process;

  /* forward */
  nfh_fwd.pf = PF_INET;
  nfh_fwd.hooknum = NF_IP_FORWARD;
  nfh_fwd.priority = NF_IP_PRI_FILTER;
  nfh_fwd.hook = process;

  /* output */
  nfh_out.pf = PF_INET;
  nfh_out.hooknum = NF_IP_LOCAL_OUT;
  nfh_out.priority = NF_IP_PRI_FILTER;
  nfh_out.hook = process;

  /* output - defrag */
  nfh_defrag_out.pf = PF_INET;
  nfh_defrag_out.hook = ipfi_defrag;
  nfh_defrag_out.hooknum = NF_INET_LOCAL_OUT;
  nfh_defrag_out.priority = NF_IP_PRI_CONNTRACK_DEFRAG;

  /* post routing */
  nfh_post.pf = PF_INET;
  nfh_post.hooknum = NF_IP_POST_ROUTING;
  nfh_post.priority = NF_IP_PRI_NAT_SRC;
  nfh_post.hook = process;

  /* Register hooks for the given net namespace */
  ret = nf_register_net_hook(net, &nfh_defrag_pre);
  if (ret < 0)
    goto err_defrag_pre;

  ret = nf_register_net_hook(net, &nfh_pre);
  if (ret < 0)
    goto err_pre;

  ret = nf_register_net_hook(net, &nfh_in);
  if (ret < 0)
    goto err_in;

  ret = nf_register_net_hook(net, &nfh_fwd);
  if (ret < 0)
    goto err_fwd;

  ret = nf_register_net_hook(net, &nfh_out);
  if (ret < 0)
    goto err_out;

  ret = nf_register_net_hook(net, &nfh_defrag_out);
  if (ret < 0)
    goto err_defrag_out;

  ret = nf_register_net_hook(net, &nfh_post);
  if (ret < 0)
    goto err_post;

  IPFI_PRINTK("IPFIRE: Registered hooks for net %px\n", net);
  return 0;

  /* Error handling - unregister in reverse order */
err_post:
  nf_unregister_net_hook(net, &nfh_defrag_out);
err_defrag_out:
  nf_unregister_net_hook(net, &nfh_out);
err_out:
  nf_unregister_net_hook(net, &nfh_fwd);
err_fwd:
  nf_unregister_net_hook(net, &nfh_in);
err_in:
  nf_unregister_net_hook(net, &nfh_pre);
err_pre:
  nf_unregister_net_hook(net, &nfh_defrag_pre);
err_defrag_pre:
  return ret;
}

static void unregister_ipfire_net(struct net *net) {
  nf_unregister_net_hook(net, &nfh_post);
  nf_unregister_net_hook(net, &nfh_defrag_out);
  nf_unregister_net_hook(net, &nfh_out);
  nf_unregister_net_hook(net, &nfh_fwd);
  nf_unregister_net_hook(net, &nfh_in);
  nf_unregister_net_hook(net, &nfh_pre);
  nf_unregister_net_hook(net, &nfh_defrag_pre);
}

int check_headers(struct sk_buff *skb) {
  if (pskb_may_pull(skb, sizeof(struct iphdr))) {
    // pskb_may_pull may realloc skb: get a fresh ptr to iphdr
    struct iphdr *ih = ip_hdr(skb);
    unsigned int ihl;
    uint8_t protocol;

    if (ih->ihl < 5 || ih->version != 4) {
      IPFI_PRINTK(
          "ipfire_core: check_headers: invalid ip hdr (ihl %d, version %d)",
          ih->ihl, ih->version);
      return -1;
    }

    ihl = ih->ihl * 4;
    protocol = ih->protocol;

    switch (protocol) {
    case IPPROTO_TCP:
      if (!pskb_may_pull(skb, ihl + sizeof(struct tcphdr)))
        return -1;
      break;
    case IPPROTO_UDP:
      if (!pskb_may_pull(skb, ihl + sizeof(struct udphdr)))
        return -1;
      break;
    case IPPROTO_ICMP:
      if (!pskb_may_pull(skb, ihl + sizeof(struct icmphdr)))
        return -1;
      break;
    case IPPROTO_IGMP:
      if (!pskb_may_pull(skb, ihl + sizeof(struct igmphdr)))
        return -1;
      break;
    case IPPROTO_GRE:
    case IPPROTO_PIM:
      /* protocols only for L2/L3 matching, no further pull needed */
      break;
    default:
      /* other protocols are allowed but not specifically handled here */
      break;
    }
    return 0;
  }
  IPFI_PRINTK("ipfire_core: check_headers: malformed ip hdr");
  return -1;
}

unsigned int process(void *priv, struct sk_buff *skb,
                     const struct nf_hook_state *state) {
  unsigned int hooknum = state->hook;
  const struct net_device *in = state->in;
  const struct net_device *out = state->out;

  unsigned int ret;
  __be32 daddr;
  ipfi_flow flow = {in, out, NODIRECTION};
  // malformed packet or unsupported protocol
  if (check_headers(skb) < 0)
    return NF_DROP;
  bool no_nat = (READ_ONCE(dnatted_entry_counter) == 0 &&
                 READ_ONCE(snatted_entry_counter) == 0) ||
                (fwopts.masquerade == 0 && fwopts.nat == 0);

  switch (hooknum) {
  case NF_IP_PRE_ROUTING:
    IPFI_STAT_INC(pre_rcv); // stats
    if (no_nat)
      return NF_ACCEPT;

    daddr = ip_hdr(skb)->daddr; /* save original destination address */
    flow.direction = IPFI_INPUT_PRE;
    ret = ipfi_pre_process(state->net, skb, &flow);
    if (ret != NF_DROP && ret != NF_STOLEN && daddr != ip_hdr(skb)->daddr) {
      // destination nat applied and destination address changed in pre routing
      dst_release(skb_dst(skb));
      skb_dst_set(skb, NULL);
    }
    return ret;
  case NF_IP_LOCAL_IN:
    IPFI_STAT_INC(in_rcv);
    flow.direction = IPFI_INPUT;
    return ipfi_response(state, skb, &flow);
  case NF_IP_LOCAL_OUT:
    IPFI_STAT_INC(out_rcv);
    flow.direction = IPFI_OUTPUT;
    return ipfi_response(state, skb, &flow);
  case NF_IP_FORWARD:
    IPFI_STAT_INC(fwd_rcv);
    flow.direction = IPFI_FWD;
    return ipfi_response(state, skb, &flow);
  case NF_IP_POST_ROUTING:
    IPFI_STAT_INC(post_rcv);
    if (no_nat)
      return NF_ACCEPT;

    flow.direction = IPFI_OUTPUT_POST;
    return ipfi_post_process(state->net, skb, &flow);
  default:
    return NF_DROP;
  }
  return NF_DROP;
}

void init_kernel_stats(struct kernel_stats *nl_kstats) {
  memset(nl_kstats, 0, sizeof(struct kernel_stats));
}

/* updates sent counter, sends packet to userspace and calls
 * update_kernel_stats()
 */
inline int send_packet_to_userspace_and_update_counters(
    struct net *net, const struct sk_buff *skb, const ipfi_flow *flow,
    const struct response *resp, const struct info_flags *flags) {
  int err = 0;
  struct sk_buff *skb_to_user = NULL;

  skb_to_user = build_info_t_nlmsg(skb, flow, resp, flags, &err);
  if (skb_to_user != NULL) {
    IPFI_STAT_INC(sent_tou);
    if (skb_send_to_user(net, skb_to_user, LISTENER_DATA) < 0) {
      printk("send_packet_to_userspace_and_update_counters skb_send failed\n");
      update_kernel_stats(IPFI_FAILED_NETLINK_USPACE, resp->verdict);
      return -1;
    }
  } else if (skb_to_user == NULL) {
    IPFI_PRINTK("IPFIRE: failed to allocate memory for socket buffer in "
                "send_packet_to_userspace_and_update_counters()\n");
    return -1;
  }
  return 0;
}

int ipfi_pre_process(struct net *net, struct sk_buff *skb, const ipfi_flow *flow) {
  int ret = -1;
  int verdict;
  struct response resp = {};
  struct info_flags flags = {};
  struct ipfire_net *ipfire_net = ipfire_pernet(net);
  flags.direction = flow->direction;
  /* in pre routing we do not do any filtering. In normal cases we will return
   * IPFI_ACCEPT as verdict in this hook. In case of errors instead, we'll
   * return IPFI_DROP, to interrupt packet processing. This happens in case of
   * checksum error in incoming packets or (unprobable) memory allocation
   * errors
   */
  verdict = NF_ACCEPT;
  /* nat and masquerade options disabled: return NF_ACCEPT in pre process */
  if ((fwopts.masquerade == 0) && (fwopts.nat == 0) &&
      READ_ONCE(dnatted_entry_counter) == 0 &&
      READ_ONCE(snatted_entry_counter) == 0) {
    return NF_ACCEPT;
  }

  /* MASQUERADE or NAT are enabled: go on! */

  /* No more kmalloc for ipfire_info_t. We use stack-based flags and response.
   */

  /* No more build_ipfire_info_from_skb or init_packet needed for translation
   * here. Translation functions now take skb and components directly.
   */

  /* if a packet comes back from a dnatted connection,
   * i.e. has been forwarded, we must de dnat it. Dynamic
   * rules are checked in this case.
   */
  if (READ_ONCE(dnatted_entry_counter) > 0) {
    ret = pre_de_dnat(net, skb, flow, &resp, &flags);

    /* implements pre processing of the packets: DNAT.
     * check if we already have a translation for this session
     * (early lookup consolidated here)
     */
    if (ret < 0) {
      struct nat_table *dnt = lookup_nat_forward(net, skb, NAT_DNAT);
      if (dnt != NULL) {
        ret = dest_translate(skb, dnt);
        nat_put(dnt);
      }
    }
  }

  /* dnat_translation() requires direct match with DNAT rules inserted by user.
   */
  if (ret < 0) /* no pre_de_dnat, maybe dnat_translation */
    ret = dnat_translation(net, skb, flow, &resp, &flags);

  /* now let's de-snat, or de-masquerade, if no match has previously succeeded
   */
  if (ret < 0 && READ_ONCE(snatted_entry_counter) > 0)
    ret = pre_de_snat(net, skb, flow, &resp, &flags);

  /* checksum is calculated inside set_pairs_in_skb(), ipfi_translation.c */
  if (ret >= 0) {
    resp.verdict = IPFI_ACCEPT;
    flags.nat = 1;

    /* we send to userspace old packet, to let see how translation changed it,
     * if loguser is greater than 5 */
    if ((ipfire_net->userspace_data_pid) && (loguser_enabled) &&
        (is_to_send(skb, &fwopts, &resp, flow, &flags)))
      send_packet_to_userspace_and_update_counters(net, skb, flow, &resp, &flags);
    else /* not sent because of log level */
      IPFI_STAT_INC(not_sent);
  } else if (ret == BAD_CHECKSUM) {
    if (we_are_exiting) {
      IPFI_STAT_INC(not_sent);
      return NF_DROP;
    }

    IPFI_STAT_INC(bad_checksum_in);
    IPFI_PRINTK(
        "IPFIRE: bad checksum on incoming packet %llu over %llu received.\n",
        this_cpu_read(ipfi_counters->bad_checksum_in),
        this_cpu_read(ipfi_counters->pre_rcv));
    /* send a packet signaling an error */
    send_packet_to_userspace_and_update_counters(net, skb, flow, &resp, &flags);
    verdict = NF_DROP;
  }
  /* No more kfree(packet) needed */
  return verdict;
}

int ipfi_post_process(struct net *net, struct sk_buff *skb, const ipfi_flow *flow) {
  struct response resp = {.verdict = IPFI_ACCEPT};
  struct info_flags flags = {};
  struct ipfire_net *ipfire_net = ipfire_pernet(net);
  flags.direction = flow->direction;
  /* do post routing tasks. Checksumming is performed in set_pairs_in_skb(),
   * the manipulation function inside ipfi_translation.c
   */
  int de_dnat_done = -1, snat_done = -1;

  /* stats. Only one field is to be updated.
   * So don't call update_kernel_stats().
   */
  kstats.post_rcv++;
  /* masquerade and NAT disabled: nothing to do. We accept here */
  if ((fwopts.masquerade == 0) && (fwopts.nat == 0) &&
      READ_ONCE(dnatted_entry_counter) == 0 &&
      READ_ONCE(snatted_entry_counter) == 0)
    return NF_ACCEPT;

  /* No more kmalloc for ipfire_info_t. */

  /* MASQUERADE and SNAT now take components directly. No
   * build_ipfire_info_from_skb needed here. */

  if (READ_ONCE(dnatted_entry_counter) > 0) {
    if ((snat_done = post_snat_dynamic(net, skb, flow, &resp, &flags)) >= 0)
      goto send_touser;

    /* If NAT is enabled, there might be packets that have been destination
     * natted in pre routing phase. Those packets must be de-natted: source
     * address must be put equal to the original destination address of the
     * dnatted packet. We must check if packet has destination address _and_
     * port equal to source address _and_ port of dnatted packet. This happens
     * in the opposite flow with respect to the one that originated
     * communication.
     */
    de_dnat_done = de_dnat_translation(net, skb, flow, &resp, &flags);
  }

  /* check if we already have a translation for this session
   * (early lookup consolidated here, covers both SNAT and Masquerade)
   */
  if (READ_ONCE(snatted_entry_counter) > 0) {
    struct nat_table *snt = lookup_nat_forward(net, skb, NAT_SNAT);
    if (snt != NULL) {
      snat_done = snat_packet(skb, snt);
      nat_put(snt);
      goto send_touser;
    }
  }

  /* masquerade_translation() scans masquerade_post list */
  if ((snat_done = masquerade_translation(net, skb, flow, &resp, &flags)) >= 0)
    goto send_touser;

  /* snat_translation scans translation_post list */
  snat_done = snat_translation(net, skb, flow, &resp, &flags);

send_touser:

  if ((snat_done >= 0) || (de_dnat_done >= 0)) {
    /* No more init_packet or build_ipfire_info_from_skb needed here either.
     * Netlink builder will build from components.
     */
    flags.nat = 1U;

    if (snat_done >= 0)
      flags.snat = 1U;
    // post_packet->flags.snat = 1;

    if ((ipfire_net->userspace_data_pid) && (loguser_enabled) &&
        (is_to_send(skb, &fwopts, &resp, flow, &flags)))
      send_packet_to_userspace_and_update_counters(net, skb, flow, &resp, &flags);
    else /* not sent because of log level */
      kstats.not_sent++;
  }
  /* Don't check for bad checksum on outgoing packets.
   * See netfilter ip_conntrack_proto_tcp.c comment */

  /* checksumming... */
  return NF_ACCEPT;
}

/* The following three functions extract from the socket buffer
 * skb the tcp/udp/icmp header.
 * Since allocate_headers() already extracts the IP header,
 * allocate_headers() itself passes this header to build_xxxh_usermess()
 * for convenience
 */
inline void build_tcph_usermess(const struct tcphdr *tcph,
                                ipfire_info_t *ipfi_info) {
  /* we fill in our userspace information */
  memcpy(&(ipfi_info->packet.transport_header.tcphead), tcph,
         sizeof(struct tcphdr));
}

/* See build_tcph_usermess() above for the comments */
inline void build_udph_usermess(const struct udphdr *p_udphead,
                                ipfire_info_t *ipfi_info) {
  memcpy(&(ipfi_info->packet.transport_header).udphead, p_udphead,
         sizeof(*p_udphead));
}

/* See build_tcph_usermess() above for the comments */
inline void build_icmph_usermess(const struct icmphdr *p_icmphead,
                                 ipfire_info_t *ipfi_info) {
  memcpy(&(ipfi_info->packet.transport_header).icmphead, p_icmphead,
         sizeof(*p_icmphead));
}

/* since version 0.98.7 we support the IGMP protocol */
inline void build_igmph_usermess(const struct igmphdr *p_igmphead,
                                 ipfire_info_t *ipfi_info) {
  memcpy(&(ipfi_info->packet.transport_header).igmphead, p_igmphead,
         sizeof(*p_igmphead));
}

inline int copy_headers(const struct sk_buff *skb, ipfire_info_t *fireinfo) {
  struct iphdr *iph;
  iph = ip_hdr(skb);
  /* protocol information */
  fireinfo->packet.ip.protocol = iph->protocol;
  fireinfo->packet.ip.saddr = iph->saddr;
  fireinfo->packet.ip.daddr = iph->daddr;
  /* internet header */
  /* tcp, udp icmp headers? */
  if (iph->protocol == IPPROTO_TCP)
    build_tcph_usermess((struct tcphdr *)((void *)iph + iph->ihl * 4),
                        fireinfo);
  else if (iph->protocol == IPPROTO_UDP)
    build_udph_usermess((struct udphdr *)((void *)iph + iph->ihl * 4),
                        fireinfo);
  else if (iph->protocol == IPPROTO_ICMP)
    build_icmph_usermess((struct icmphdr *)((void *)iph + iph->ihl * 4),
                         fireinfo);
  else if (iph->protocol == IPPROTO_IGMP)
    build_igmph_usermess((struct igmphdr *)((void *)iph + iph->ihl * 4),
                         fireinfo); /* since 0.98.7 */
  else
    return -1;
  return 0;
}

int ipfi_response(const struct nf_hook_state *state, struct sk_buff *skb,
                  ipfi_flow *flow) {
  struct info_flags flags = {};
  struct net *net = state->net;
  struct ipfire_net *ipfire_net = ipfire_pernet(net);
  struct response res = iph_in_get_response(net, skb, flow, &flags);
  /* decide according to loguser if to send or not feedback */
  if ((ipfire_net->userspace_data_pid) && (loguser_enabled)) {
    if ((is_to_send(skb, &fwopts, &res, flow, &flags) > 0)) {
      int err;
      struct sk_buff *skb_touser =
          build_info_t_nlmsg(skb, flow, &res, &flags, &err);
      if (skb_touser == NULL) /* shouldn't happen :r */
        IPFI_PRINTK("IPFIRE: failed to allocate memory for socket buffer in "
                    "iph_in_get_response()\n");
      else if (skb_send_to_user(net, skb_touser, LISTENER_DATA) < 0)
        update_kernel_stats(IPFI_FAILED_NETLINK_USPACE, res.verdict);
    }

    /* Qt-GUI: if gui_notifier_enabled we send the info if there is no match
     * (popup asking the user the verdict for the new seen packet - if
     * directions are in or out -) OR if there was a rule matching and a
     * notification was requested for tha packets matching _that_ rule.
     */
    if (gui_notifier_enabled &&
        ((res.verdict == IPFI_IMPLICIT && flow->direction != IPFI_FWD) ||
         (res.verdict != IPFI_IMPLICIT && res.notify))) {
      printk("GUI NOTIFIER ENABLED!!\n");
      /* previous socket buffer sent to userspace: the kernel will have freed
       * it... so the pointer skb_touser is no more valid: create a new socket
       * buffer with the same ipfire_info_t contents: this will be sent via
       * the notifier socket.
       */
      int err = 0;
      struct sk_buff *skb_touser =
          build_info_t_nlmsg(skb, flow, &res, &flags, &err);
      if (skb_touser != NULL &&
          skb_send_to_user(net, skb_touser, GUI_NOTIF_DATA) < 0) {
        IPFI_PRINTK("failed to send message to userspace via netlink for net %px: %d\n",
                    net, err);
        update_kernel_stats(IPFI_FAILED_NETLINK_USPACE, res.verdict);
      }
    }

  } else /* packets not sent because of log level */ {
    kstats.not_sent++;
  }

  /* update the sum of the packets processed */
  kstats.sum++;

  if (res.verdict > 0) {
    /* in output direction we can do DNAT, if the packet locally
     * generated is allowed to leave for its destination (i.e. ret > 0).
     * No need to recalculate the header checksum. The work is done inside
     * ipfi_translation: set_pairs_in_skb().
     */
    if (fwopts.nat != 0 && flow->direction == IPFI_OUTPUT) {
      struct nat_table *dnt =
          READ_ONCE(nat_counters[NAT_DNAT]) > 0
              ? lookup_nat_forward(net, skb, NAT_DNAT)
              : NULL;
      int dnat_ret = -1;
      if (dnt != NULL) {
        /*
         * If an existing DNAT entry is found, we use it. We also synchronize
         * the rule_id to ensure the logged message correctly identifies which
         * rule originally caused this translation.
         */
        res.rule_id = dnt->rule_id;
        dnat_ret = dest_translate(skb, dnt);
        nat_put(dnt);
      } else {
        dnat_ret = dnat_translation(net, skb, flow, &res, &flags);
      }

      if (dnat_ret >= 0) {
        flags.nat = 1;

        /*
         * EXHAUSTIVE COMMENT ON RE-ROUTING (OUTPUT DNAT):
         *
         * When a packet's destination IP address is modified in the LOCAL_OUT
         * path (OUTPUT hook), the original routing decision (made by the
         * stack BEFORE the netfilter hooks) becomes stale.
         *
         * If the new destination IP belongs to a different network reachable
         * via a different interface, or if it requires a different gateway,
         * the packet must be re-routed to ensure it reaches its intended
         * destination and that the outgoing interface and source IP (if not
         * fixed) are consistent with the new path.
         *
         * ip_route_me_harder() is the standard Linux kernel function used by
         * Netfilter (e.g., iptables NAT) to perform this re-routing. It
         * re-evaluates the routing table based on the updated skb->nh.iph
         * (network header).
         *
         * Arguments:
         * - state->net: The network namespace context.
         * - state->sk:  The socket associated with the packet (locally
         * generated).
         * - skb:        The packet buffer itself.
         * - RTN_UNSPEC: Address type (unspecified, let the routing engine
         * decide).
         *
         * Failure to call this after DNAT in OUTPUT often leads to kernel
         * panics or silent packet loss because the stack later finds
         * inconsistencies between the skb->dst and the actual packet headers.
         */
        if (ip_route_me_harder(state->net, state->sk, skb, RTN_UNSPEC)) {
          IPFI_PRINTK("IPFIRE: ip_route_me_harder failed after OUTPUT DNAT\n");
          /* If re-routing fails, the packet is in an inconsistent state.
           * We should ideally drop it to avoid further corruption or panics.
           */
          return NF_DROP;
        }

        /*
         * After a successful DNAT translation and re-routing in the OUTPUT
         * path, we send a log message to userspace. This provides visibility
         * into locally generated packets that have been redirected.
         *
         * We use the explicit sequence:
         * 1. build_info_t_nlmsg(): Constructs the netlink message containing
         *    the packet headers and translation flags.
         * 2. skb_send_to_user(): Dispatches the constructed message to the
         *    registered userspace listener.
         */
        if ((ipfire_net->userspace_data_pid) && (loguser_enabled) &&
            (is_to_send(skb, &fwopts, &res, flow, &flags) > 0)) {
          int err;
          struct sk_buff *skb_touser =
              build_info_t_nlmsg(skb, flow, &res, &flags, &err);
          if (skb_touser != NULL) {
            skb_send_to_user(net, skb_touser, LISTENER_DATA);
          } else {
            IPFI_PRINTK(
                "IPFIRE: failed to build log message after OUTPUT DNAT for net %px\n", net);
          }
        }
      } // dnat_ret >= 0
    } // fwopts.nat != 0 and flow->direction == IPFI_OUTPUT
  } // res.verdict > 0

  /* update statistics */
  update_kernel_stats(flow->direction, res.verdict);

  /* Map internal IPFI verdicts to netfilter verdicts:
   * IPFI_ACCEPT (2) -> NF_ACCEPT (1)
   * IPFI_DROP (1) -> NF_DROP (0)
   * IPFI_IMPLICIT (0) -> apply default_policy
   */
  if (res.verdict == IPFI_ACCEPT)
    return NF_ACCEPT;
  else if (res.verdict == IPFI_DROP)
    return NF_DROP;
  else {
    /* IPFI_IMPLICIT: apply default policy */
    if (default_policy == IPFI_ACCEPT)
      return NF_ACCEPT;
    return NF_DROP;
  }
}

/* no more needed since 1.96 */
int recalculate_ip_checksum(struct sk_buff *skb, int direction) {
  int len;
  int datalen;
  int iph_sum_old;
  struct iphdr *iph;
  struct tcphdr *th;
  struct udphdr *uh;

  if (skb == NULL)
    return network_header_null("recalculate_ip_checksum()",
                               "socket buffer NULL");
  len = skb->len;
  iph = ip_hdr(skb);

  datalen = skb->len - iph->ihl * 4;
  iph_sum_old = iph->check;
  iph->check = 0;
  iph->check = ip_fast_csum((u8 *)iph, iph->ihl);

  /* tcp */
  switch (iph->protocol) {
  case IPPROTO_TCP:
    th = (struct tcphdr *)((void *)iph + iph->ihl * 4);
    th->check = 0;
    th->check = tcp_v4_check(datalen, iph->saddr, iph->daddr,
                             skb_checksum(skb, iph->ihl * 4, datalen, 0));
    break;
  case IPPROTO_UDP:
    uh = (struct udphdr *)((void *)iph + iph->ihl * 4);
    uh->check = 0;
    uh->check = udp_v4_check(datalen, iph->saddr, iph->daddr,
                             skb_checksum(skb, iph->ihl * 4, datalen, 0));
    break;
  default:
    break;
  }
  /* see include/skbuff.h: "B.Checksumming on output":
   * CHECKSUM_NONE: skb is checksummed by protocol or csum is not required.
   * If checksum is calculated here, no need to recalculate it. */
  if ((direction == IPFI_OUTPUT) || (direction == IPFI_OUTPUT_POST))
    skb->ip_summed = CHECKSUM_NONE;
  return 0;
}

module_init(ini);
module_exit(fini);
