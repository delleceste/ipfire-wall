/* packet_flow_trace.c
 *
 * This file is a synthesized trace of the IPFire kernel module's packet flow logic.
 * It consolidates functions from multiple files to demonstrate the path of a packet
 * entering the firewall, hitting a permission rule, and creating a state table entry.
 *
 * Source files involved:
 * - kernel/ipfire.c
 * - kernel/filter/filter_engine.c
 * - kernel/filter/rule_match.c
 * - kernel/filter/state/state_check.c
 * - kernel/filter/state/state_machine.c
 * - kernel/filter/state/state_table.c
 */

#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

/* --- FROM kernel/ipfire.c --- */

/* Main hook function */
unsigned int process(void *priv, struct sk_buff *skb,
                     const struct nf_hook_state *state) {
  unsigned int hooknum = state->hook;
  const struct net_device *in = state->in;
  const struct net_device *out = state->out;
  ipfi_flow flow = {in, out, NODIRECTION};

  if (check_headers(skb) < 0)
    return NF_DROP;

  switch (hooknum) {
  case NF_IP_LOCAL_IN: /* INPUT chain */
    flow.direction = IPFI_INPUT;
    return ipfi_response(state, skb, &flow);
  case NF_IP_LOCAL_OUT: /* OUTPUT chain */
    flow.direction = IPFI_OUTPUT;
    return ipfi_response(state, skb, &flow);
  case NF_IP_FORWARD: /* FORWARD chain */
    flow.direction = IPFI_FWD;
    return ipfi_response(state, skb, &flow);
  /* PRE_ROUTING and POST_ROUTING (NAT) omitted for brevity as per request focus (filtering/state) */
  default:
    return NF_DROP;
  }
}

int ipfi_response(const struct nf_hook_state *state, struct sk_buff *skb,
                  ipfi_flow *flow) {
  struct info_flags flags = {};
  struct response res = iph_in_get_response(skb, flow, &flags);
  /* ... logging logic omitted ... */
  return res.verdict == IPFI_ACCEPT ? NF_ACCEPT : NF_DROP;
}

struct response iph_in_get_response(struct sk_buff *skb, ipfi_flow *flow,
                                    struct info_flags *flags) {
  struct response response = {};
  flags->direction = flow->direction;
  /* invoke engine function passing the appropriate rule lists */
  if (flow->direction == IPFI_INPUT)
    response = ipfire_filter(&in_drop, &in_acc, &fwopts, skb, flow, flags);
  else if (flow->direction == IPFI_OUTPUT)
    response = ipfire_filter(&out_drop, &out_acc, &fwopts, skb, flow, flags);
  else if (flow->direction == IPFI_FWD)
    response = ipfire_filter(&fwd_drop, &fwd_acc, &fwopts, skb, flow, flags);
  return response;
}

/* --- FROM kernel/filter/filter_engine.c --- */

struct response ipfire_filter(const ipfire_rule *dropped,
                              const ipfire_rule *allowed,
                              const struct ipfire_options *ipfi_opts,
                              struct sk_buff *skb, const ipfi_flow *flow,
                              struct info_flags *flags) {
    struct response response = { .verdict = IPFI_IMPLICIT };
    ipfire_rule *rule;
    short pass = 0, drop = 0, res;
    struct state_table *newtable = NULL;
    struct iphdr *iph = ip_hdr(skb);

    /* 1. Check existing state */
    {
        __u8 ftp_tmp = flags->ftp;
        response = check_state(skb, flow, &ftp_tmp);
        flags->ftp = ftp_tmp;
    }
    if (response.verdict > 0) { /* State match found */
        response.state = 1U;
        return response;
    }

    /* 2. Check DROP rules */
    rcu_read_lock();
    list_for_each_entry_rcu(rule, &dropped->list, list) {
        /* ... Match logic (direction, device, ip, proto) ... */
        /* If match: check specific protocol filters */
        if ((res = ip_layer_filter(iph, rule, flow->direction, flow->in, flow->out)) > 0) {
             /* Protocol specific filters omitted for brevity, essentially same as below */
             drop = 1;
        }
        
        if (drop) {
            response.verdict = IPFI_DROP;
            rcu_read_unlock();
            return response;
        }
    }

    /* 3. Check ALLOW rules */
    list_for_each_entry_rcu(rule, &allowed->list, list) {
        if ((res = direction_filter(flow->direction, rule)) < 0) goto next_pass_rule;
        if ((res = device_filter(rule, flow->in, flow->out)) < 0) goto next_pass_rule;
        if ((res = ip_layer_filter(iph, rule, flow->direction, flow->in, flow->out)) < 0) goto next_pass_rule;

        /* Protocol specific matches */
        if (iph->protocol == IPPROTO_TCP) {
            struct tcphdr *th = (struct tcphdr *)((void *)iph + iph->ihl * 4);
            if (ipfi_tcp_filter(th, rule) < 0) goto next_pass_rule;
        } 
        /* UDP/ICMP logic similar ... */

        /* Rule Matched! */
        pass = 1;
        response.verdict = IPFI_ACCEPT;

        /* 4. Create State Entry if Stateful */
        if ((rule->state || ipfi_opts->all_stateful) && ipfi_opts->state) {
             newtable = keep_state(skb, rule, flow);
             response.state = 1U;
        }
        
        rcu_read_unlock();
        if (newtable != NULL) {
            add_state_table_to_list(newtable);
        }
        return response;

next_pass_rule:;
    }
    rcu_read_unlock();
    return response;
}

/* --- FROM kernel/filter/state/state_check.c --- */

struct response check_state(struct sk_buff *skb, const ipfi_flow *flow,
                            __u8 *ftp_state) {
  struct state_table *table_entry = NULL;
  struct response ret = { .verdict = IPFI_IMPLICIT };
  short reverse = 0;

  rcu_read_lock_bh();
  list_for_each_entry_rcu(table_entry, &state_list, lnode) {
    if (skb_matches_state_table(skb, table_entry, &reverse, flow) > 0) {
      /* Match found! */
      ret.verdict = IPFI_ACCEPT;
      ret.st.state = set_state(skb, table_entry, reverse); /* Update machine state */
      ret.state = 1U;
      
      update_timer_of_state_entry(table_entry); /* Refresh timeout */
      rcu_read_unlock_bh();
      return ret;
    }
  }
  rcu_read_unlock_bh();
  return ret;
}

/* --- FROM kernel/filter/rule_match.c --- */

int ip_layer_filter(const struct iphdr *iph, const ipfire_rule* r, int direction,
                    const struct net_device *in, const struct net_device *out)
{
    int match = 0;
    if ((match = address_match(iph, r, direction, in, out)) < 0) return -1;
    
    if (r->nflags.proto && r->ip.protocol != iph->protocol) return -1;
    /* ... other IP checks ... */
    
    return 1;
}

int address_match(const struct iphdr * iph, const ipfire_rule * r,
                  int direction, const struct net_device *in, const struct net_device *out)
{
    /* Simplified logic: return 1 if src/dst match rule, -1 otherwise */
    /* Checks against single IPs, intervals, exclusions, etc. */
    /* ... implementation calls get_dev_ifaddr if MYADDR is used ... */
    return 1; /* Assume match for trace purposes */
}

/* --- FROM kernel/filter/state/state_machine.c --- */

struct state_table *keep_state(const struct sk_buff *skb, const ipfire_rule *p_rule,
                               const ipfi_flow *flow) {
    struct state_table *state_t = kmalloc(sizeof(struct state_table), GFP_ATOMIC);
    memset(state_t, 0, sizeof(struct state_table));
    
    fill_net_table_fields(state_t, skb, flow); /* Fill 5-tuple from packet */
    set_state(skb, state_t, 0); /* Initialize state (e.g., SYN_SENT) */
    
    return state_t;
}

int set_state(const struct sk_buff* skb, struct state_table *entry, short reverse)
{
    int state = state_machine(skb, entry->state.state, reverse);
    entry->state.state = state;
    return state;
}

int state_machine(const struct sk_buff *skb, int current_state, short reverse)
{
    /* TCP State Transition Logic */
    /* Calculates new state based on flags (SYN, ACK, FIN, RST) and current state */
    /* e.g., if NOSTATE + SYN -> return SYN_SENT */
    /* e.g., if SYN_SENT + SYN/ACK (reversed) -> return SYN_RECV */
    /* ... logic omitted ... */
    return ESTABLISHED; /* placeholder */
}

/* --- FROM kernel/filter/state/state_table.c --- */

int add_state_table_to_list(struct state_table *newtable) {
  spin_lock_bh(&state_list_lock);
  
  fill_timer_table_fields(newtable); /* Setup timeout timer */
  add_timer(&newtable->timer_statelist);
  list_add_rcu(&newtable->lnode, &state_list); /* Add to global list */
  
  state_tables_counter++;
  spin_unlock_bh(&state_list_lock);
  return 0;
}

int skb_matches_state_table(const struct sk_buff *skb, const struct state_table *entry, 
                            short *reverse, const ipfi_flow *flow) {
    /* Check protocol, then 5-tuple (src/dst IP, src/dst Port) */
    /* Match direct: */
    if (direct_state_match(skb, entry, flow) > 0) {
        *reverse = 0;
        return 1;
    }
    /* Match reverse (reply): */
    else if (reverse_state_match(skb, entry, flow) > 0) {
        *reverse = 1;
        return 1;
    }
    return -1;
}
