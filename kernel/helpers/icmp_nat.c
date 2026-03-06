/*
 * nat/icmp_nat.c: ICMP NAT Logic
 */

#include "icmp_nat.h"
#include "../../filter/state/state_table.h"
#include "../ipfi_machine.h"
#include "../ipfire.h"
#include "../nat/nat.h"
#include "../nat/nat_table.h"
#include <linux/icmp.h>
#include <linux/ip.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <linux/udp.h>
#include <net/checksum.h>
#include <net/ip.h>

/* Helper to safely get the inner IPv4 header and the start of the inner L4
 * header */
static int get_inner_headers(const struct sk_buff *skb,
                             struct iphdr **inner_iph, void **inner_l4h) {
  struct iphdr *iph = ip_hdr(skb);
  struct icmphdr *icmph;
  int ihl = iph->ihl * 4;

  /* Ensure we have the ICMP header */
  if (!pskb_may_pull((struct sk_buff *)skb, ihl + sizeof(struct icmphdr)))
    return -1;

  icmph = (struct icmphdr *)((void *)iph + ihl);

  /* Check if it's an ICMP error type */
  if (icmph->type != ICMP_DEST_UNREACH && icmph->type != ICMP_TIME_EXCEEDED &&
      icmph->type != ICMP_PARAMETERPROB)
    return -1;

  /* The inner IP header starts after the ICMP header (8 bytes) */
  if (!pskb_may_pull((struct sk_buff *)skb,
                     ihl + sizeof(struct icmphdr) + sizeof(struct iphdr)))
    return -1;

  /* Recompute pointers after potential pull */
  iph = ip_hdr(skb);
  *inner_iph = (struct iphdr *)((void *)iph + ihl + sizeof(struct icmphdr));

  /* Ensure we have enough of the inner L4 header (at least 8 bytes for ports)
   */
  if (!pskb_may_pull((struct sk_buff *)skb,
                     ihl + sizeof(struct icmphdr) + (*inner_iph)->ihl * 4 + 8))
    return -1;

  /* Recompute pointers */
  iph = ip_hdr(skb);
  *inner_iph = (struct iphdr *)((void *)iph + ihl + sizeof(struct icmphdr));
  *inner_l4h = (void *)(*inner_iph) + (*inner_iph)->ihl * 4;

  return 0;
}

static void recompute_icmp_checksum(struct sk_buff *skb,
                                    struct icmphdr *icmph) {
  unsigned int icmp_off = (unsigned char *)icmph - skb->data;
  unsigned int icmp_len = skb->len - icmp_off;

  icmph->checksum = 0;
  icmph->checksum = csum_fold(skb_checksum(skb, icmp_off, icmp_len, 0));
}

/*
 * icmp_nat_process: Handle NAT translation for ICMP error packets.
 * This function translates the outer IP header and the embedded inner headers
 * to correctly route an ICMP error packet across the NAT.
 */
int icmp_nat_process(struct sk_buff *skb, unsigned int hooknum) {
  struct iphdr *outer_iph, *inner_iph;
  struct icmphdr *icmph;
  void *inner_l4h;
  net_quadruplet inner_quad;
  u32 key;
  unsigned int bkt;
  struct nat_table *nt = NULL;
  enum nat_type n_type;
  int ret = -1;
  u8 inner_proto;

  if (!skb || !(skb))
    return -1;

  /* We only process IPv4 ICMP packets here */
  if (ip_hdr(skb)->protocol != IPPROTO_ICMP)
    return -1;

  if (get_inner_headers(skb, &inner_iph, &inner_l4h) < 0)
    return -1;

  outer_iph = ip_hdr(skb);
  icmph = (struct icmphdr *)((void *)outer_iph + outer_iph->ihl * 4);

  /* Extract the inner network quadruplet.
   * Note: The inner packet represents the ORIGINAL traffic that caused the
   * error.
   */
  memset(&inner_quad, 0, sizeof(inner_quad));
  inner_quad.saddr = inner_iph->saddr;
  inner_quad.daddr = inner_iph->daddr;
  inner_quad.valid = 1;
  /* Capture the inner protocol early to prevent TOCTOU drift */
  inner_proto = inner_iph->protocol;

  if (inner_proto == IPPROTO_TCP) {
    struct tcphdr *th = (struct tcphdr *)inner_l4h;
    inner_quad.sport = th->source;
    inner_quad.dport = th->dest;
  } else if (inner_proto == IPPROTO_UDP) {
    struct udphdr *uh = (struct udphdr *)inner_l4h;
    inner_quad.sport = uh->source;
    inner_quad.dport = uh->dest;
  } else {
    /* We only handle ICMP errors for TCP/UDP inner payloads right now */
    IPFI_PRINTK("ipfire: icmp_nat: inner proto %u not supported\n",
                inner_proto);
    return -1;
  }

  // IPFI_PRINTK("ipfire: icmp_nat: inner quad s=%pI4:%u d=%pI4:%u prot=%u\n",
  //             &inner_quad.saddr, ntohs(inner_quad.sport), &inner_quad.daddr,
  //             ntohs(inner_quad.dport), inner_proto);

  /*
   * Look up the inner tuple in the NAT tables.
   * The inner packet corresponds to the POSTNAT index because the original
   * packet has ALREADY been translated before it caused the error downstream.
   */
  key = get_nat_tuple_hash(inner_quad.saddr, inner_quad.sport, inner_quad.daddr,
                           inner_quad.dport, inner_proto);
  bkt = key & ((1 << NAT_HASH_BITS) - 1);

  rcu_read_lock_bh();

  /* Try DNAT ORIG index using hash_for_each_rcu since the inner_quad hash key
   * doesn't match the client IP hashed in NAT_IDX_ORIG.
   */
  n_type = NAT_DNAT;
  {
    unsigned int iter_bkt;
    hash_for_each_rcu(nat_hashtables[n_type][NAT_IDX_ORIG], iter_bkt, nt,
                      h.hnode) {
      if (nt->protocol == inner_proto) {
        /* Define IP Terminology for DNAT:
         * A  = Client (Original Source)       -> nt->old_saddr
         * B  = Firewall Public IP             -> nt->old_daddr
         * B' = Firewall Masq/Local IP         -> nt->our_ifaddr (if SNAT'd too)
         * C  = DNAT Server (Internal Target)  -> nt->new_addr
         *
         * Expected inner packet (the original packet that hit the error):
         * expected_saddr is A (if pure DNAT) or B' (if DNAT + Masquerade).
         */
        __be32 expected_saddr = nt->our_ifaddr ? nt->our_ifaddr : nt->old_saddr;

        /* Match Case 1: Error generated by FORWARD-direction traffic.
         * "Forward" means the traffic was flowing Client A -> Server C.
         * Server C received A's packet, rejected it, and sent an ICMP error
         * back. The Inner Quad is that original packet sent TO Server C: Src =
         * expected_saddr (A or B') Dst = nt->new_addr (C)
         */
        if (inner_quad.saddr == expected_saddr &&
            inner_quad.sport == nt->old_sport &&
            inner_quad.daddr == nt->new_addr &&
            inner_quad.dport == nt->new_port) {
          if (nat_hold_rcu(nt)) {
            goto match_found;
          }
        }
        /* Match Case 2: Error generated by REVERSE-direction traffic.
         * "Reverse" means the traffic was flowing Server C -> Client A.
         * Client A (or the firewall B) received C's response, rejected it,
         * and sent an ICMP error back to C.
         * The Inner Quad is that original packet sent FROM Server C:
         *   Src = nt->new_addr (C)
         *   Dst = expected_saddr (A or B')
         */
        if (inner_quad.saddr == nt->new_addr &&
            inner_quad.sport == nt->new_port &&
            inner_quad.daddr == expected_saddr &&
            inner_quad.dport == nt->old_sport) {
          if (nat_hold_rcu(nt)) {
            goto match_found;
          }
        }
        /* Match Case 3: DNAT forward direction in POST_ROUTING.
         * The PRE_ROUTING hook already completely translated the inner packet
         * back to its original pre-NAT state (A -> B).
         * Inner Quad is now:
         *   Src = nt->old_saddr (A)
         *   Dst = nt->old_daddr (B)
         */
        if (hooknum == NF_INET_POST_ROUTING &&
            inner_quad.saddr == nt->old_saddr &&
            inner_quad.sport == nt->old_sport &&
            inner_quad.daddr == nt->old_daddr &&
            inner_quad.dport == nt->old_dport) {
          if (nat_hold_rcu(nt)) {
            goto match_found;
          }
        }
      }
    }
  }

  /* Try SNAT POSTNAT index */
  n_type = NAT_SNAT;
  hlist_for_each_entry_rcu(nt, &nat_hashtables[n_type][NAT_IDX_POSTNAT][bkt],
                           h_indices[NAT_IDX_POSTNAT - 1]) {
    if (nt->protocol == inner_proto) {
      /* Define IP Terminology for SNAT:
       * A  = Client (Original Source)       -> nt->old_saddr
       * B  = Firewall Public IP             -> nt->old_daddr
       * B' = Firewall Masq/Local IP         -> nt->our_ifaddr or nt->new_addr
       * C  = Remote Server                  -> nt->old_daddr
       *
       * Match Case: SNAT forward direction (client A to server C).
       * Server C generated the ICMP error back to B'.
       * Inner Quad is the packet sent TO Server C (post-SNAT):
       *   Src = expected_saddr (B', the translated source)
       *   Dst = nt->old_daddr (C)
       */
      __be32 expected_saddr = nt->our_ifaddr ? nt->our_ifaddr : nt->new_addr;
      if (inner_quad.saddr == expected_saddr &&
          inner_quad.sport == nt->new_port &&
          inner_quad.daddr == nt->old_daddr &&
          inner_quad.dport == nt->old_dport) {
        if (nat_hold_rcu(nt)) {
          goto match_found;
        }
      }
    }
  }

  rcu_read_unlock_bh();
  return -1; /* No translation matched */

match_found:
  rcu_read_unlock_bh();
  /*
   * It is safe to copy fields into locals after rcu_read_unlock_bh()
   * because we held a reference count via nat_hold_rcu() inside the
   * critical section. The memory won't be freed, and these 5-tuple
   * fields are immutable once initialized.
   */
  __be32 nt_old_saddr = nt->old_saddr;
  __be32 nt_old_daddr = nt->old_daddr;
  __be32 nt_new_addr = nt->new_addr;
  __be16 nt_old_sport = nt->old_sport;
  __be16 nt_old_dport = nt->old_dport;
  __be16 nt_new_port = nt->new_port;
  enum nat_type nt_type = nt->type;
  __be32 nt_our_ifaddr = nt->our_ifaddr;

  /* We must ensure skb is writable before making modifications.
   * Only need it up to the end of the inner L4 header we plan to modify.
   * Note: 'needed' is an offset from skb->data, so it implicitly covers
   * all outer headers (IP and ICMP).
   */
  unsigned int needed = (unsigned char *)inner_l4h - skb->data;
  if (inner_proto == IPPROTO_TCP)
    needed += sizeof(struct tcphdr);
  else if (inner_proto == IPPROTO_UDP)
    needed += sizeof(struct udphdr);

  if (skb_ensure_writable(skb, needed)) {
    if (net_ratelimit())
      printk(KERN_DEBUG
             "ipfire: icmp_nat: skb_ensure_writable failed (needed %u)\n",
             needed);
    nat_put(nt);
    return -1;
  }

  /* Re-fetch pointers after skb_ensure_writable */
  outer_iph = ip_hdr(skb);
  icmph = (struct icmphdr *)((void *)outer_iph + outer_iph->ihl * 4);
  inner_iph = (struct iphdr *)((void *)icmph + sizeof(struct icmphdr));
  inner_l4h = (void *)inner_iph + inner_iph->ihl * 4;

  /* Defensive TOCTOU check: ensure the protocol hasn't been modified
   * concurrently by another packet processor before the skb was linearized */
  if (unlikely(inner_iph->protocol != inner_proto ||
               inner_proto != nt->protocol)) {
    if (net_ratelimit())
      printk(KERN_WARNING "ipfire: icmp_nat: inner protocol drift detected!\n");
    nat_put(nt);
    return -1;
  }

  /*
   * For NF_IP_PRE_ROUTING, the error is coming from the outside returning
   * inside. For NF_IP_POST_ROUTING, the error is generated inside returning
   * outside.
   */
  if (hooknum == NF_INET_PRE_ROUTING) {
    if (nt_type == NAT_SNAT) {
      /*
       * SNAT PREROUTING: Error coming back from external host (reply to SNAT
       * client). Outer destination and Inner source must change from
       * `new_addr` (or `our_ifaddr` for masquerading) to `old_saddr`.
       * Inner source port must change from `new_port` to `old_sport`.
       */
      __be32 new_ip = nt_old_saddr;
      __be32 old_ip = inner_iph->saddr;
      __be16 new_port = nt_old_sport;
      __be16 old_port = inner_quad.sport;

      /* 1. Modify outer destination IP */
      csum_replace4(&outer_iph->check, outer_iph->daddr, new_ip);
      outer_iph->daddr = new_ip;

      /* 2. Modify inner source address */
      csum_replace4(&inner_iph->check, old_ip, new_ip);
      inner_iph->saddr = new_ip;

      /* Update inner L4 checksum for pseudo-header IP change */
      if (inner_proto == IPPROTO_TCP) {
        struct tcphdr *th = (struct tcphdr *)inner_l4h;
        inet_proto_csum_replace4(&th->check, skb, old_ip, new_ip, true);
      } else {
        struct udphdr *uh = (struct udphdr *)inner_l4h;
        if (uh->check)
          inet_proto_csum_replace4(&uh->check, skb, old_ip, new_ip, true);
      }

      /* 3. Modify inner source port */
      if (old_port != new_port) {
        if (inner_proto == IPPROTO_TCP) {
          struct tcphdr *th = (struct tcphdr *)inner_l4h;
          inet_proto_csum_replace2(&th->check, skb, old_port, new_port, false);
          th->source = new_port;
        } else {
          struct udphdr *uh = (struct udphdr *)inner_l4h;
          if (uh->check)
            inet_proto_csum_replace2(&uh->check, skb, old_port, new_port,
                                     false);
          uh->source = new_port;
        }
      }
      ret = 1;

    } else if (nt_type == NAT_DNAT) {
      /*
       * DNAT PREROUTING: ICMP error from/to a DNATed destination.
       */
      if (inner_quad.daddr == nt_new_addr) {
        /*
         * DNAT Forward direction error (Client A to Server C).
         * Inner Quad is the packet sent TO Server C.
         * We must reverse the DNAT (and any SNAT/masquerade) on the OUTER Dst
         * and on all INNER headers.
         *
         * We use inner_quad.daddr (= C) as the match key, NOT
         * outer_iph->daddr (= B', the masquerade addr). The inner packet
         * is the post-NAT original that reached the server; its destination
         * is C = nt_new_addr. The outer destination is the masq addr (B'),
         * which is unrelated to the NAT entry's new_addr.
         *
         * Ideally the outer Src after translation should be B (the firewall's
         * public address), because A thinks it was talking to B. However,
         * changing the outer Src to B (a local IP) causes the kernel's
         * fib_validate_source to reject the packet as a martian source (a
         * local address arriving on the external interface). Therefore we
         * leave the outer Src as C (the server that generated the error).
         * This is the same behaviour as iptables DNAT + MASQUERADE.
         *
         * IP Terminology:
         * A  = Client (Original Source)       = nt_old_saddr
         * B  = Firewall Public IP             = nt_old_daddr
         * B' = Firewall Masq/Local IP         = nt_our_ifaddr /
         * inner_iph->saddr C  = DNAT Server (Internal Target)  = nt_new_addr
         *
         * As seen on the wire (arriving on firewall):
         *   Outer IP: Src=C (server .49)  Dst=B' (masq addr .245)
         *   Inner IP: Src=B' (masq .245)  Dst=C  (server .49)
         *
         * After translation (forwarded to original client A):
         *   Outer IP: Src=C (.49, UNCHANGED - see above)  Dst=A (client .25)
         *   Inner IP: Src=A (client .25)   Dst=B (firewall public .245)
         */
        __be32 old_inner_s = inner_iph->saddr; /* B' (masq IP) or A (client) */
        __be32 new_inner_s = nt_old_saddr;     /* A  (original client) */
        __be32 old_inner_d = inner_iph->daddr; /* C  (DNAT target server) */
        __be32 new_inner_d = nt_old_daddr; /* B  (public FW, pre-DNAT dst) */

        __be16 old_inner_sp = inner_quad.sport;
        __be16 new_inner_sp = nt_old_sport;
        __be16 old_inner_dp = inner_quad.dport;
        __be16 new_inner_dp = nt_old_dport;

        /* 1. Fix Outer Dst: B' -> A
         *    Outer Src (C) is NOT changed — keep server as sender. */
        csum_replace4(&outer_iph->check, outer_iph->daddr, new_inner_s);
        outer_iph->daddr = new_inner_s;

        /* 2. Fix Inner IP Headers */
        /* Inner Src: B' -> A */
        csum_replace4(&inner_iph->check, old_inner_s, new_inner_s);
        inner_iph->saddr = new_inner_s;
        /* Inner Dst: C -> B */
        csum_replace4(&inner_iph->check, old_inner_d, new_inner_d);
        inner_iph->daddr = new_inner_d;

        /* 3. Fix Inner L4 Header (pseudo-header + port updates) */
        if (inner_proto == IPPROTO_TCP) {
          struct tcphdr *th = (struct tcphdr *)inner_l4h;
          inet_proto_csum_replace4(&th->check, skb, old_inner_s, new_inner_s,
                                   true);
          inet_proto_csum_replace4(&th->check, skb, old_inner_d, new_inner_d,
                                   true);
          if (old_inner_sp != new_inner_sp) {
            inet_proto_csum_replace2(&th->check, skb, old_inner_sp,
                                     new_inner_sp, false);
            th->source = new_inner_sp;
          }
          if (old_inner_dp != new_inner_dp) {
            inet_proto_csum_replace2(&th->check, skb, old_inner_dp,
                                     new_inner_dp, false);
            th->dest = new_inner_dp;
          }
        } else {
          struct udphdr *uh = (struct udphdr *)inner_l4h;
          if (uh->check) {
            inet_proto_csum_replace4(&uh->check, skb, old_inner_s, new_inner_s,
                                     true);
            inet_proto_csum_replace4(&uh->check, skb, old_inner_d, new_inner_d,
                                     true);
            if (old_inner_sp != new_inner_sp)
              inet_proto_csum_replace2(&uh->check, skb, old_inner_sp,
                                       new_inner_sp, false);
            if (old_inner_dp != new_inner_dp)
              inet_proto_csum_replace2(&uh->check, skb, old_inner_dp,
                                       new_inner_dp, false);
          }
          uh->source = new_inner_sp;
          uh->dest = new_inner_dp;
        }
        ret = 1;

      } else if (inner_quad.saddr == nt_new_addr) {
        /*
         * DNAT Reverse direction error (Server C to Client A).
         * Inner Quad is the packet sent FROM Server C.
         * The router or A generated an ICMP error back to C.
         * Only the source needs to be un-DNAT-ed: C -> B (or B').
         *
         * IP Terminology:
         * A  = Client (Original Source)       = nt_old_saddr
         * B  = Firewall Public IP             = nt_old_daddr
         * C  = DNAT Server (Internal Target)  = nt_new_addr
         *
         * Here, the ICMP error is going TO C, meaning outer Dst=C.
         * Inner packet was C -> A. So inner Src=C.
         * We need to change inner Src from C -> B to match the original
         * packet as it left the firewall.
         */
        __be32 new_ip = nt_old_daddr;     /* B (public FW) */
        __be32 old_ip = inner_iph->saddr; /* C (server) */
        __be16 new_port = nt_old_dport;
        __be16 old_port = inner_quad.sport;

        csum_replace4(&outer_iph->check, outer_iph->saddr, new_ip);
        outer_iph->saddr = new_ip;

        csum_replace4(&inner_iph->check, old_ip, new_ip);
        inner_iph->saddr = new_ip;
        if (inner_proto == IPPROTO_TCP) {
          struct tcphdr *th = (struct tcphdr *)inner_l4h;
          inet_proto_csum_replace4(&th->check, skb, old_ip, new_ip, true);
        } else {
          struct udphdr *uh = (struct udphdr *)inner_l4h;
          if (uh->check)
            inet_proto_csum_replace4(&uh->check, skb, old_ip, new_ip, true);
        }

        if (old_port != new_port) {
          if (inner_proto == IPPROTO_TCP) {
            struct tcphdr *th = (struct tcphdr *)inner_l4h;
            inet_proto_csum_replace2(&th->check, skb, old_port, new_port,
                                     false);
            th->source = new_port;
          } else {
            struct udphdr *uh = (struct udphdr *)inner_l4h;
            if (uh->check)
              inet_proto_csum_replace2(&uh->check, skb, old_port, new_port,
                                       false);
            uh->source = new_port;
          }
        }
        ret = 1;
      }
    }
  } else if (hooknum == NF_INET_POST_ROUTING) {
    if (nt_type == NAT_DNAT) {
      if (inner_quad.saddr == nt_old_saddr &&
          inner_quad.sport == nt_old_sport &&
          inner_quad.daddr == nt_old_daddr &&
          inner_quad.dport == nt_old_dport) {
        /*
         * DNAT POST_ROUTING Forward direction (Client A to Server C).
         * This ICMP error was already partially translated in PRE_ROUTING.
         * The inner headers are already de-NATed back to original (Src=A,
         * Dst=B). Outer Dst was already changed to A.
         *
         * IP Terminology:
         * A  = Client (Original Source)       = nt_old_saddr
         * B  = Firewall Public IP             = nt_old_daddr
         * C  = DNAT Server (Internal Target)  = nt_new_addr
         *
         * Now we only need to change the outer Src from C (.49, the real
         * server) to B (.245, the firewall's public address), so client A
         * sees the ICMP as coming from B — the address it thinks it is
         * talking to.
         *
         * This Cannot be done in PRE_ROUTING because B is a local IP of the
         * incoming interface (martian source algorithm drops it). Here in
         * POST_ROUTING, the packet is going OUT to A, so setting Src=B is valid
         * (masquerade-like).
         */
        __be32 old_src = outer_iph->saddr; /* C (server, .49) */
        __be32 new_src = nt_old_daddr;     /* B (firewall public, .245) */
        csum_replace4(&outer_iph->check, old_src, new_src);
        outer_iph->saddr = new_src;
        ret = 1;
      } else {
        /*
         * DNAT POSTROUTING Reverse direction (Server C to Client A).
         * Error generated internally returning to external client A.
         *
         * IP Terminology:
         * A  = Client (Original Source)       = nt_old_saddr
         * B  = Firewall Public IP             = nt_old_daddr
         * B' = Firewall Masq/Local IP         = nt_our_ifaddr
         * C  = DNAT Server (Internal Target)  = nt_new_addr
         *
         * Outer source must change from C (server IP) back to B (or B').
         * Inner destination must change from C to B (or B').
         * Inner destination port must change from new_port to old_dport.
         */
        __be32 new_ip =
            (nt_our_ifaddr) ? nt_our_ifaddr : nt_old_daddr; /* B' or B */
        __be32 old_ip = inner_iph->daddr;                   /* C */
        __be16 new_port = nt_old_dport;
        __be16 old_port = inner_quad.dport;

        /* 1. Modify outer source IP */
        csum_replace4(&outer_iph->check, outer_iph->saddr, new_ip);
        outer_iph->saddr = new_ip;

        /* 2. Modify inner destination address */
        csum_replace4(&inner_iph->check, old_ip, new_ip);
        inner_iph->daddr = new_ip;

        if (inner_proto == IPPROTO_TCP) {
          struct tcphdr *th = (struct tcphdr *)inner_l4h;
          inet_proto_csum_replace4(&th->check, skb, old_ip, new_ip, true);
        } else {
          struct udphdr *uh = (struct udphdr *)inner_l4h;
          if (uh->check)
            inet_proto_csum_replace4(&uh->check, skb, old_ip, new_ip, true);
        }

        /* 3. Modify inner destination port */
        if (old_port != new_port) {
          if (inner_proto == IPPROTO_TCP) {
            struct tcphdr *th = (struct tcphdr *)inner_l4h;
            inet_proto_csum_replace2(&th->check, skb, old_port, new_port,
                                     false);
            th->dest = new_port;
          } else {
            struct udphdr *uh = (struct udphdr *)inner_l4h;
            if (uh->check)
              inet_proto_csum_replace2(&uh->check, skb, old_port, new_port,
                                       false);
            uh->dest = new_port;
          }
        }
        ret = 1;
      }
    } else if (nt_type == NAT_SNAT) {
      /*
       * SNAT (or Masquerade) POSTROUTING Forward direction Error.
       * Error generated internally (by the firewall itself) returning to A.
       *
       * IP Terminology:
       * A  = Client (Original Source)       = nt_old_saddr
       * B  = Firewall Public IP             = nt_old_daddr
       * B' = Firewall Masq/Local IP         = nt_our_ifaddr or nt_new_addr
       * C  = Remote Server                  = nt_old_daddr
       */
      if (inner_quad.saddr == nt_old_saddr) {
        __be32 new_ip = nt_our_ifaddr ? nt_our_ifaddr : nt_new_addr; /* B' */
        __be32 old_ip = inner_iph->saddr;                            /* A */
        __be16 new_port = nt_new_port;
        __be16 old_port = inner_quad.sport;

        csum_replace4(&outer_iph->check, outer_iph->saddr, new_ip);
        outer_iph->saddr = new_ip;

        csum_replace4(&inner_iph->check, old_ip, new_ip);
        inner_iph->saddr = new_ip;
        if (inner_proto == IPPROTO_TCP) {
          struct tcphdr *th = (struct tcphdr *)inner_l4h;
          inet_proto_csum_replace4(&th->check, skb, old_ip, new_ip, true);
        } else {
          struct udphdr *uh = (struct udphdr *)inner_l4h;
          if (uh->check)
            inet_proto_csum_replace4(&uh->check, skb, old_ip, new_ip, true);
        }

        if (old_port != new_port) {
          if (inner_proto == IPPROTO_TCP) {
            struct tcphdr *th = (struct tcphdr *)inner_l4h;
            inet_proto_csum_replace2(&th->check, skb, old_port, new_port,
                                     false);
            th->source = new_port;
          } else {
            struct udphdr *uh = (struct udphdr *)inner_l4h;
            if (uh->check)
              inet_proto_csum_replace2(&uh->check, skb, old_port, new_port,
                                       false);
            uh->source = new_port;
          }
        }
        ret = 1;
      }
    }
  }

  if (ret == 1) {
    /* Recompute full ICMP checksum since inner packet changed */
    recompute_icmp_checksum(skb, icmph);

    /* Update the timer for the session tracking the error */
    nt->state = state_machine(skb, nt->state, 0);
    ipfi_entry_update_timer(&nt->h, nt->protocol, nt->state);
  }

  nat_put(nt);
  return ret;
}

/* Matches ICMP error payload against a state entry */
int match_icmp_error_payload(const struct sk_buff *skb,
                             const struct state_table *entry, short *reverse) {
  struct iphdr *iph;
  struct icmphdr *icmph;
  struct iphdr *inner_iph;
  void *inner_l4h;
  net_quadruplet inner_quad;
  u8 inner_proto;

  if (!skb || !entry || !reverse)
    return -1;

  iph = ip_hdr(skb);
  if (iph->protocol != IPPROTO_ICMP)
    return -1;

  icmph = (struct icmphdr *)((void *)iph + iph->ihl * 4);
  if (icmph->type == ICMP_DEST_UNREACH || icmph->type == ICMP_TIME_EXCEEDED ||
      icmph->type == ICMP_PARAMETERPROB) {

    if (get_inner_headers(skb, &inner_iph, &inner_l4h) < 0)
      return -1;

    memset(&inner_quad, 0, sizeof(inner_quad));
    inner_quad.saddr = inner_iph->saddr;
    inner_quad.daddr = inner_iph->daddr;
    inner_proto = inner_iph->protocol;

    if (inner_proto == IPPROTO_TCP) {
      struct tcphdr *th = (struct tcphdr *)inner_l4h;
      inner_quad.sport = th->source;
      inner_quad.dport = th->dest;
    } else if (inner_proto == IPPROTO_UDP) {
      struct udphdr *uh = (struct udphdr *)inner_l4h;
      inner_quad.sport = uh->source;
      inner_quad.dport = uh->dest;
    } else {
      return -1;
    }

    if (inner_proto == entry->protocol) {
      /* Direct match of the inner packet */
      if (inner_quad.saddr == entry->saddr &&
          inner_quad.daddr == entry->daddr &&
          inner_quad.sport == entry->sport &&
          inner_quad.dport == entry->dport) {
        *reverse = 0;
        return 1;
      }
      /* Reverse match of the inner packet */
      if (inner_quad.saddr == entry->daddr &&
          inner_quad.daddr == entry->saddr &&
          inner_quad.sport == entry->dport &&
          inner_quad.dport == entry->sport) {
        *reverse = 1;
        return 1;
      }
    }
  }
  return -1;
}

/* Hashes the inner IP payload of an ICMP error for state table lookups */
int get_icmp_inner_hash(const struct sk_buff *skb, u32 *hash_key) {
  struct iphdr *iph;
  struct icmphdr *icmph;
  struct iphdr *inner_iph;
  void *inner_l4h;
  u8 inner_proto;
  u16 sport = 0, dport = 0;

  if (!skb || !hash_key)
    return -1;

  iph = ip_hdr(skb);
  if (iph->protocol != IPPROTO_ICMP)
    return -1;

  icmph = (struct icmphdr *)((void *)iph + iph->ihl * 4);
  if (icmph->type == ICMP_DEST_UNREACH || icmph->type == ICMP_TIME_EXCEEDED ||
      icmph->type == ICMP_PARAMETERPROB) {

    if (get_inner_headers(skb, &inner_iph, &inner_l4h) < 0)
      return -1;

    inner_proto = inner_iph->protocol;

    if (inner_proto == IPPROTO_TCP) {
      struct tcphdr *th = (struct tcphdr *)inner_l4h;
      sport = th->source;
      dport = th->dest;
    } else if (inner_proto == IPPROTO_UDP) {
      struct udphdr *uh = (struct udphdr *)inner_l4h;
      sport = uh->source;
      dport = uh->dest;
    } else {
      return -1;
    }

    *hash_key = get_state_hash(inner_iph->saddr, inner_iph->daddr, sport, dport,
                               inner_proto);
    return 0;
  }
  return -1;
}
