/* filter/state/state_check.c: State checking logic for ipfire-wall */

#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include "ipfi.h"
#include "ipfi_machine.h"
#include "ipfi_state_machine.h"
#include "ipfi_ftp.h"
#include "globals.h"

struct response check_state(struct sk_buff* skb, const ipfi_flow *flow, __u8 *ftp_state)
{
    struct state_table *table_entry=NULL, *new_ftp_entry=NULL;
    struct response ret = {};
    short reverse = 0;
    struct iphdr *iph = ip_hdr(skb);
    __u16 sport = 0, dport = 0;
    u32 key;

    if (!iph) return ret;

    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *th = (struct tcphdr *)((void *)iph + iph->ihl * 4);
        sport = th->source;
        dport = th->dest;
    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *uh = (struct udphdr *)((void *)iph + iph->ihl * 4);
        sport = uh->source;
        dport = uh->dest;
    }

    key = get_state_hash(iph->saddr, iph->daddr, sport, dport, iph->protocol);

    rcu_read_lock_bh();

    hash_for_each_possible_rcu(state_hashtable, table_entry, hnode, key)
    {
        printk("check_state sport %d dport %d -> key %d\n", ntohs(sport), ntohs(dport), key);
        if (skb_matches_state_table(skb, table_entry, &reverse, flow) > 0)
        {
            ret.verdict = IPFI_ACCEPT;
            ret.notify = table_entry->notify;
            ret.st.reverse = reverse;
            ret.st.state = set_state(skb, table_entry, reverse);
            ret.state = 1U;
            
            if( (table_entry->ftp == FTP_LOOK_FOR) && (table_entry->protocol == IPPROTO_TCP) )
            {
                new_ftp_entry = ftp_support(table_entry, skb);
                if(new_ftp_entry != NULL) {
                    if (lookup_state_table_n_update_timer(new_ftp_entry, NOLOCK)  != NULL) {
                        kfree(new_ftp_entry);
                    }
                    else
                    {
                        add_ftp_dynamic_rule(new_ftp_entry);
                    }
                }
            }
            else if(table_entry->ftp == FTP_DEFINED)
            {
                table_entry->ftp = FTP_ESTABLISHED;
                struct tcphdr *th = (struct tcphdr *)((void *)iph + iph->ihl * 4);
                table_entry->sport = th->source;
            }
            update_timer_of_state_entry(table_entry);
            rcu_read_unlock_bh();
            ret.rule_id = table_entry->rule_id;
            if (ftp_state)
                *ftp_state = table_entry->ftp;
            return ret;
        }
        else
            printk("no match in tables\n");
    }
    rcu_read_unlock_bh();
    return ret;
}
