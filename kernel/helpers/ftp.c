/* ip firewall Giacomo S.
 * Passive ftp support module */

/***************************************************************************
 *  Copyright  2005  Giacomo
 *  jacum@libero.it
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
/* see ipfi.c for details */

#include "helpers/ftp.h"
#include "../filter/state/state_table.h"
#include "globals.h"
#include "ipfi_machine.h"
#include "ipfire.h"
#include "netlink/ipfi_netl.h"
#include <linux/list.h>
#include <linux/module.h>

#define FTPBUF 256
#define CLEANEDBUF 128

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Giacomo S. <jacum@libero.it>");
MODULE_DESCRIPTION("Passive FTP support module");

/* Removed thread-unsafe global: char ftp_buffer[FTPBUF]; */

/* returns 1 if a new entry is added, 0 if the skb data do not
 * contain ftp 227 information about ip and port,
 * -1 if an error occurs
 * Comes from:
 * -iph_in_get_response();
 * - ipfire_filter();
 * - check_state();
 * skb already checked in ipfi_response() against `NULL' value
 */
struct state_table *ftp_support(struct state_table *tentry,
                                const struct sk_buff *skb) {
  char ftp_buffer[FTPBUF];
  return packet_contains_ftp_params(skb, tentry, ftp_buffer);
}

/* if skb data contain ftp address and port, allocate and return the new entry
 * to be added to the dynamic tables list */
struct state_table *
packet_contains_ftp_params(const struct sk_buff *skb,
                           const struct state_table *orig_entry,
                           char *ftp_buffer) {
  struct state_table *newt = NULL;
  if (data_start_with_227(skb, ftp_buffer) > 0)
    newt = get_params_and_alloc_newentry(orig_entry, ftp_buffer);
  return newt;
}

/* just inspect if skb contains 227 command  ("Entering passive mode").
 * Handles multi-response segments: when FTP commands are pipelined (e.g.
 * USER/PASS/PASV/QUIT sent at once), the server may reply with several
 * response lines concatenated in a single TCP segment.  We must search for
 * the "227" line anywhere in the payload, not just at byte 0.
 *
 * On success, ftp_buffer contains ONLY the "227 ...(A,B,C,D,p,q)\r\n" line
 * (subsequent lines are stripped) so that check_buf / get_ftpaddr_and_port
 * can parse it correctly.
 */
int data_start_with_227(const struct sk_buff *skb, char *ftp_buffer) {
  unsigned int dataoff, datalen;
  char *data_ptr;
  char *p, *eol;
  struct tcphdr *th;
  struct iphdr *iph;

  iph = ip_hdr(skb);

  /* a packet arrives here if protocol is TCP, see check_state() */
  th = (struct tcphdr *)((void *)iph + iph->ihl * 4);
  dataoff = iph->ihl * 4 + th->doff * 4;
  /* If there is no data in the buffer, return -1 */
  if (dataoff >= skb->len)
    return -1;
  datalen = skb->len - dataoff;

  if (datalen > FTPBUF - 1)
    datalen = FTPBUF - 1;

  data_ptr = skb_header_pointer(skb, dataoff, datalen, ftp_buffer);

  if (data_ptr == NULL) {
    IPFI_PRINTK("IPFIRE: fb_ptr NULL! (ipfi_ftp.c)\n");
    return -1;
  }

  if (data_ptr != ftp_buffer)
    memcpy(ftp_buffer, data_ptr, datalen);

  ftp_buffer[datalen] = '\0';

  /* 227 ( ) A,B,C,D,p,q -> minimal string representing a 227 command */
  if (datalen < 16)
    return 0;

  /* Search for "227" at the start of any response line.
   * FTP response lines are delimited by \r\n, so a mid-buffer 227 is
   * always preceded by \n (or it is at position 0). */
  p = ftp_buffer;
  while ((p = strstr(p, "227")) != NULL) {
    /* Accept if it's at position 0 or preceded by \n */
    if (p == ftp_buffer || *(p - 1) == '\n') {
      /* Isolate this single line: find the \n that ends it */
      eol = strchr(p, '\n');
      if (eol) {
        *(eol + 1) = '\0'; /* keep the \n, remove whatever follows */
      }
      /* Now move the 227 line to the start of ftp_buffer */
      if (p != ftp_buffer)
        memmove(ftp_buffer, p, strlen(p) + 1);

      IPFI_PRINTK("IPFIRE FTP: found 227 line: %s", ftp_buffer);
      return 1;
    }
    p++; /* advance past this non-matching "227" occurrence */
  }
  return 0;
}

/* returns a new kmallocated struct state_table. It is the copy of the
 * original ftp table, with the new address and port.
 * _Remember_ to initialize a new timer and to add the rule at the tail
 * of the list in the calling function. */
struct state_table *
get_params_and_alloc_newentry(const struct state_table *orig,
                              char *ftp_buffer) {
  ftp_info ftpi;
  struct state_table *newt = NULL;
  ftpi = get_ftpaddr_and_port(ftp_buffer);

  if (ftpi.valid) {
    newt = (struct state_table *)kmem_cache_alloc(state_cache, GFP_ATOMIC);
    if (!newt) {
      IPFI_PRINTK("failed to allocate space for the ftp state table!\n");
      return NULL;
    }
    /* to start, copy old table into new one */
    memset(newt, 0, sizeof(struct state_table));
    refcount_set(&newt->h.refcnt, 1);
    newt->saddr = orig->saddr;
    newt->sport = 0; /* Client data connection uses unknown ephemeral port */
    newt->direction = orig->direction;
    newt->notify = orig->notify;
    newt->admin = orig->admin;
    newt->protocol = orig->protocol;
    newt->h.status = orig->h.status;
    if (orig->in_devname[0]) {
      strncpy(newt->in_devname, orig->in_devname, IFNAMSIZ - 1);
      newt->in_devname[IFNAMSIZ - 1] = '\0';
    }
    if (orig->out_devname[0]) {
      strncpy(newt->out_devname, orig->out_devname, IFNAMSIZ - 1);
      newt->out_devname[IFNAMSIZ - 1] = '\0';
    }
    newt->state = orig->state;
    newt->daddr = ftpi.ftp_addr;
    newt->dport = ftpi.ftp_port;
    newt->ftp = FTP_DEFINED;
    newt->rule_id = orig->rule_id;
    newt->related = 1;
  }
  /* return the new allocated state table or NULL */
  return newt;
}

/* checks a bit of syntax in buffer related to 227 command.
 * Note: some FTP servers append characters after ')' before \r\n, e.g.:
 *   227 Entering Passive Mode (85,188,1,133,213,231).\r\n
 * so we search backwards for ')' rather than requiring it at a fixed offset. */
inline int check_buf(const char *ftpcmd) {
  int len = strlen(ftpcmd);
  int j;
  unsigned i = 0;
  unsigned commas = 0, parenthesis = 0;
  if (len - 3 < 0 || len > FTPBUF)
    return -1;
  if (ftpcmd[len - 1] != '\n')
    return -1;
  if (ftpcmd[len - 2] != '\r')
    return -1;
  /* Search backwards from \r for ')'; allow trailing chars like '.' */
  for (j = len - 3; j >= 0; j--) {
    if (ftpcmd[j] == ')')
      break;
  }
  if (j < 0)
    return -1;
  for (i = 0; i < len && i < FTPBUF; i++) {
    if (ftpcmd[i] == ',')
      commas++;
    else if (ftpcmd[i] == '(')
      parenthesis++;
  }
  if ((commas != 5) || (parenthesis != 1))
    return -1;

  return 1;
}

/* takes ftp string and fills in integers representing ip and port */
int clean_ftp_command(char *cleaned, char *ftp_buffer) {
  unsigned i = 0, j = 0;

  if (check_buf(ftp_buffer) < 0) {
    IPFI_PRINTK("IPFIRE: bad format for 227 ftp command: \"%s\"\n", ftp_buffer);
    return -1;
  }

  while ((i < FTPBUF) && (ftp_buffer[i] != '\0') && (ftp_buffer[i] != '('))
    i++;
  /* reached '(', ftp_buffer[i] points to '(' */
  i++; /* pass '(' */
  while ((i < FTPBUF) && (j < CLEANEDBUF - 1) && (ftp_buffer[i] != '\0') &&
         (ftp_buffer[i] != ')')) {
    cleaned[j] = ftp_buffer[i];
    i++;
    j++;
  }
  cleaned[j] = '\0'; /* Terminate string */

  return 1;
}

/* inspects skb data and retrieves ftp address and port.
 * returns a structure of type ftp_info, which has the flag valid
 * set to 1 if it is valid, 0 if something failed. The caller must
 * check against the valid flag.
 */
ftp_info get_ftpaddr_and_port(char *ftp_buffer) {
  ftp_info ftpi, invalid_ftpinfo;
  char cleaned[CLEANEDBUF];
  __u8 a1, a2, a3, a4, p1, p2;
  __u32 n = 0, m = 0, o = 0;

  memset(&ftpi, 0, sizeof(ftp_info));
  memset(&invalid_ftpinfo, 0, sizeof(invalid_ftpinfo));

  /* validate the ftp_info aimed at containing a valid result */
  ftpi.valid = 1;

  if (clean_ftp_command(cleaned, ftp_buffer) < 0) {
    IPFI_PRINTK("IPFIRE: error cleaning ftp buffer!\n");
    return invalid_ftpinfo;
  }

  if (sscanf(cleaned, "%hhu,%hhu,%hhu,%hhu,%hhu,%hhu", &a1, &a2, &a3, &a4, &p1,
             &p2) != 6) {
    IPFI_PRINTK("IPFIRE: sscanf failed on cleaned buffer: %s\n", cleaned);
    return invalid_ftpinfo;
  }
  /* compute address */
  ftpi.ftp_addr = a4;
  n = a1;
  n = n << 24;
  m = a2;
  m = m << 16;
  o = a3;
  o = o << 8;
  ftpi.ftp_addr = ftpi.ftp_addr + n + m + o;
  ftpi.ftp_addr = htonl(ftpi.ftp_addr);
  /* port */
  n = p1;
  n = n << 8;
  ftpi.ftp_port = p2 + n;
  ftpi.ftp_port = htons(ftpi.ftp_port);

  IPFI_PRINTK("IPFIRE FTP: Parsed PASV response: IP %pI4, Port %u\n",
              &ftpi.ftp_addr, ntohs(ftpi.ftp_port));

  return ftpi;
}

/*
 * rehash_ftp_expectation — one-shot optimisation for FTP passive data flows.
 *
 * When a passive-mode FTP 227 response is parsed, we create an expectation
 * entry with sport=0 (wildcard) because the client's ephemeral data port is
 * unknown at that point.  This entry is hashed into the sport=0 bucket.
 *
 * On the first data-connection packet, lookup_ftp_expectation() finds the
 * entry via the sport=0 bucket (secondary lookup).  The caller may then
 * invoke this function to:
 *   1. Fill in the real client source port (new_sport).
 *   2. Move the entry from the sport=0 bucket to the correct 5-tuple bucket.
 *   3. Set ftp = FTP_ESTABLISHED so subsequent packets hit the normal O(1)
 *      hash path and bypass the secondary lookup entirely.
 *
 * This is purely an optimisation — without it, every data packet would go
 * through the secondary lookup, which is still correct but O(bucket_size)
 * per packet.  For FTP traffic volumes, either approach is acceptable.
 *
 * Lock ordering: when two distinct buckets must be locked, the lower-numbered
 * bucket is always locked first to prevent AB-BA deadlocks.
 *
 * NOT WIRED UP YET — call site needs to be added once the caller decides
 * to use this optimisation.
 */
void rehash_ftp_expectation(struct state_table *entry, __be16 new_sport) {
  __u32 old_key = get_state_hash(entry->saddr, entry->daddr, 0, entry->dport,
                                 entry->protocol);
  /* MUST use hash_min() — same function as
   * hash_add_rcu/hash_for_each_possible_rcu */
  unsigned int old_bkt = hash_min(old_key, STATE_HASH_BITS);

  __u32 new_key = get_state_hash(entry->saddr, entry->daddr, new_sport,
                                 entry->dport, entry->protocol);
  unsigned int new_bkt = hash_min(new_key, STATE_HASH_BITS);

  if (old_bkt == new_bkt) {
    spin_lock_bh(&state_bucket_locks[old_bkt]);
    entry->sport = new_sport;
    entry->ftp = FTP_ESTABLISHED;
    spin_unlock_bh(&state_bucket_locks[old_bkt]);
  } else {
    /* Lock ordering to prevent deadlocks */
    if (old_bkt < new_bkt) {
      spin_lock_bh(&state_bucket_locks[old_bkt]);
      spin_lock_bh(&state_bucket_locks[new_bkt]);
    } else {
      spin_lock_bh(&state_bucket_locks[new_bkt]);
      spin_lock_bh(&state_bucket_locks[old_bkt]);
    }

    hlist_del_rcu(&entry->h.hnode);
    entry->sport = new_sport;
    entry->ftp = FTP_ESTABLISHED;
    hash_add_rcu(state_hashtable, &entry->h.hnode, new_key);

    if (old_bkt < new_bkt) {
      spin_unlock_bh(&state_bucket_locks[new_bkt]);
      spin_unlock_bh(&state_bucket_locks[old_bkt]);
    } else {
      spin_unlock_bh(&state_bucket_locks[old_bkt]);
      spin_unlock_bh(&state_bucket_locks[new_bkt]);
    }
  }
}

/*
 * lookup_ftp_expectation — secondary hash lookup for FTP passive data flows.
 *
 * The FTP helper creates expectation entries with sport=0 (wildcard) because
 * the client's ephemeral source port is unknown when parsing the 227 response.
 * These entries live in the hash bucket keyed by:
 *   get_state_hash(client_ip, server_data_ip, 0, server_data_port, TCP)
 *
 * For passive FTP, the client opens the data connection to the server:
 *   src = client_ip : client_ephemeral   (sport of the outgoing SYN)
 *   dst = server_data_ip : server_data_port  (dport of the outgoing SYN)
 *
 * So we probe the hash with dport (= server data port), which matches
 * the expectation's stored dport.  The sport wildcard (0) is handled
 * inside direct_state_match() when ftp == FTP_DEFINED.
 *
 * Must be called under rcu_read_lock_bh().
 *
 * Returns the matched state_table entry, or NULL if no expectation matches.
 */
struct state_table *lookup_ftp_expectation(const struct sk_buff *skb,
                                           const struct iphdr *iph,
                                           __be16 sport, __be16 dport,
                                           short *reverse,
                                           const ipfi_flow *flow) {
  struct state_table *table_entry;
  /* Probe with sport=0 (wildcard) and the server data port as dport.
   * MUST use hash_for_each_possible_rcu — it internally applies hash_min()
   * (golden-ratio multiplicative hash) to map the key to a bucket, which is
   * the same function that hash_add_rcu used when storing the entry.
   * A manual "key & mask" bitmask computes a DIFFERENT bucket! */
  __u32 ftp_key = get_state_hash(iph->saddr, iph->daddr, 0, dport, IPPROTO_TCP);

  hash_for_each_possible_rcu(state_hashtable, table_entry, h.hnode, ftp_key) {
    if (table_entry->ftp == FTP_DEFINED) {
      if (skb_matches_state_table(skb, table_entry, reverse, iph, sport, dport,
                                  flow) > 0)
        return table_entry;
    }
  }
  return NULL;
}
