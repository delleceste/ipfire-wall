#ifndef IPFI_MACHINE_H
#define IPFI_MACHINE_H

/* See ipfi.c for details and
 * use of this software.
 * (C) 2005 Giacomo S.
 */

#include <common/ipfi_structures.h>
#include "globals.h"
#include "helpers/ftp.h"
#include "ipfire.h"
#include "netlink/ipfi_netl.h"
#include <linux/hashtable.h>
#include <linux/jhash.h>
#include <linux/timer.h>

#include "../filter/state/state_check.h"
#include "../filter/state/state_machine.h"
#include "../filter/state/state_table.h"
#include "../filter/state/state_timeout.h"

#ifndef STATE_HASH_BITS
#define STATE_HASH_BITS 12 /* default: override via make STATE_HASH_BITS=N */
#endif

/* ftp passive support */
#define FTP_NONE 0     /* not an ftp rule */
#define FTP_LOOK_FOR 1 /* look for port and ip */
#define FTP_DEFINED 2  /* port and ip determined */
/* after first packet is accepted going out, source port is corrected
 * and since then ftp becomes FTP_ESTABLISHED and all subsequent
 * checks will involve also source port. In FTP_DEFINED state in fact,
 * source port is not checked */
#define FTP_ESTABLISHED 3

extern struct workqueue_struct *ipfire_wq;

struct state {
  __u8 reverse : 1, notify : 1, unused : 6;
  struct state_t state;
};

/* Prototypes for main filtering logic types */
#include "../filter/filter_engine.h"
#include "../filter/rule_match.h"

/* DEAD CODE REMOVED: fill_table_with_name, fill_packet_with_name,
 * fill_packet_with_table_rulename, ixmp_match, transport_state_match */

#endif
