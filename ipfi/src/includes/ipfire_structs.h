#ifndef IPFIRE_STRUCTS_H
#define IPFIRE_STRUCTS_H

#include <sys/socket.h>
#include "list.h"
#include "build.h" /* For compilation date and system type */
#include <sys/types.h>
#include <linux/types.h>
#include <asm/types.h> /* for "__u8" et al */
#include <stddef.h>
#include <pwd.h>
#include <time.h>

/* Need to define this here. Not available from
 * linux/rcupdate.h.
 */
struct rcu_head {
	struct rcu_head *next;
	void (*func)(struct rcu_head *head);
};

#define u8 	__u8
#define u16 	__u16
#define u32 	__u32

#include <common/defs/ipfi_structures.h>

/* max length of file names */
#define MAXFILENAMELEN 60
#define MAXLINELEN 			512
#define MAXFILTERLINELEN 		1024
#define MAXPIPESIZEMESS			MAXFILTERLINELEN + 128


#define PWD_FIELDS_LEN	64
/* len of a log line */
#define LOGLINELEN			200

#define USERNAME 		0
#define HOMEDIR 			1

#define CFGDIR_CREAT			1
#define CFGDIR_CREAT_FAILED		(-1)
#define CFGDIR_MIGRATED			2
#define CFGDIR_MIGRATED_FAILED		(-2)
#define SHARE_CFGDIR_MISSING		(-3)
#define CFGDIR_UPTODATE			0
#define CFGDIR_BOTH			10


/* for module loading */
#define MODULENAME "ipfi"

#ifndef PROC_SYS_MODPROBE
#define PROC_SYS_MODPROBE "/proc/sys/kernel/modprobe"
#endif
#define PROC_MODULES "/proc/modules"

#define USERFIRENAME "IPFIRE"

#define DESCRIPTION "Userspace IPFIREwall program. Command line interface."
#define USPACE_BUILD_SYS 		_BUILD_SYS
#define USPACE_BUILD_DATE 	_BUILD_DATE

#define SHARE_CFGDIR "/usr/share/ipfire/config/IPFIRE"

typedef struct
{
	short int command;
	short int decision;
	unsigned long long id;
	unsigned short direction;
}response;

/* Remember to change this struct also inside utils.c */
typedef struct
{
        ipfire_rule *rule;
	struct state_t stat;
        /* fields to compare */
        __u32  position:1, device:1, indevice:1, outdevice:1, nat:1, masquerade:1,
        snat:1, dnat:1, policy:1, protocol:1, tcp:1, udp:1,
        icmp:1, direction:1, in:1, out:1, fwd:1, pre:1, post:1,
	port:1, ip:1, /* match ip or port, without distinguishing between src or dst */
 	/* NOTE: added igmp support */
        state:1, stateless:1, sip:1, dip:1, sport:1, dport:1, igmp:1, other:4;

	__u16 setup:1, setupok:1, est:1, finwait:1, closewait:1, lastack:1, closed:1, 
		timewait:1, free:8;

}ipfire_rule_filter;
/* loguser, from ipfi.h: 
                 if loguser >= 2  implicit denial is sent back;
                 if loguser >= 4 implicit and explicit denial;
                 if loguser >= 5 all filtering is sent back;
                 if loguser >= 6 filtering and pre/post stuff is sent.
                 commands in do_control are always sent back: loguser
                 then decides to print or not information. To have information
                 printed on commands received _at_startup_ loguser
                 must be 7.
 */
 /* loglevel
    if loglevel > 3 printk of rule added in manage_rule() 
    (ipfi_netl.c );  
    if loglevel > 2 printk of command received in do_control
    (ipfi_netl.c);
  */

/* struct containing options passed by command line */
struct cmdopts 
{
			u16 noflush_on_exit:1,
			 kloglevel:3,
			 loguser:3,
			 quiet:1,
			 user_allowed:1,
			 daemonize:1,
			 quiet_daemonize:1,
			 all_stateful:1, /* not used */
			 other:3;
};

struct userspace_opts
{
	char permission_filename[MAXFILENAMELEN];
	char blacklist_filename[MAXFILENAMELEN];
	char translation_filename[MAXFILENAMELEN];
	char options_filename[MAXFILENAMELEN];
	char blacksites_filename[MAXFILENAMELEN];
	char mailer_options_filename[MAXFILENAMELEN];
	char language_filename[MAXFILENAMELEN];
	short loglevel;
	short clearlog;
	short justload;
	short flush;
	short rmmod;
	short resolv_services;
	short dns_resolver;
	short mail;
	unsigned int mail_time;
	short rc; /* causes little amount of printing at startup */
	int dns_refresh; /* in seconds, refresh interval */
	char logfile_name[MAXFILENAMELEN];
	unsigned proc_rmem_default, proc_rmem_max;
	short int policy; /* 0 default, drop, > 0 accept */
};

/* used to detect missing packets */
struct netlink_stats
{
	unsigned long long in_rcv;
	unsigned long long out_rcv;
	unsigned long long pre_rcv;
	unsigned long long post_rcv;
	unsigned long long fwd_rcv;
	unsigned long long last_in_rcv;
	unsigned long long last_out_rcv;
	unsigned long long last_pre_rcv;
	unsigned long long last_post_rcv;
	unsigned long long last_fwd_rcv;
	unsigned long long sum_now;
	unsigned long long total_lost;
	unsigned long long last_rcv;
	unsigned long long lost;
	unsigned int not_sent_nor_lost;
	/* % of packets lost over sum_now */
	float percentage;
	short direction_now; /* INPUT, OUTPUT... */
	long long int difference; 
};

/* a servent structure a bit littler: we are not
 * interested in alias */
struct ipfire_servent
{
	unsigned last:1;
	char    s_name[16];        /* official service name */
    int     	s_port;         /* port number */
    char    s_proto[5];       /* protocol to use */
};

#endif
