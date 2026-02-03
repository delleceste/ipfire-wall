#ifndef IPFI_STRUCTURES_H
#define IPFI_STRUCTURES_H



//#warning ("\033[1;31mKERNEL MODE includes linux/tcp.h, user includes netinet/tcp.h\033[0m")
#ifdef __KERNEL__
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/time64.h>
#include <linux/types.h>
#include <linux/igmp.h>
#include <linux/netlink.h>
#include <linux/netdevice.h>
#else
#include <netinet/tcp.h>
#include <linux/udp.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/igmp.h>
#include <linux/netlink.h>
#include <linux/netdevice.h>
#endif

//#include <linux/in.h>

/* return values from function processing received data */
enum ipfire_response
{
    /* functions in kernel space will always return DROP or ACCEPT.
  * The value IPFI_IMPLICIT is sent back to userspace to inform
  * the user that no matching rule was found in the list
  */
    IPFI_IMPLICIT = -1,
    /* IPFI_DROP,  equivalent to NF_DROP from linux/netfilter.h: do not continue to process the packet and deallocate it */
    IPFI_DROP = 0,
    IPFI_ACCEPT, /* from linux/netfilter.h, equivalent to NF_ACCEPT */
    /* from IPFI_ACCEPT on, use include/linux/netfilter.h  `responses from hook functions' definitions */
};

enum flow_direction
{
    NODIRECTION = 0,
    IPFI_INPUT_PRE,
    IPFI_INPUT,
    IPFI_OUTPUT,
    IPFI_OUTPUT_POST,
    IPFI_FWD,
};

/* rule policy */
enum policy
{
    DENIAL= 0,
    ACCEPT,
    TRANSLATION,
    BLACKSITE,
};

enum { SOURCE =0, DEST, SOURCE_NAT, DEST_NAT };

enum { INDEV = 0, OUTDEV };

enum mssopts { NOP = 0, MSS_VALUE, ADJUST_MSS_TO_PMTU };

/* connection states */
enum connstates {
    IPFI_NOSTATE = 0,
    NULL_FLAGS,
    INVALID_FLAGS,
    INVALID_STATE,
    SYN_SENT,
    SYN_RECV, /* SYN/ACK received */
    ESTABLISHED,
    FIN_WAIT, /* FIN packet seen */
    CLOSE_WAIT,  /* ACK seen (after FIN) */
    LAST_ACK,   /* FIN seen (after FIN) */
    IPFI_TIME_WAIT,  /* last ack seen */
    CLOSED, /* connection closed */
    GUESS_ESTABLISHED ,
    NOTCP,
    UDP_NEW ,
    UDP_ESTAB ,
    UDP_UNKNOWN,
    ICMP_STATE ,
    IGMP_STATE,
    GRE_STATE,
    PIM_STATE, /* pim protocol */
    GUESS_CLOSING,
    GUESS_SYN_RECV,
    FTP_NEW
};

/* available command values */
enum command_options
{
    OPTIONS = 0,
    ADDRULE,
    DELRULE,
    PRINT_RULES,
    FLUSH_RULES,
    PRINT_STATE_TABLE,
    IPFIRE_BUSY,
    RULE_ALREADY_PRESENT,
    PRINT_FINISHED,
    ROOT_NOFLUSHED,
    FLUSH_PERMISSION_RULES,
    FLUSH_DENIAL_RULES,
    FLUSH_TRANSLATION_RULES,
    KSTATS_REQUEST,
    HELLO,
    STOP_LOGUSER,
    START_LOGUSER,
    IS_LOGUSER_ENABLED,
    KSTRUCT_SIZES,
    KSTATS_LIGHT_REQUEST,
    /* a rule is not added because user does
  * not have the rights */
    RULE_NOT_ADDED_NO_PERM,
    /* HELLO error messages */
    H_INFOSIZE_MISMATCH,
    H_RULESIZE_MISMATCH,
    H_CMDSIZE_MISMATCH,
    H_UID_MISMATCH,
    /* hello ok message */
    HELLO_OK,
    /* a simple goodbye is sent after a hello_handshake
  * error, to tell kernel we are exited */
    SIMPLE_GOODBYE,
    ACKNOWLEDGEMENT,
    PRINT_DNAT_TABLE,
    PRINT_SNAT_TABLE,
    PRINT_KTABLES_USAGE,
    SMART_SIMPLE,
    SMART_STATE,
    SMARTLOG_TYPE,

    START_NOTIFIER,
    STOP_NOTIFIER,

    RELOAD_VECTOR,
    RELOAD_FILE,
    /* respones from kernel */
    /* generic error */
    ADDING_FAILED,
    /* have not the permission to change rules */
    ADDING_FAILED_NORIGHTS,
};

enum netlinksock_opts
{
    CONTROL_DATA, LISTENER_DATA, GUI_NOTIF_DATA,
};

enum loglevel
{
    NOLOG,
    LOG_DEN,
    LOG_ALLOWED,
    LOG_IMPLICIT,
    LOG_ALL,
    /* LOG_ALL + other things: */
    LOG_VV,
};

enum son_message
{
    /* messages from son to kernel */
    STARTING = 0, /* message field possible values */
    EXITING,
    LIST_CHANGED,
};

#define VERSION "1.99.9"
#define LATEST_KERNEL_SUPPORTED "linux-6.12"
#define CODENAME "\e[0;31mlin\e[0m"
#define _CODENAME "lin"
#define AUTHOR "Giacomo S."
#define AUTHOR_MAIL "\e[4mdelleceste@gmail.com\e[0m"
#define FIREDATE "June 2005 -  Jan 2026"

/* Rule names will be long at most RULENAMELEN-1
 * characters. RULENAMELEN actually takes into
 * account the terminating '\o'
 */
#ifdef ENABLE_RULENAME
/* length of rule name */
#define RULENAMELEN		31
#endif

#define IDLEN	20
#define IFNAMSIZ        16 	/* from linux/if.h */

#ifndef INET_ADDRSTRLEN
#define INET_ADDRSTRLEN 16 /* from in.h */
#endif

#define TASK_COMM_LEN 16 /* task command length */

/* 0.99.5: multiport or multi ip: maximum number of elements of ip/port arrays */
#define MAXMULTILEN			50

/* maximum timeout for kernel timers:
 * max = 2^32/2/HZ.
 * 2^32 'cause architecture is a 32 bit one;
 * /2 'cause a subtraction is made;
 * HZ is 1000.
 * max is 2147483,648 ~ 24 days.
 * For connection timeouts, we set maximum to 1.296.000,
 * that is 15 days.
 * 'unsigned long' is 32 bits on 32 bits architecture.
 */
#define MAX_TIMEOUT 1296000UL

/* For log info, a little value: don't fill memory with
 * these log entries. 5 minutes.
 */
#define MAX_LOGINFO_TIMEOUT 300UL


#define MINPORT 0
#define MAXPORT 65535

/* begin data structure definitions */

/* structure for initial handshake. Contains
 * sizes of structures used by kernel/user
 * communication. User and kernel structs
 * must be the same */
struct firesizes
{
    size_t rulesize;
    size_t cmdsize;
    size_t infosize; /* size of ipfire info */
    size_t statesize;
    size_t snatsize;
    size_t dnatsize;
    size_t loginfosize;
    uid_t uid;
    char uspace_firename[TASK_COMM_LEN];
};

typedef struct {
    int in_idx, out_idx;
} net_dev;

typedef struct {
    const struct net_device* in, *out;
    u8 direction;
} ipfi_flow;

/** packet mangle options. Each mangle option can be grouped
 *  into a specific structure. Up to now, we only change mss
 *  according to the manip_option enumeration above.
 */
struct packet_manip {
    struct mss_mangle
    {
        __u8 enabled:1, error:1, skb_enlarged:1, old_lessthan:1, option:4;
        __u16 mss;
    }mss;
};

struct manip_info {
    struct packet_manip pmanip;
};

/* The following stores information about a connection state */
struct state_t {
    __u8 state:7,reverse:1;
};

struct response {
    struct state_t st;
    uint8_t notify:1,state:1,verdict:6;
    short rulepos;
};

struct info_flags {
    __u16 direction:3,		/* in, out or forward */
        state:1,		/* if true, a match in state tables happened */
        nat:1,			/* firewall has natted the connection */
        snat:1,
        badsum:1,	/* bad checksum */
        external:1,  	/* packet is arriving on external interface (nat) */
        ftp:2,
        exit:1, /* notifies that the userspace thread (on the GUI only) can finish */
        nat_max_entries:1, /* maximum number of entries reached in the kernel tables */
        snat_max_entries:1, /* in these cases packet_id contains the number representing */
        state_max_entries:1, /* the limit reached */
        _free:2; /* in conjunction with `state' flag above, indicates a packet reverse-matched in a stateful connection */
};

struct packet_headers {
    struct iphdr iphead;	/* ip header */
    union {
        struct tcphdr tcphead;	/* tcp header */
        struct udphdr udphead;
        struct icmphdr icmphead;
        struct igmphdr igmphead;
    } transport_header;
};

/**    * response: a negative number represents denial due to
     * the denial rule at position 'response', a positive one
     * represents permission due to match with permission
     * rule at position 'respoonse'. 0 means no explicit rule
     * has been found.
     */
typedef struct {		/* see linux/skbuff.h */
    struct packet_headers packet;
    struct info_flags flags;
    net_dev netdevs;
    // struct manip_info manipinfo;
    struct response response;
} ipfire_info_t;

/* messages from son to kernel */
#define STARTING		100	/* message field possible values */
#define EXITING		101
#define LIST_CHANGED	102

typedef struct {
    short message;
} listener_message;

typedef struct
{
    __u32 ipsrc[MAXMULTILEN];  /* network byte order! */
    __u32 ipdst[MAXMULTILEN];  /* network byte order! */
    __u8 protocol;
    __u16 total_length;
    __u8 tos;
}ipparams;

typedef struct
{
    __u8 type;
    __u8 code;
    __u16 echo_id;
    __u16 echo_seq;
    __u16 frag_mtu;
}icmp_params;

/* parameters related to transport layer */
typedef struct
{
    __u16 sport[MAXMULTILEN];  /* network byte order! */
    __u16 dport[MAXMULTILEN];  /* network byte order! */
    __u8 syn:1,
        fin:1,
        rst:1,
        psh:1,
        ack:1,
        urg:1,
        free1:1,
        free2:1;
}transparams;

/* this enum expresses the meaning of each source and
 * destination field. There can be one single value, an
 * interval of values, or a meaning of a single value, but
 * intended as "different from", or an interval to be excluded.
 * See ipfi_machine.c for use.
 */

enum field_meaning
{
    SINGLE = 0,
    DIFFERENT_FROM,
    INTERVAL,
    INTERVAL_DIFFERENT_FROM,
    MULTI,
    MULTI_DIFFERENT,
};

typedef struct
{
    __u16 spmean:3,
        dpmean:3,
        samean:3,
        damean:3;
}meanings;

/* src_addr/dst_addr flags values */
enum { NOADDR = 0, ONEADDR, MYADDR,  };

/* this flags represent whether the corresponding field must be checked or not
 * by the firewall */
typedef struct {
    /* flags we are going to use for now. In the future this might grow */
    /* ip */
    __u16 src_addr:2, dst_addr:2, /* NONE (0), ONEADDR, MYADDR */
                      proto:1, tot_len:1, tos:1,
                      /* tcp/transport */
                      src_port:1, dst_port:1, syn:1, fin:1, rst:1, psh:1, ack:1, urg:1,

                      state:1; /* stateful connection implementation */

    /* icmp */
    __u16 icmp_type:1, icmp_code:1, icmp_echo_id:1, icmp_echo_seq:1,
                       policy:3,
                       /* ACCEPT or DENIAL or TRANSLATION */
                       /* match the name of the device */
                       indev:1,
                       outdev:1,
                       /* for nat */
                       newaddr:1,
                       newport:1,
                       /* direction: INPUT, OUTPUT... mandatory in NAT */
                       direction:1,
                       ftp:1,
                       other:3;
} netflags;


typedef struct {
    char in_devname[IFNAMSIZ];
    char out_devname[IFNAMSIZ];
    int in_ifindex, out_ifindex; // filled in in kernel space
} deviceparams;

/* NOTE: only user who inserted a rule is able to
 * delete it, unless he is root.
 */
typedef struct {
    deviceparams devpar;
    ipparams ip;
    transparams tp;
    icmp_params icmp_p;
    netflags nflags;
    meanings parmean;	/* meaning of each parameter */
    __u8 direction:4,		/* IPFI_INPUT, IPFI_OUTPUT, IPFI_FWD, ...POST, ...PRE */
        nat:1, masquerade:1, state:1, snat:1;

    /* for snat or dnat */
    __u32 newaddr;
    __u16 newport;

    /* packet mangling, described by struct packet_manip */
    struct packet_manip pkmangle;

    /* --------------------------------------------------------------- *
  * boundary for caracterizing parameters of the rule: differences
  * among fields above cause two rules to be different.
  * In rule comparison, fields below are ignored.
  */

    /* natural and has_id not used by the kernel */
    __u8 notify:1, natural:1, other:6;

#ifdef ENABLE_RULENAME
    char rulename[RULENAMELEN];
#endif
    struct list_head list;
    uid_t owner;
    unsigned int position;	/* position of the rule in list. Starts from 0 */

    struct rcu_head rule_rcuh;
} ipfire_rule;

/* command from userspace */
typedef struct {

    short cmd;		/* command type */

    union{
        ipfire_rule rule;
        struct firesizes fwsizes;
    }content;

    int anumber;		/* a number reserved for some cmd values */
    /* command options, 8 for now */
    __u16 is_rule:1,		/* is it a rule or not? */
        /* if not a rule, the following options may be specified */
        options:1,		/* if it's not a rule, may be an option */
        nat:1,			/* enable Network Address Translation */
        masquerade:1,		/* enable IP masquerading */
        clear:1,		/* clear all rules */
        exiting:1,		/* tell kernel module we are going down */
        stateful:1,		/* enable state machine */
        loglevel:3, loguser:3, noflush_on_exit:1, user_allowed:1,	/* another option, not used for now */
        all_stateful:1;

    unsigned long int snatted_lifetime;
    unsigned long int dnatted_lifetime;
    unsigned long int state_lifetime;
    unsigned long int setup_shutd_state_lifetime;
    unsigned long int loginfo_lifetime;
    unsigned long int max_loginfo_entries;
    unsigned long int max_nat_entries;
    unsigned long int max_state_entries;
} command;

struct state_info
{
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    short direction;
    unsigned int originating_rule;
    unsigned int timeout;
    __u8 protocol;
    int in_ifindex, out_ifindex;
    struct state_t state;
    __u8 notify:1, admin:1,other:6;
};


struct dnat_info
{
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u32 newdaddr;
    __u16 newdport;

    short direction;
    unsigned int id;
    unsigned int timeout;
    __u8 protocol;
    int in_ifindex;
    int out_ifindex;
    struct state_t state;
};

struct snat_info
{
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u32 newsaddr;
    __u16 newsport;

    short direction;
    unsigned int id;
    unsigned int timeout;
    __u8 protocol;
    int in_ifindex, out_ifindex;
    struct state_t state;
};

struct ktables_usage
{
    unsigned int state_tables;
    unsigned int snat_tables;
    unsigned int dnat_tables;
    unsigned int loginfo_tables;
};

/* structure to keep statistics about packets
 * received from kernel and decisions made.
 */
struct kernel_stats
{
    unsigned long long in_rcv;
    unsigned long long out_rcv;
    unsigned long long pre_rcv;
    unsigned long long post_rcv;
    unsigned long long fwd_rcv;
    unsigned long long sum;
    unsigned long long total_lost;
    unsigned long long sent_tou;
    unsigned long long last_failed;

    /* response-related */
    unsigned long long in_acc;
    unsigned long long in_drop;
    unsigned long long in_drop_impl;
    unsigned long long in_acc_impl;

    unsigned long long out_acc;
    unsigned long long out_drop;
    unsigned long long out_drop_impl;
    unsigned long long out_acc_impl;

    unsigned long long fwd_acc;
    unsigned long long fwd_drop;
    unsigned long long fwd_drop_impl;
    unsigned long long fwd_acc_impl;
    /* packets not sent because of loglevel */
    unsigned long long not_sent;

    /* for packets to be NATTED, we must control checksum:
    * if a packet arrives with bad checksum, we don't translate it */
    unsigned long long int bad_checksum_in;
    unsigned long long int bad_checksum_out;

    /* Time when module was loaded */
    /* Time when module was loaded */
#ifdef __KERNEL__
    time64_t kmod_load_time;
#else
    time_t kmod_load_time;
#endif
    /* Default policy applied when packets do not meet any rule */
    short int policy;
};

struct kstats_light
{
    unsigned long long blocked;
    unsigned long long allowed;
};



#endif


