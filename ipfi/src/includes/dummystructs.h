/* These structures are here just to know
 * about their size. They are not used. 
 * They are taken from ipfi_translation.h */
 
 /* the table contains information about destination adddress
 * translated connections. The list of dnatted tables must be
 * checked on arrival of a packet on the interface interested.
 */
struct dnatted_table
{
	__u32 old_saddr;
	__u16 old_sport;
	__u32 old_daddr;
	__u16 old_dport;
	__u32 new_daddr;
	__u16 new_dport;
	
	__u32 our_ifaddr;

	short direction;
	unsigned long id;
	short external;  /* 1 if packet is incoming from external interface */
	int position;
	unsigned short protocol;
	/* From version 0.98.2 on, we keep the state of the NAT tables, just to
	 * apply the correct timeouts on them.
	 */
	int state;
	char in_devname[IFNAMSIZ];
	char out_devname[IFNAMSIZ];
#ifdef ENABLE_RULENAME
	char rulename[RULENAMELEN];
#endif	
	struct timer_list timer_dnattedlist;
	struct list_head list;
	/* RCU */
	struct rcu_head dnat_rcuh;
};

/* the table contains information about source adddress
 * translated connections. The list of snatted tables must be
 * checked on arrival of a packet on the interface interested.
 */
struct snat_entry
{
	__u32 old_saddr;
	__u16 old_sport;
	__u32 old_daddr;
	__u16 old_dport;
	__u32 new_saddr;
	__u16 new_sport;

	short direction;
	unsigned long id;
	int position;
	unsigned short protocol;
	/* See the comment for the above dnatted_table */
	int state;
	char in_devname[IFNAMSIZ];
	char out_devname[IFNAMSIZ];
#ifdef ENABLE_RULENAME
	char rulename[RULENAMELEN];
#endif	
	struct timer_list timer_snattedlist;
	struct list_head list;
	/* RCU */
	struct rcu_head snat_rcuh;
};

struct state_table
{
	__u32 saddr;
	__u32 daddr;
	__u16 sport;
	__u16 dport;
	__u8 direction:3,
		ftp:3, /* passive ftp support */
		other:2;
	unsigned long id;
	unsigned long originating_rule;
	unsigned short protocol;
	char in_devname[IFNAMSIZ];
	char out_devname[IFNAMSIZ];
#ifdef ENABLE_RULENAME
	char rulename[RULENAMELEN];
#endif
	
	struct timer_list timer_statelist;
	struct list_head list;
	struct state_t state;
	
	/* RCU */
	struct rcu_head state_rcuh;
};

struct ipfire_loginfo
{
	ipfire_info_t info;
	unsigned long position;
	struct list_head list;
	struct timer_list timer_loginfo;
	struct rcu_head rcuh;
};

