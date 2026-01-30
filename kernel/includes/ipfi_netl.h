#ifndef IPFI_NETL_H
#define IPFI_NETL_H

/* See ipfi.c for details and 
 * use of this software. 
 * (C) 2005 Giacomo S. 
 */

#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/init.h>
#include <linux/ip.h>
#include <linux/notifier.h>
#include <linux/netlink.h>
#include <linux/time.h> 
#include <net/sock.h>
#include "ipfi.h"
#include "ipfi_log.h"
#include "ipfi_machine.h"
#include "ipfi_translation.h"
#include "../../common/defs/ipfi_structures.h"

/* Smart logging */
enum smartlog_type
{
  SMART_LOG = 1,
  SMART_LOG_WITH_STATE_CHECK,
};

/* every LOG_PACKETS_RECV packets
 * received for each hook, write a line to
 * syslog */
#define LOG_PACKETS_RECV 1000000ULL

/* every  LOG_NETLINK_FAILURES write
 * a message to syslog */
#define LOG_NETLINK_FAILURES 25000

/* netlink related function calls */


/** @param skb socket buffer received by netlink socket callback nl_receive_control()
 * Extracts the command data structure from skb with NLMSG_DATA (extract_data() ) and 
 * according to the command type, invokes one of the functions in ipfi_process_control.
 * @return less than zero if an error occurred.
 */
int process_control_received(struct sk_buff *skb);

 /** Handshake with userspace program: checks if structure sizes 
  * are correct 
  */
int initial_handshake(command* hello, uid_t userspace_uid);

/* Fills in the firesizes structure with the size of the 
 * structures.
 */
void get_struct_sizes(struct firesizes* fsz);

/* copies kernel sizes in firesizes structure to send
 * back to userspace. */
void fill_firesizes_with_kernel_values(command* cmd, size_t krulesize, size_t kinfosize,  size_t kcmdsize, uid_t uspace_uid);

int init_netl(void);
void fini_netl(void);

/* Sends in userspace the struct sizes */
int send_struct_sizes(void);

/* Sends in userspace the type of logging to userspace in use.
 * Reads fwopts.
 */
int send_smartlog_type(void);

/* depending on loguser, this function decides if
 * firewall has to send packet info to userspace 
 * firewall */
int
is_to_send(ipfire_info_t* info, const struct ipfire_options* ipo);

/* packets sent to userspace get the "logu_id" field incremented 
 * by one each time. If this counter exceeds ULONG_MAX, it 
 * has to be re-initialized to 0, to prevent overflow */
unsigned long long update_sent_counter(int direction);

int send_data_to_user(struct sk_buff *skb, pid_t destination_pid, struct sock* which_socket);

int
 build_message_in_skb(struct sk_buff *skb, void *message,
				     size_t message_size);
 
void set_outgoing_skb_params(struct sk_buff *skbf);
int nl_receive_outcome(struct sock* sknl_ipfi_data_rec);

/** int ipfi_response() in ipfire_core.c invokes this function.
 * @param ipfi_info is kmallocated by ipfi_response() itself at the beginning.
 *
 * If allocation succeeds, ipfire_info_t is initialized with socket buffer values 
 * and then begins its long travel starting from iph_in_get_response().
 * At the end of ipfi_response, after that the verdict has been decided for the 
 * packet inside skb, ipfi_info is kfreed.
 * The main task of iph_in_get_response() is to invoke ipfire_filter for incoming,
 * outgoing and to forward packets. Once the response is determined by ipfire_filter(),
 * this function sends the info_t to userspace, if required - according to is_to_send() 
 * return value, and updates some statistics.
 *
 * In addition, it checks if manipulation of the packet is needed, for instance mss change,
 * which is the only mangle function provided by ipfirewall.
 *
 * @return is, again, the response obtained by ipfire_filter().
 */
int iph_in_get_response(struct sk_buff* skb, int direction, const  struct net_device *in, const  struct net_device *out);

/* sends an acknowledgement to userspace program 
 * before actuating a command */
inline int send_acknowledgement(pid_t uspace_pid);

/* given a direction or a constant identifying the counter
 * which has to be incremented, this function increments 
 * corresponding counter. Response is unsigned long
 * because if the counter to be incremented is total_lost
 * (last case), printk logs the packet_id field of packet
 * that failed to be sent. Moreover, response field is
 * copied to last_failed field of kernel stats structure. */
void 
update_kernel_stats(int counter_to_increment,
				    unsigned long int response);
			     
/* checks if timeouts are too high and, if so, sets them to the
 * maximum value allowed. 
 * In 32 bit architecture, maximum value for timeouts is 
 * 2^32/2/HZ, see ipfi_netl.h near the definition of
 * MAX_TIMEOUT.
 */
void check_max_timeout_values(command* cmd);

/* sets various options related to firewall behaviour, as specified by
 * command received from userspace.
 */
int set_firewall_options(command* cmd, const uid_t commander);

void opts_to_cmd(command* cmd);

int print_command(const command* cmd);

/* adds the new rule contained inside the command to the right list of 
 * rules, depending on direction and policy */
int add_rule_to_list_by_command(command *cmd);

void print_loginfo_memory_usage(unsigned long lifetime);

void print_state_entries_memory_usage(void);

void print_nat_entries_memory_usage(void);

int send_rule_list_to_userspace(void);
int send_a_list(ipfire_rule* rlist);
int send_tables(void);
int send_dnat_tables(void);
int send_snat_tables(void);
int send_ktables_usage(void);
int do_userspace_exit_tasks(uid_t userspace_commander);
int flush_ruleset(uid_t userspace_commander, int flush_command);
int free_rules(ipfire_rule*, uid_t user);
int free_dynamic_tables(void);
int free_dnatted_table(void);
int free_snatted_table(void);
int tell_user_howmany_rules_flushed(int howmany);

/** @param cmd a kmallocated command.
 *  @return less than 0 in case of error (-ENOMEM)
 *
 *  The parameter cmd _must_ be a kmallocated pointer to command data structure.
 *  Never pass command* through & operator in the caller!
 *  This function calls build_command_packet(cmd) obtaining a pointer to a struct sk_buff.
 *  If that pointer is not NULL, the command is ready to be sent to userspace via the 
 *  netlink CONTROL socket.
 */
int send_back_command(const command* cmd);

int manage_rule(command* rule_from_user);

int register_log_function(int loguserlevel); /* SMART_SIMPLE or SMART_STATE */

int skb_send_to_user(struct sk_buff* skb, int type_of_message);
int get_input_response(void);
int get_output_response(void);
int get_forward_response(void);

/* This function is invoked when userspace firewall 
 * sends a simple exit command. It resets counters and
 * pid values for accepting new registrations for right
 * userspace firewalls */
int simple_exit(void);

int do_userspace_exit_tasks(uid_t userspace_commander);
void init_options(struct ipfire_options* opts);

/** @cmd the command containing the rule as content. The rule is compared with all
 * the rules in the list to establish if it is already present.
 */
int rule_not_already_loaded(const command *);

int
find_rules_in_list(const ipfire_rule* rlist, const ipfire_rule* rule);

void init_kernel_stats(struct kernel_stats* nl_kstats);
				    
/* sends to userspace the passed kernel_stats structure */
int send_kstats(void );

/* Sends to userspace the passed kernel_stats light structure.
 * This is for the GUI which has a SystemTray that indicates the
 * traffic being filtered.
 */
int send_kstats_light(void );


#endif
