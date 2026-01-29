#ifndef IPFIRE_USERSPACE_H
#define IPFIRE_USERSPACE_H

/* linux/netlink.h creates problems. Copied and patched from kernel includes */
//#include "kincludes/netlink.h"
//#include <arpa/inet.h>
#include "ipfire_structs.h"
#include <linux/in.h>		/* for "__kernel_caddr_t" et al	*/
#include <sys/socket.h> /* for sa_family_t */
#include <sys/types.h>
#include <linux/netlink.h>
// #include "list.h"
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>	/* ULONG_MAX... */
#include <unistd.h>
#include <errno.h>
#include <pwd.h>
#include <ctype.h> /* isdigit.. */
#include <signal.h>
#include <pwd.h>
#include <time.h>
/* for open */
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/wait.h> /* for wait */
#include<sys/utsname.h> /* for system information */


#include "libnetl.h"
#include "colors.h"

/* Declaration of network functions. #include gives conflicts */
int inet_pton(int af, const char *src, void *dst);

const char *inet_ntop(int af, const void *src,
                           char *dst, socklen_t cnt);

// u16 htons(u16 hostshort);
// u32 ntohl(u32 netlong);
// u16 ntohs(u16 netshort);
// u32 htonl(u32 hostlong);

struct servent {
              char    *s_name;        /* official service name */
              char    **s_aliases;    /* alias list */
              int     s_port;         /* port number */
              char    *s_proto;       /* protocol to use */
};


char *inet_ntoa(struct in_addr in);
	
/* .. and isblank(), which should be in ctype.h .. */
// int isblank(int c);
	
/* IPFIRE USERSPACE FUNCTIONS */


/* constructs hello command filling in sizes of data
 * structures. Receives the program name as got by
 * argv[0] */
int build_hello_command(command* cmdh, char *argv0);

/* sends hello message to kernel space. Returns code
 * filed in by kernel in field command of coming back 
 * command */
int hello_handshake(command* cmdh);

int process_kernelspace_data(ipfire_info_t* ipfi_kern);

/* reads rules from a configuration file and allocates a dynamic vector containing them */
ipfire_rule* allocate_ruleset(int whichfile, int *number_of_rules);
unsigned int get_number_of_rules(FILE* fp);

/* initializes file names to default values */
int init_useropts(struct userspace_opts *uops);

/* if type is USERNAME, user name is copied in info,
 * else if type is HOMEDIR, home directory name is
 * copied in info */
int get_user_info(int type, char* info);

/* transforms user name to upper case, after
 * getting it by means of get_user_info() */
void toupper_username(char* upperun);

/* save_rules() sends file pointer and a rule
 * to be written on file */
int write_rule(FILE* fp, const ipfire_rule r, int index);

/* writes headers in configuration files, i.e. comments
 * to those files for a user who wants to explore them */
void write_header(FILE* fp, int whichfile);

/* manages saving all rules (3 vectors) */
int save_rules();

/* depending on direction, this function sets flags on rule
 * so that src/dst addresses will be chosen by kernel.
 * Note that only in input or output direction this option
 * is correct. */
int set_myaddr_flags(ipfire_rule* r, int direction, int meaning,
						int hook);

int get_integer(const char* line);
int get_address(struct in_addr *addr, const char* line);
/* fills in ruleset, putting each rule in the previously allocated vector ipfr */
int parse_rulefile_and_fill(FILE* fp, ipfire_rule* ipfr, int whichfile);
/* init with zeros rule and command structures */
void init_rule(ipfire_rule* rule);
void init_cmdopts(struct cmdopts* cmdo);

/* Parses the command line.
 * different_ruleset_by_cmd is set to 1 if
 * the user specifies an alternate file name for
 * any of the ruleset files, or for the log file.
 */
int parse_cmdline(struct cmdopts* cmdo, 
		struct userspace_opts *uo, command* cmd, 
		int argc, char* argv[] ,
		int *different_ruleset_by_cmd);
		
void init_command(command* cmd);
void init_table(struct state_info *st);

/* checks if timeouts are too long and, if so, sets them to the maximum
 * value allowed. See above, near definition of MAX_TIMEOUT.
 * This is called by get_options().
 */
void check_max_lifetime_values(command* opt);

/* reads options from a config file */
int get_options(command* opt,
					struct userspace_opts *uo, struct cmdopts* cmdo);

int get_string(char *string, const char* line);

/* copy into string at most limit characters */
int get_string_n(char *string, const char* line, int limit);
					
/* gets the name of the rule from file. Invoked by 
 * parse_rulefile_and_fill() */
void get_rule_name(const char* line, char* name);

/* fill appropriate fields to make command look as an option one */
int build_option_command(command* cmd);

/* Builds a command to stop or start the netlink communication
 * between the kernel and the packet printing process in
 * userspace. With this (version 0.98), there is no need to tell
 * the son process to stop printing: it will simply stop receiving
 * packets from the kernel space.
 */
int build_loguser_enabled_command(command *cmd, int enabled);

/* the command must indicate there is a rule */
int build_rule_command(command* cmd);
/* prints significative options */
int print_command(const command* opt);


/* prints some information about the meanings of
 * log user levels */
void print_loguser_meanings(int level);
					
/* prints command line options. At startup this one is called
 * with verbose set to 0, so that it doesn't print all the 
 * options */
void print_cmd_options(const struct cmdopts* cmdo, 
		    const struct userspace_opts* uo, int verbose);

/* this one is called every time a command is sent to kernel.
 * Kernel verifies credentials and then sends an acknowledgement
 * before committing a command */
int wait_acknowledgement(void);
	
/* sends a command structure to kernel netlink socket.
 * Returns -1 on failure, the number of bytes sent in case
 * of success.
*/
int send_command_to_kernel(const command * cmd);

/* receives a command structure from kernel space, putting it 
 * in memory pointed by cmdrec. Returns -1 on failure, the
 * number of bytes read in case of success.
*/
int read_command_from_kernel(command* cmdrec);
	
/* sends a command to kernel space. After this is done, memory 
 * dynamically allocated is freed. int type_of_message can be
 * one among COMMAND (to allocate space for a command 
 * structure), LISTENER_DATA (to allocate space for a listener_message
 * data structure), or KSTATS (to reserve space for a struct kernel_stats.
 */
int 
send_to_kernel( void* mesg, const struct netl_handle* handle, 
 			int type_of_message);
	
int send_cmd_to_kernel( command mess, struct netl_handle* handle, int type_of_message);
	
int firewall_busy(command* com);

/* when userspace program exits, it tells kernel and kernel sends
 * back a message reporting the number of rules flushed */
void print_kernel_userspace_exit_status(const command *exc, int rc_enabled);
	

/* each element of the vector pointed by rules is copied in a 
 * command struct and then sent to kernel 
 */
int send_rules_to_kernel(ipfire_rule* rules,  int nrules);

int send_goodbye(struct netl_handle* nh_control);
	
/* sends a simple goodbye to kernel after a start 
 * failure */
int send_simple_goodbye(void);

/* manages adding a new rule, asking user for position
 * and then invoking add_rule() */
int manage_adding_rule(const ipfire_rule* newrule);

/* this function manages deleting a rule, presenting to
 * the user an interface to choose the position of the 
 * rule to remove */
int manage_deleting_rule(ipfire_rule * r);

/* deletes a rule at the position specified in vector indicated
 * by which_vector. Code in this function could be not necessary
 * if pop_rules_from_pos() was directly invoked. Anyway, it makes
 * manage_deleting_rule() a bit lighter */
int delete_rule_at_position(int position, int which_vector);

/* adds rule at the position specified. Position starts from 1.
 * If position is 0, then rule is added at the tail of the vector.
 * The function reads the policy field of the rule, and then 
 * decides which vector is to be added to. */
int add_rule_at_position(const ipfire_rule *r, int position);

/* given two ipfire_rules mallocated pointers, a new rule, a
 * new position, the old dimension of old pointer, this function
 * inserts at position 'position' the new rule. */
int push_rule_at_pos(ipfire_rule *oldv, ipfire_rule *newv, 
						int position, const int nmax, 
						const ipfire_rule* newr);

/* gets a line from standard input performing some
 * operations as returning 0 if line is made of a single
 * newline, -1 in case of error. */
int get_line(char * dest);

/* asks user to press a key, then sends to listener
 * a command to enable printing */
inline int prompt_return_to_menu(void);

/* get a new rule from stdin */
int get_new_rule(ipfire_rule* r);

/* gets the device copying its name in appropriate field */
int get_device(ipfire_rule* r, int direction);

/* removes first n nondigits from string addr.
 * Must be called _before_ functions which fill
 * _not_ values */
void remove_exclmark(char* addr);

/* returns 1 if address in string addr
 * is expressed in cidr form */
int is_cidr(const char* addr);

/* address in string addr in the form x.y.z.w/a.b.c.d
 * or x.y.z.w/n is converted in a string of the form 
 * h.i.l.m-p.q.r.s */
int cidr_to_interval(char* addr);

/* fills in rule ipsrc or ipdst fields, depending on the  direction
 * specified. Returns -1 on error, 0 if address does not have 
 * to be specified, 1 in case of success. Direction in this case
 * is SOURCE or DEST, hook is IPFI_INPUT, IPFI_OUTPUT... */
int get_in_address(char* addr, ipfire_rule* r, int direction, int hook);

/* parses addr and returns 1 if mask is expressed in 
 * dotted decimal form (i.e. 192.168.1.100/255.255.255.0),
 * 0 otherwise (i.e. 192.168.1.100/24). -1 in case of error. */
int get_address_and_mask(const char* addr, 
				__u32* address, __u32* mask);
				
/* given a string, it gets transformed in an interval,
 * depending on values of address and netmask */
void addr_and_dotted_mask_to_inet_interval(const __u32 address, 
		const __u32 mask, __u32* start_address, 
		__u32* end_address);
		
/* given an address and a netmask in integer decimal form,
 * fills in min and max values of internet addresses according
 * to netmask value */
void addr_and_integer_to_inet_interval(const __u32 inetaddress, 
		   const __u32 inetmask, __u32* start_address, __u32* end_address);		
			
/* given two addresses in network byte order, transforms
 * them into strings and then forms an interval of the form
 * 192.168.0.0-192.168.0.100 */
int addresses_to_string_interval(char* addr, 
			const __u32 starta, const __u32 enda);			

/* converts the integer representing protocol in a string 
 * with its name */
 void get_proto_name(char* name, int pro);

/* asks user which protocol regards new rule */
int get_in_protocol(ipfire_rule *r);

/* given a string, deletes leading "!" and fills in
 * r with appropriate values for ip addresses */
int fill_not_ip(const char* naddr, ipfire_rule* r, int direction);

/* calls fill_ip_interval to fill rule with right addresses making
 * part of the interval, then changes values of meanings */
int fill_not_ip_interval(const char* addr, ipfire_rule* r, int direction);

/* given a string, fills in r with a simple ip in appropriate field */
int fill_plain_address(const char* naddr, ipfire_rule* r, 
				int direction);

/* when user writes !80 this function treats leading "!" */
int fill_not_port(const char* port, ipfire_rule* r, int direction);

/* gets from standard input other IP layer parameters */
int get_ip_specific_parameters(ipfire_rule* r);

/* checks if tos value is permitted. Returns > 0 on success,
 * 0 otherwise */
int check_tos(u8 tos);

/* checks if port is in range */
int check_port(int p);

/* given a protocol, two strings and two ports
 * in network byte order, copies service name 
 * as in etc/services in corresponding strings.
 * If no match is found, strings are empty ( "" )
 */
inline int resolv_ports(const struct ipfire_servent* ipfise,
									const unsigned short protocol, 
									char* srcserv, char* dstserv,
									__u16 sport, __u16 dport);

/* checks if total length value is permitted. Returns 0 on success,
 * -1 otherwise */
int check_totlen(u16 total_length);

/* checks if the first ip address is less than
 * the second. Equal values are not allowed */
int check_ip_interval(u32 ip1, u32 ip2);

/* fills in rule source port or destination port fields,
 * depending on the  direction specified. 
 * Returns -1 in case of error, 0 if no port is specified,
 * 1 if port is specified and correct */
int get_in_port(char* port, ipfire_rule* r, int direction);

/* the same as for address case */
int fill_port_interval(const char* port, ipfire_rule* r, int direction);

int fill_not_port_interval(const char* port, ipfire_rule* r, int direction);

int fill_plain_port(const char* port, ipfire_rule* r, int direction);

/* checks if ports specified are ok and if first port is
 * less than second. Equal values are not allowed */
int check_port_interval(int p1, int p2);

/* gets flags such as syn, fin, ack... */
int get_tcp_specific_parameters(ipfire_rule* r);

/* gets MSS */
int get_mss_parameters(ipfire_rule *r);

/* gets new address and port for translation. Returns -1 in case
 * of errors, 0 otherwise */
int get_nat_parameters(ipfire_rule* r, int nat_kind);

/* main interaction menu */
int interaction(const struct netl_handle* nh_control);
	
/* functions for stopping and resuming printing */
inline void stop_printing(void);

/* function sends flush request. Requires flush command 
 * to be specified, since it allows flushing all rules 
 * (FLUSH_RULES), or only permission (FLUSH_PERMISSION_RULES)
 * or only denial (FLUSH_DENIAL_RULES) or only translation
 * rules (FLUSH_TRANSLATION_RULES). */
int flush_request(const struct netl_handle* nh_control, 
							int flush_com);

/* This function updates kernel rules. Depending on policy,
 * interested rules are first flushed, then a new vector
 * is reloaded. If flag is RELOAD_FILE, rules are reloaded 
 * from file */
int update_kernel_rules(int policy, int flag);

/* calls update_kernel_rules() 3 times if root, 2 if not root,
 * each time flushing and then reloading accept, denial 
 * and translation rules */
int update_all_rules(void);

/* logging */
int openlog(const struct userspace_opts* uo);
int closelog(void);

/* this function checks if log is enabled 
 * and calls do_log if yes */
inline int flog(const char* line);
/* this one writes */
inline int do_log(const char* line);

/* given a log code, prints it separating each
 * entry with a '|' character. Used for printing
 * a packet received by kernelspace. Codes 
 * are stored in "log_codes.h" */
inline int flogpack(int code);

/* logs startup */
int log_initialization(const struct tm *tm, const char* user);

/* logs exiting */
int log_exiting(const struct tm* tm, const char* user,
					const struct netlink_stats* nls);

/* put all fields to 0 when listener starts */
void init_netlink_stats(struct netlink_stats* nls);

/* function that checks if some packets have been lost
 * during receiving on netlink socket. */
int check_stats(struct netlink_stats* ns, const ipfire_info_t* msg);
	
/* prints information about packets lost */
int print_lostpack_info(const struct netlink_stats* nls);

/* reads nls and prints its fields */
void print_stats(struct netlink_stats* ns);
	
/* sends kernel a request to obtain statistics
 * about packets received, dropped, acceppted...
 */
int request_kstats(void);

int change_smart_log(int level);

/* receives from netlink socket a statistics structure */
int receive_kstats(struct kernel_stats* ks);

/* three functions in utils.c */

/* returns > 0 if the packet is to be filtered out, i.e. tells
 * print_packet not to print the packet on stdout.
 */
int filter_packet_to_print(const ipfire_info_t* p, const ipfire_rule_filter* f);

int print_packet(const ipfire_info_t *pack, 
	const struct ipfire_servent* ipfise,
	const ipfire_rule_filter* f);

/* logs packets received from netlink socket to file */
int log_packet(const ipfire_info_t *pack, int loglevel);

/* three functions in utils.c */

/* allocates and copies into memory entries from /etc/services */
struct ipfire_servent *alloc_and_fill_services_list(void);
	
/* deep copy of structure. We are not interested in alias */
inline void copy_servent(struct ipfire_servent *dst, 
			const struct servent* src);

/* given a pointer to mallocated ipfire_servent structure, 
 * this function looks for match in port and protocol and 
 * copies into name the name of the service, if a match
 * is found */
int get_service_name(const struct ipfire_servent* ise, char* name, char* proto, 
			int port);

/* unloads kernel module at exit */
int unload_module(void);

/* loads kernel module at startup */
int load_module(void);

/* reads from /proc the name of modprobe command.
 * Requires a pointer to a 1024 chars allocated buffer */
int get_modprobe_command(char* mpcmd);

/* returns -1 in case of error, 0 if ipfi is not loaded,
 * 1 if ipfi kernel module is already loaded. */
int module_already_loaded(void);

/* Starter. Calls resolver every refresh_timeout seconds
 * and everytime receives a sigusr1 signal.
 * See resolver.h for resolver functions. */
pid_t start_resolver(int refresh_timeout, int resolve_once, int semid);

/* Seconds are converted in days, hours, minutes and seconds, saved
 * in *d, *h, *m and *s. In utils.c.
 */
int seconds_to_dhms(unsigned seconds, unsigned* d, unsigned short *h, 
		    unsigned short *m, unsigned short* s);

/* checks if .IPFIRE exists. If not, tries to initialize it
 * copying from /usr/share/ipfire/config/IPFIRE the default files
 */
int setup_confdir(); /* common.c */

int install_default_dir(const char *confdirname);

#endif
