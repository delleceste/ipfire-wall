#ifndef IPFI_UTILS_H
#define IPFI_UTILS_H

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include "ipfire_structs.h"
#include <netdb.h>
#include <arpa/inet.h>
#include "colors.h"
#include "log_codes.h"
#include "languages.h"

int do_log(const char* line);

/* function to send a message to be logged */
int flog(const char* line);

/* given a log code, prints it separating each
 * entry with a '|' character. Used for printing
 * a packet received by kernelspace. Codes 
 * are stored in "log_codes.h" */
int flogpack(int code);

/* given a protocol, two strings and two ports
 * in network byte order, copies service name 
 * as in etc/services in corresponding strings.
 * If no match is found, strings are empty ( "" )
 */
int resolv_ports(const struct ipfire_servent* ipfise,
	const unsigned short protocol, 
	char* srcserv, char* dstserv,
	__u16 sport, __u16 dport);
									
/* allocates and copies into memory entries from /etc/services */
struct ipfire_servent *alloc_and_fill_services_list(void);
	
/* deep copy of structure. We are not interested in alias */
void copy_servent(struct ipfire_servent *dst, 
			const struct servent* src);									

/* given a pointer to mallocated ipfire_servent structure, 
 * this function looks for match in port and protocol and 
 * copies into name the name of the service, if a match
 * is found */
int get_service_name(const struct ipfire_servent* ise, char* name, char* proto, 
			int port);

void get_icmp_type_code(const int t, const int c, char* type, char *code);

void get_igmp_type_code(const int t, const int c, char* type, char *code);

int filter_packet_to_print(const ipfire_info_t* p, const ipfire_rule_filter* f);

/* removed duplicate resolv_ports declaration */
	
void restore_color(int direction);
	

#endif

