#include <sys/types.h>
#include <sys/socket.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <pwd.h>
#include <ctype.h> /* isdigit.. */
#include <signal.h>
#include <pwd.h>
#include <time.h>
#include <netdb.h>

#include "log_codes.h"
#include "colors.h"
#include "../g_getcharlib/g_getcharlib.h"

#define MAXFILENAMELEN 100
#define MAXLINELEN 300
#define UNAMELEN		25
#define IFNAMSIZ		16
#define INET_ADDRSTRLEN 16
#define MAXADDRLEN	300
#define SERVICENAMELEN	15

#ifdef ENABLE_RULENAME
#define RULENAMELEN 51
#endif

#define SRC 0
#define DEST 1

struct anopts
{
	char infilename[MAXFILENAMELEN];
	char outfilename[MAXFILENAMELEN];
	char tmpfilename[MAXFILENAMELEN];
	short resolve;
	short srvc_resolve;
	short quiet;
	short tcpflags;
};

struct aninfo
{
	struct tm tm;
	struct tm tmexit;
	/* total packets in netlink stats */
	unsigned long int total_packets;
	/* packets lost in kernel/user comm, according
	* to netlink stats */
	unsigned long int upackets_lost;
	
	char username[UNAMELEN];
	/* first line of a chunk and last line */
	int begpos;
	int endpos;
};

struct global_ustats
{
	unsigned long tot_in;
	unsigned long in_drop;
	unsigned long in_acc;	
	unsigned long in_drop_impl;
	float perc_in_drop;
	float perc_in_drop_impl;
	
	unsigned long tot_out;
	unsigned long out_drop;
	unsigned long out_acc;
	unsigned long out_drop_impl;
	float perc_out_drop;
	float perc_out_drop_impl;
	
	unsigned long tot_fwd;
	unsigned long fwd_drop;
	unsigned long fwd_acc;
	unsigned long fwd_drop_impl;
	float perc_fwd_drop;
	float perc_fwd_drop_impl;
	
	unsigned long prerouted;
	unsigned long postrouted;
	
	/* packets that matched stateful connections */
	unsigned long stateful;
	
};

struct anpacket
{
	short nat;
	short response;
	short state;
	short direction;
	short sunresolved;
	short dunresolved;
	char in_device[IFNAMSIZ];
	char out_device[IFNAMSIZ];
	int protocol;
	unsigned long id;
	char saddr[INET_ADDRSTRLEN];
	char saddr_resolved[MAXADDRLEN];
	char saddr_alias1[MAXADDRLEN];
	char saddr_alias2[MAXADDRLEN];
	unsigned short sport;
	char daddr[INET_ADDRSTRLEN];
	char daddr_resolved[MAXADDRLEN];
	char daddr_alias1[MAXADDRLEN];
	char daddr_alias2[MAXADDRLEN];
	unsigned short dport;
	char sport_res[SERVICENAMELEN];
	char dport_res[SERVICENAMELEN];
#ifdef ENABLE_RULENAME
	char rulename[RULENAMELEN];
#endif
	/* flags: */
	short syn;
	short ack;
	short fin;
	short urg;
	short psh;
	short rst;
	/* conta le occorrenze di un pacchetto */
	long counter;
};

int get_options(int argc, char* argv[], struct anopts * ops);

void print_options(const struct anopts* ops);

void init_options(struct anopts* o);

int get_nchunks(const char* infile);

int get_nlines(const char* filename);

int clean_log(const struct anopts* ao);

int get_right_position(FILE* fp, int chunk, struct aninfo* ai);

int get_date_and_time(const char* line, struct aninfo* ai);

int get_exit_info(const char* line, struct aninfo* ai);

int process_chunk(int chunk, const char* tmpfile, char* outfile);

int get_packet_and_add_to_vector(int index, struct anpacket* anp, 
				 const char* line);

int print_results(unsigned long int nentries);

void restore_color(int direction);

void print_anentry(const struct anpacket *anp);

int print_alias(const struct anpacket* anp);

/* legge il vettore mallocato e globale e fa tutti i calcoli..
 * scrivendo il risultato sul file puntato da fpout */
int analyze(FILE* fpout, unsigned long int number_of_elements);

int lookup_equals(struct anpacket* anp, 
		  unsigned long int nelems, 
		  unsigned long int current_index);

int anentries_equal(const struct anpacket *a1, const struct anpacket* a2);

unsigned long sum_on_counters(unsigned long int index);

void make_stats(unsigned long nelems);

void calculate_percentages(void);

void print_ustats(void);

void print_time_info(struct aninfo* ai);

int resolve_addresses(unsigned long int nents);

int resolve_ports(unsigned long int nents);

inline void get_protocol(const int protocol, char* cproto);

void look_for_alias(struct anpacket* anp, struct hostent* he, 
		    int direction);


/* returns 1 if the number of bars "|" in line is correct,
 * 0 otherwise. This function avoids parsing unterminated
 * lines */
int expected_number_of_bars(const char* line);
