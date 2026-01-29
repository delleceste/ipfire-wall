#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include "colors.h"

/* max length of file names */
#define MAXFILENAMELEN 60
#define MAXLINELEN 			100

#ifdef ENABLE_RULENAME
#define RULENAMELEN		51
#endif

/* policy */
#define DENIAL 	0
/* for update_kernel_rules() */
#define RELOAD_FILE 1

struct userspace_opts
{
	char permission_filename[MAXFILENAMELEN];
	char blacklist_filename[MAXFILENAMELEN];
	char translation_filename[MAXFILENAMELEN];
	char options_filename[MAXFILENAMELEN];
	char blacksites_filename[MAXFILENAMELEN];
	short loglevel;
	short clearlog;
	short justload;
	short flush;
	short rmmod;
	short resolv_services;
	short dns_resolver;
	int dns_refresh; /* in seconds, refresh interval */
	char logfile_name[MAXFILENAMELEN];
};

/* dns resolver for blacklisted sites */

/* Starter. Calls resolver every refresh_timeout seconds
 * and everytime receives a sigusr1 signal */
pid_t start_resolver(int refresh_timeout, int resolve_once, int semid);

/* main son sleep-resolve cycle */
int manage_resolving(int refresh_timeout, int resolve_once);

/* resolver: every refresh_timeout seconds, resolves names
 * of blacklisted sites, and updates blacklist file. Then sends 
 * a SIGUSR2 to parent to notify rules must be reloaded. */
int resolver(void);

/* copies rules from old blacklist file to temporary file */
int copy_oldrules(FILE* fptemp);

/* removes old blacklist ruleset and renames temporary 
 * file with new rules into official blacklist filename */
int copy_newrules(const char* tempfilename);

 /* singnal handler of resolver */
void sigres_handler(int signum);

/* scans h_addr_list of he and add a rule for each address */
int write_resolved_blackrule(const struct hostent* he, FILE* fptmp,
						int *numrules);

/* This function updates kernel rules. Depending on policy,
 * interested rules are first flushed, then a new vector
 * is reloaded. If flag is RELOAD_FILE, rules are reloaded 
 * from file */
int update_kernel_rules(int policy, int flag);
