/* Functions used in command line interface 
 * of IPFIRE.
 * Giacomo S.
    jacum@libero.it
 */

#ifndef INTERFACE_H
#define INTERFACE_H

#include<ctype.h>

struct ipfire_rule;

/* when a response to a hello message contains 
 * an error, this function prints some details */
void print_hello_error(const command* hello);

/* prints rules in user vector, not all those
 * loaded in firewall. Those printed are personal
 * rules. Calls print_rules() for each vector. */
int print_my_rules(void); 

/* this one asks if one wants to enable ftp passive support */
void ask_if_ftp_support(ipfire_rule* r);

/* Returns < 0 if the rule does not match the filter */
int  filter_rule(const ipfire_rule*  rule, const ipfire_rule_filter* filter);

/* prints rules present in the vector v_rules */
int print_rules(const ipfire_rule* v_rules, int numrules, const ipfire_rule_filter* filter);

/*
 * Returns a dynamically allocated structure ipfire_rule_filter,
 * which must be freed by the caller!
 */
ipfire_rule_filter* setup_filter(const char *filter_pattern);

/* Prompts a menu in which the user writes the filter. */
/* returns a memory allocated pointer which must be freed after use */
char *setup_filter_pattern();

/* This one frees the ipfire_rule dynamically allocated
 * by the setup_filter().
 * It must be called to free the dynamically allocated resources.
 */
void free_filter_rule(ipfire_rule_filter *f);

void print_filter_help();

void print_filter(const ipfire_rule_filter *f);

int filter_is_active();

/* Returns > 0 if pattern is contained in the string */
int string_contains_pattern(const char *string, const char* pattern);

/* writes a command on pipe shared between main
 * interface and listener (son) and then signals listener
 * that there is a message for it */
int send_command_to_listener(const char* com);

/* sets kind of rule to be inserted */
int set_kinda_rule(const int scelta, ipfire_rule *r);

int get_direction(ipfire_rule* r);

int get_icmp_specific_parameters(ipfire_rule *r);

int get_masquerade_parameters(ipfire_rule* r);

#ifdef ENABLE_RULENAME
int get_in_rule_name(ipfire_rule* r);
#endif

/* returns 0 if it's not an interval, the position of
 * dividing character "-" otherwise */
int is_interval(const char* line);

int fill_ip_interval(const char* addr, ipfire_rule* r, int direction);

/* invoked by listener when packet loss happens.
 * It disables verbose printing, re-enabling it
 * if 'v' key is pressed */
inline void quiet_modality(int quiet);

/* prints command line interface main menu */
inline void print_menu(short filter_enabled, short resolv_services);

/* Converts seconds into days hours mins secs and prints */
void print_seconds_to_dhms(unsigned int seconds);

/* prints help messages about usage */
inline void print_help(void);

inline void print_configuration_options(void);

/* parent prints kernel statistics after a stats 
 * request. */
void print_kstats(const struct kernel_stats* ks);

/* prints system information and program information */
void print_sysinfo(void);

#endif



