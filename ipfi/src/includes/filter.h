#ifndef IPFIRE_FILTER_H
#define IPFIRE_FILTER_H

#include "ipfire_structs.h"

/* Returns a filter rule. 
 * The caller must free() this returned structure after use!
 */
ipfire_rule_filter* setup_filter(const char* filter);

/* This one frees the ipfire_rule dynamically allocated 
 * by the setup_filter().
 * It must be called to free the dynamically allocated resources.
 */
void free_filter_rule(ipfire_rule_filter *f);

/* Returns 0 if pattern is NOT contained in string,
 * the position of the end of the pattern in the string if the
 * pattern is contained in string.
 */
int string_contains_pattern(const char *string, const char* pattern);

void print_filter(const ipfire_rule_filter *f);

void print_filter_help();

/* This one prepares a string to provide a filter to 
 * setup_filter(). 
 * Returns a memory allocated char * which must be freed by
 * the  caller after use.
 */
char *setup_filter_pattern();	


#endif
