#ifndef IPFI_HEADER_CHECK_H
#define IPFI_HEADER_CHECK_H

/* Prints an error message and always returns -1.
 * It is used to signal on syslog a network IP or TCP or UDP 
 * header null and to return the -1 as error code.
 */
int network_header_null(const char *funcname, const char *message);


#endif
