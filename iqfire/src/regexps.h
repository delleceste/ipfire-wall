#ifndef REGEXPS_H
#define REGEXPS_H

/* some regexp definitions */
#define IP_REGEXP "(?:\\b(?:25[0-5]|2[0-4][0-9]|[1][0-9][0-9]|[1-9][0-9]|[0-9]?)\\." \
	"(?:25[0-5]|2[0-4][0-9]|[1][0-9][0-9]|[1-9][0-9]|[0-9]?)\\." \
	"(?:25[0-5]|2[0-4][0-9]|[1][0-9][0-9]|[1-9][0-9]|[0-9]?)\\." \
	"(?:25[0-5]|2[0-4][0-9]|[1][0-9][0-9]|[1-9][0-9]|[0-9]?)\\b)"
		
#define IP_INTERVAL_REGEXP (IP_REGEXP "\\-" IP_REGEXP)
#define IP_AND_MASK_REGEXP ( "(?:(?:" IP_REGEXP "/" IP_REGEXP ")|(?:" \
    IP_REGEXP "/(?:(?:[3][0-2])|(?:[1-2][0-9])|(?:[0-9]{1,1}))))" )

#define PORT_REGEXP "(?:(?:\\b[0-6][0-5][0-5][0-3][0-5](?!\\.)\\b)|(?:\\b[0-5][0-9][0-9][0-9][0-9](?!\\.)\\b)|(?:\\b[0-9][0-9][0-9][0-9](?!\\.)\\b)|(?:\\b[0-9][0-9][0-9](?!\\.)\\b)|(?:\\b[0-9][0-9](?!\\.)\\b)|(?:\\b[0-9](?!\\.)\\b))"

#define IP_GENERIC_REGEXP \
 	"(?:MY)|(?:any)|(?:-)|(?:\\!{0,1}" IP_REGEXP "[-/]" IP_REGEXP ")|" \
 	"(?:\\!{0,1}" IP_REGEXP ")|(?:\\!{0,1}" IP_REGEXP "[/](\\b[3][0-2]|[1-2][0-9]|[0-9]{1,1}\\b))|" \
	"(?:[\\!]{0,1}(?:" IP_REGEXP "(?:,[\\s]{0,1}){0,1}){2,10})"
	
#define SIMPLER_PORT_REGEXP "(?:(?:\\b[0-6][0-5][0-5][0-3][0-5]\\b)|(?:\\b[0-5][0-9][0-9][0-9][0-9]\\b)|(?:\\b[0-9][0-9][0-9][0-9]\\b)|(?:\\b[0-9][0-9][0-9]\\b)|(?:\\b[0-9][0-9]\\b)|(?:\\b[0-9]\\b))"
#define PORT_GENERIC_REGEXP  \
	"(?:any)|(?:-)|(?:" SIMPLER_PORT_REGEXP "[-]{1,1}" SIMPLER_PORT_REGEXP ")|(?:[\\!]{0,1}" SIMPLER_PORT_REGEXP ")|(?:[\\!]{0,1}(?:" SIMPLER_PORT_REGEXP "(?:,[\\s]{0,1}){0,1}){2,6})"

/* a network interface is a string made up of at most IFNAMSIZ characters and terminated with a number.
 * Suppose it is enough to consider a word an interface if it has from 2 to 15 characters and ends with 
 * a number or two.
 */
#define IF_REGEXP \
  "(?:\\b[A-Za-z]{2,15}[0-9]{1,2}\\b)"

#endif


