/* Resolves internet names in ipv4 addresses. Invoked every determined intervals,
 * it updates the blacklist blocking forward and outgoing connections towards
 * undesired sites.
 */
 
/***************************************************************************
 *  Copyright  2005  Giacomo
 *  jacum@libero.it
 ****************************************************************************/

/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 */

#include "includes/resolver.h"
#include "includes/semafori.h"

int semid_lockf;

/* Starter. Calls resolver every refresh_timeout seconds
 * and everytime receives a sigusr1 signal */
pid_t start_resolver(int refresh_timeout, int resolve_once, int semid)
{
	pid_t respid;
	semid_lockf = semid;
	if( (respid = fork() ) < 0)
	{
		perror(RED "Error creating dns resolver process" CLR);
			return -1;
	}
	else if(respid == 0) /* son */
	{
		if(manage_resolving(refresh_timeout, resolve_once) > 0)
			exit(EXIT_SUCCESS);
		exit(EXIT_FAILURE);
	}
	else
		return respid;
}
	
int manage_resolving(int refresh_timeout, int resolve_once)
{
	int res = 0;
	signal(SIGUSR1, sigres_handler);
	signal(SIGINT, sigres_handler);
	signal(SIGHUP, sigres_handler);
	signal(SIGTERM, sigres_handler);
	do{
		res = resolver();
		if(resolve_once)
			return res;
		/* if !resolve_once, we signal parent */
		if(res >= 0)
		{
			if(kill(getppid(), SIGUSR2) < 0)
				printf(RED "Error signaling firewall that blacklist file has been updated!" NL);
		}
		sleep(refresh_timeout);
	}while(1);
	
	return res;
}

void sigres_handler(int signum)
{
	if(signum == SIGUSR1)
	{
		printf(VIOLET "\nRefreshing names..." NL);
		/* sleep is interrupted and resolving starts */
	}
	else if(signum != SIGSEGV)
	{
		printf(MAROON "Resolver exiting." NL);
		exit(EXIT_SUCCESS);
	}
	else
	{
		printf(RED "* RESOLVER: FATAL ERROR * " NL);
		exit(EXIT_FAILURE);
	}
}

int resolver(void)
{
	FILE* fptemp = NULL, *fpblack = NULL;
	extern struct userspace_opts uops;
	char tempfilename[MAXFILENAMELEN];
	char blackaddr[MAXLINELEN];
	struct hostent* blackhe;
	int numrules = 0;
	int resolved = 0;
	
	printf(YELLOW "Resolver starting ..." NL);
	fflush(stdout);
	if(strlen(uops.blacklist_filename) < MAXFILENAMELEN - 10)
	{
		strncpy(tempfilename, uops.blacklist_filename, MAXFILENAMELEN - 10);
		strcat(tempfilename, ".dnstmp");
	}
	
	fpblack = fopen(uops.blacksites_filename, "r");
	if(fpblack == NULL)
	{
		printf( NL RED "Error opening file \"%s\" in read mode.\nWaiting..." CLR, 
			uops.blacksites_filename);
		fflush(stdout);
		perror("");
		return -1;
	}
	
	fptemp = fopen(tempfilename, "w");
	if(fptemp == NULL)
	{
		perror(RED "Error opening temp file %s in write mode. Waiting..." NL);
		fclose(fpblack);
		return -1;
	}
	/* In numrules the number of old rules saved in the temporary file. */
	if( (numrules = copy_oldrules(fptemp) ) < 0)
	{
		printf(RED "Error copying old rules to temp file" NL);
		fclose(fptemp), fclose(fpblack);
		return -1;
	}
	
	while(fgets(blackaddr, MAXLINELEN, fpblack) != NULL)
	{
		resolved = 0;
		if(strncmp(blackaddr, "#", 1) == 0)
			goto next;
		if(blackaddr[strlen(blackaddr)-1] == '\n')
			blackaddr[strlen(blackaddr) - 1] = '\0';
		blackhe = gethostbyname(blackaddr);
		if(blackhe == NULL)
		{
			herror( RED UNDERL "Error" CLR " getting host names");
			printf("[%s]", blackaddr);
			printf(NL);
			break;
		}
		/* numrules gets updated every time */
		if( (resolved = write_resolved_blackrule(blackhe, fptemp, &numrules) ) < 0)
		{
			fclose(fptemp), fclose(fpblack);
			return -1;
		}
		next:
		if(resolved > 1)
			printf(YELLOW "%s has %d different addresses." NL, blackhe->h_name, resolved);
	}
	if(numrules > 0)
		fprintf(fptemp, "END");
	/* new ruleset containing old and new rules is ready */
	fclose(fptemp);
	fclose(fpblack);
	if(copy_newrules(tempfilename) < 0)
	{
		printf(RED "Error updating new blacklist file!\n" NL);
		return -1;
	}
	return 0;
}

/* copies rules from old blacklist file to temporary file.
 * Returns the number of rules copied.
 */
int copy_oldrules(FILE* fptemp)
{
	FILE* blacklist_file;
	char line[MAXLINELEN];
	extern struct userspace_opts uops;
	int counter = 0;
	int normal_rule = 1;
	
	if( (blacklist_file = fopen(uops.blacklist_filename, "r") ) == NULL)
	{
		perror("Error opening blacklist file for reading (copy oldrules)");
		return -1;
	}
	
	while(fgets(line, MAXLINELEN, blacklist_file) != NULL)
	{
		if(strncmp(line, "END", 3) == 0)
			break;
		if(strncmp(line, "BSRULE", 6) == 0)
			normal_rule = 0;
		if(strncmp(line, "RULE", 4) == 0)
			normal_rule = 1;
		if(normal_rule == 1)
		{
			if(strncmp(line, "RULE", 4) == 0)
				counter ++;
			fprintf(fptemp, "%s", line);
		}
	}
	fclose(blacklist_file);
	return counter;
}

/* removes old blacklist ruleset and renames temporary 
 * file with new rules into official blacklist filename */
int copy_newrules(const char* tempfilename)
{
	extern struct userspace_opts uops;

	if(sem_locked(semid_lockf) )
	{
		printf(RED "Error updating blacklist file: semaphore is red!" NL NL);
		return -1;
	}
	if(remove(uops.blacklist_filename) < 0)
	{
		perror(RED "Error removing old blacklist file" CLR);
		return -1;
	}
	if(rename(tempfilename, uops.blacklist_filename) < 0)
	{
		perror(RED "Error renaming old blacklist file with new one" CLR);
		return -1;
	}
	return 0;
}

int write_resolved_blackrule(const struct hostent* he, FILE* fptemp,
						int *numrules)
{
	int counter = *numrules;
	int i = 0;
	char address[INET_ADDRSTRLEN];
	#ifdef ENABLE_RULENAME
	char name[RULENAMELEN];
	#endif
	
	while(he->h_addr_list[i] != NULL)
	{
		counter ++;
		/* output hook... */
		fprintf(fptemp, "BSRULE\n");
		#ifdef ENABLE_RULENAME
		snprintf(name, RULENAMELEN, "OUT:%s", he->h_name);
		fprintf(fptemp, "NAME=%s\n", name);	
		#endif
		fprintf(fptemp, "POSITION=%d\n", counter);		
		fprintf(fptemp, "DIRECTION=OUTPUT\n");
		if(inet_ntop(AF_INET, he->h_addr_list[i], address, INET_ADDRSTRLEN) <= 0)
		{
			perror("inet_ntop");
			return -1;
		}
		fprintf(fptemp, "DSTADDR=%s\n", address);	
		/* ..and forward of course */
		counter ++;
		fprintf(fptemp, "BSRULE\n");
		#ifdef ENABLE_RULENAME
		snprintf(name, RULENAMELEN, "FWD:%s", he->h_name);
		fprintf(fptemp, "NAME=%s\n", name);	
		#endif
		fprintf(fptemp, "POSITION=%d\n", counter);
		fprintf(fptemp, "DIRECTION=FORWARD\n");
		fprintf(fptemp, "DSTADDR=%s\n", address);	
		i++;		
	}
	*numrules = counter;
	return i;
}
