#include "includes/proc.h"
#include "includes/languages.h"
#include "includes/colors.h"
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

/* returns -1 if fails, the value read on success */
int read_rmem_default()
{
	FILE *fp;
	char filenam[64] = "/proc/sys/net/core/rmem_default";
	int val = -1;
	if((fp = fopen(filenam, "r")) == NULL)
	{
		printf("Error opening \"%1\" for reading", filenam);
		perror("");
	}
	else
	{
		fscanf(fp, "%d", &val);
		fclose(fp);
	}
	return val;	
}

/* returns -1 if fails, the value read on success */
int read_rmem_max()
{
	FILE *fp;
	char filenam[64] = "/proc/sys/net/core/rmem_max";
	int val = -1;
	if((fp = fopen(filenam, "r")) == NULL)
	{
		printf("Error opening \"%1\" for reading", filenam);
		perror("");
	}
	else
	{
		fscanf(fp, "%d", &val);
		fclose(fp);
	}
	return val;	
}

/* < 0 failed, 1 accept, 0 deny */
short int read_policy()
{
	FILE *fp;
	int i;
	char filenam[64] = "/proc/IPFIRE/policy";
	char line[128] = "";
	
	int val = -1;
	if((fp = fopen(filenam, "r")) == NULL)
	{
		printf("Error opening \"%1\" for reading", filenam);
		perror("");
	}
	else
	{
		val = 0; /* suppose no "accept" found first */
		/* /proc/IPFIRE/policy contains a string, ending with
		 * "accept" if the default policy is accept.
		 */
		if(fgets(line, 127, fp) != NULL)
		{
			for(i = 0; i <= strlen(line) - 6; i++)
				if(strncmp(line + i, "accept", 6) == 0)
					val = 1;
		}
		fclose(fp);val = 0; /* no "accept" found */
	}
	return val;
}

/* returns -1 if fails, 0 otherwise */
int write_rmem_default(unsigned int n)
{
	FILE *fp;
	char filenam[64] = "/proc/sys/net/core/rmem_default";

	if((fp = fopen(filenam, "w")) == NULL)
	{
		printf("Error opening \"%1\" for writing", filenam);
		perror("");
		return -1;
	}
	else
	{
		fprintf(fp, "%d", n);
		fclose(fp);
		return 0;
	}
}

/* returns -1 if fails, 0 otherwise */
int write_rmem_max(unsigned int n)
{
	FILE *fp;
	char filenam[64] = "/proc/sys/net/core/rmem_max";

	if((fp = fopen(filenam, "w")) == NULL)
	{
		printf("Error opening \"%1\" for writing", filenam);
		perror("");
		return -1;
	}
	else
	{
		fprintf(fp, "%d", n);
		fclose(fp);
		return 0;
	}
}

/* returns -1 if fails, 0 otherwise.
 * accepts 0 for drop, > 0 for accept.
 */
int write_policy(unsigned short p)
{
	FILE *fp;
	char filenam[64] = "/proc/IPFIRE/policy";

	if((fp = fopen(filenam, "w")) == NULL)
	{
		printf("Error opening \"%1\" for writing", filenam);
		perror("");
		return -1;
	}
	else
	{
		/* /proc/IPFIRE/policy contains a string, ending with
		* "accept" if the default policy is accept.
		*/
		if(p > 0) /* accept */
			fprintf(fp, "accept");
		else
			fprintf(fp, "drop");
		fclose(fp);
		return 0;
	}
}

int check_proc_entries(short policy, unsigned proc_rmem_max, unsigned proc_rmem_default)
{
	if(getuid() != 0)
		return -1;
	if(policy != -1)
	{
		if(read_policy() != policy)
		{
			printf(TR("Updating default policy for packets without a rule: "));
			if(write_policy(policy) >= 0)
			{
				if(policy > 0)
					PGRN, printf(TR("accept")), PNL;
				else
					PRED, printf(TR("drop")), PNL;	  
			}
			else
			{
				PRED, printf(TR("failed")), PNL;
				return -1;
			}
		}
	}
// 	else
// 		printf(TR("Not updating default policy: not specified in config file")), PNL;
	
	if(proc_rmem_max != -1)
	{
		if(read_rmem_max() != proc_rmem_max)
		{
			printf(TR("Updating /proc/sys/net/core/rmem_max "));
			if(write_rmem_max(proc_rmem_max) >= 0)
				PGRN, printf("%d\n", 	 proc_rmem_max); 
			else
			{
				PRED, printf(TR("failed")), PNL;
				return -1;
			}
		}
		
	}
// 	else
// 		printf(TR("Not updating /proc/sys/net/core/rmem_max: not specified in config file")), PNL;
	
	if(proc_rmem_default != -1)
	{
		if(read_rmem_default() != proc_rmem_default)
		{
			printf(TR("Updating /proc/sys/net/core/rmem_default "));
			if(write_rmem_default(proc_rmem_default) >= 0)
				PGRN, printf("%d\n", 	 proc_rmem_default); 
			else
			{
				PRED, printf(TR("failed")), PNL;
				return -1;
			}
		}
	}
// 	else
// 		printf(TR("Not updating /proc/sys/net/core/rmem_default: not specified in config file")), PNL;
	return 0;
}

