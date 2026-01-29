#define _GNU_SOURCE  /* for strcasestr */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/* The compiler used to compile the kernel must have the same major and 
 * minor version as the current compiler used to build the kernel module.
 * Otherwise, the kernel module won't work and cause kernel crashes.
 */

int get_kernel_gcc_version(char *s);

int main(int argc, char **argv)
{
	char *str;
	int ret;
	if(argc != 2)
	{
		printf("\e[1;31m*\e[0m Usage: %s string (/proc/version string)\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	/* read the string and look for "Linux version" */
	str = strcasestr(argv[1], "Linux version");
	if(str == NULL)
	{
		printf("\e[1;31m* \e[0mthe string \"Linux version\" wasn't found in the\n"
			"  command line argument. Did you really pass \"/proc/version\"\n"
			"  output string as command line parameter?\n");
		exit(EXIT_FAILURE);
	}
	/* the string contains "Linux version"... ahead it should contain the gcc version.
	 * We do not look for kernel version since we know that ipfire-wall only works with
	 * the 2.6.x version and 2.6.x kernels require major and minor version be equal.
	 */
	str = strcasestr(argv[1], "(gcc");
	if(str == NULL)
		str = strcasestr(argv[1], "(version gcc");
	if(str == NULL)
	{
		printf("\e[1;31m*\e[0m Not the string \"(gcc\" nor the string \"(version gcc\"\n"
			"  were found on the command line argument provided: are you sure you\n"
			"  specified the output of /proc/version [something like\n"
			"  \"Linux version 2.6.27-gentoo-11_I-08 (root@woody) (gcc version 4.3.2 (Gentoo 4.3.2 p1.0) ) #1 SMP...\"]?\n");
		exit(EXIT_FAILURE);
	}
	else
	{
		ret = get_kernel_gcc_version(str);
		switch(ret)
		{
			case 0:
				
			break;

			case 1:

			break;
		}
	}


}

int get_kernel_gcc_version(char *s)
{
	int maj, min;
	int gcc_maj = __GNUC__;
	int gcc_min = __GNUC_MINOR__;
	int i, j;
	char tmp[8];
	/* look for X.X.X into the gcc version - really we are only interested in major and minor version */
	for(i = 0; i < strlen(s) && !isdigit(s[i]); i++)
		; /* pass all characters that are not numbers */
	/* i points to the first number in the string */
	j = 0;
	while(i < strlen(s) && s[i] != '.' && j < 8)
	{
		tmp[j] = s[i];
		i++;
		j++;
	}
	if(i == strlen(s) || j == 8)
	{
		printf("\e[1;31m*\e[0m no gcc version in the form X.X.X found in the string \"%s\"\n", s);
		return -1;
	}
	tmp[j] = '\0'; /* terminate correctly the major version */
	maj = atoi(tmp);
	/* pass the '.' char */
	i++;
	/* look for minor version */
	j = 0;
	while(i < strlen(s) && j < 8 && s[i] != '.')
	{
		tmp[j] = s[i];
		j++;
		i++;
	}
	if(j == 8 || i == strlen(s))
	{
		printf("\e[1;31m*\e[0m no gcc minor version in the form X.X.X found in the string \"%s\"\n", s);
		return -1;
	}
	tmp[j] = '\0';
	min = atoi(tmp);
	if(min == gcc_min && maj == gcc_maj)
	{
		printf("\e[1;32m*\e[0m good: kernel was compiled with gcc %d.%d.x and the current compiler version is %d.%d.x\n",
			maj, min, gcc_maj, gcc_min);
		return 0;
	}
	else
	{
		printf("\e[1;31m* \e[0mthe gcc version with which the kernel was compiled differs from the current version:\n"
			"  kernel was compiled with gcc-%d.%d.x\n"
			"  the current compiler is  gcc-%d.%d.x\n"
			"  Either rebuild the kernel with the current compiler or build ipfire-wall with the old compiler that\n"
			"  the kernel was built with.\n"
			"\e[1;31m*\e[0m Compiling ipfire-wall kernel module with this gcc version mismatch will definitely\n"
			"  break your system!\n", maj, min, gcc_maj, gcc_min);
		return 1;
	}

	

}






