#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "includes/languages.h"
#include "includes/colors.h"
#include "includes/ipfire_userspace.h"

#define MAXLANGLINELEN 1024

/* Returns the greatest value between a and b */
int greatest(int a, int b)
{
	if(a > b)
		return a;
	else
	 	return b;
}

/* rc on means that the program has been started with rc option and
 * so no information about language has to be printed out.
 */
int allocate_translation_strings(const char* lang_filename, short rc)
{
	unsigned counter = 0, i = 0, j, equal_present, linecount = 0;
	float allocsize = 0;
	char line[MAXLANGLINELEN];
	char homedir[PWD_FIELDS_LEN];
	char full_filename[MAXFILENAMELEN];
	FILE* fp;
	lang_strings = NULL;
	strcpy(full_filename, "");
	
	/* No filename given: default language */
	if(strlen(lang_filename) == 0)
	{
		if(!rc)
			printf("[" GRAY "default" CLR "]");
		return 0;
	}
	/* Try to detect language */
	if(!rc)
	{
		printf("[");
		if( (strncmp(lang_filename, "it", 2) == 0) ||
				(strncmp(lang_filename, "IT", 2) == 0) )
			printf(GRAY "italiano" CLR);
		else if( (strncmp(lang_filename, "en", 2) == 0) ||
				(strncmp(lang_filename, "EN", 2) == 0) )
			printf(GRAY "english" CLR);
		else if( (strncmp(lang_filename, "es", 2) == 0) ||
				(strncmp(lang_filename, "ES", 2) == 0) )
			printf(GRAY "espanol" CLR);
		else if( (strncmp(lang_filename, "fr", 2) == 0) ||
				(strncmp(lang_filename, "FR", 2) == 0) )
			printf(GRAY "francais" CLR);
	}
	/* Add others.. */
	/* Get user's home directory */
	get_user_info(HOMEDIR, homedir); 
  	/* PWD_FIELDS_LEN is 20, filenames are MAXFILENAMELEN (60) */
  	/* Compose language pack filename. */
	if(strlen(homedir) + strlen("/.IPFIRE/languages/") + strlen(lang_filename) > MAXFILENAMELEN - 1)
	{
		PRED, printf("language file name path too long! Cannot continue!"), PNL;
		return -1;
	}
  	strncat(full_filename, homedir, MAXFILENAMELEN - 1 - strlen(full_filename) );
  	strncat(full_filename, "/.IPFIRE/languages/",  MAXFILENAMELEN - 1 - strlen(full_filename) );
	strncat(full_filename, lang_filename, MAXFILENAMELEN - 1 - strlen(full_filename) );
	
	fp = fopen(full_filename, "r");
	if(fp == NULL)
	{
		printf(RED "Error opening language file \"%s\"." NL, 
			full_filename);
		return -1;
	}
	while(fgets(line, MAXLANGLINELEN, fp) != NULL)
	{
		if(strlen(line) > 0)
		{
			/* count lines which aren't comments and aren't empty */
			if(line[0] != '#' && line[0] != '\n')
				counter++;
		}
	}
	
	if(fseek(fp, 0L, SEEK_SET)  != 0)
	{
		PRED, printf("Error rewinding the file!");
		perror("");
		PNL, PNL;
		return -1;
	}

	lang_strings = (char **) malloc(sizeof(char*) * counter);
	if(lang_strings == NULL)
	{
		printf(RED "Error allocating memory for language strings!" NL);
		perror("");
		return -1;
	}
	
	i = 0;
	while(fgets(line, MAXLANGLINELEN, fp) != NULL)
	{
		linecount++;
		equal_present = 0;
		
		if(strlen(line) > 0 && (line[0] == '#' || line[0] == '\n') )
		{
			/* A comment or a single newline: don't allocate, don't 
			 * save the string. */	
		}
		else if(strlen(line) > 0) /* A valid language line */
		{
			if(i >= counter)
			{
				PRED, printf("Error! Trying to allocate %d lines on a %d allocated pointer!",
					i, counter),
				PNL, PNL;
				break;
			}
			/* +1 for '\0' ! */
			lang_strings[i] = (char*) malloc(sizeof(char) * (strlen(line) + 1) );
			if(lang_strings[i] == NULL)
			{
				printf(RED "Error allocating memory for %d language string!" NL,
					i+1 );
				perror("");
				return -1;
			}
			memset(lang_strings[i], 0, strlen(line) + 1 );
			strncpy(lang_strings[i], line, strlen(line) + 1);
			for(j = 0; j < strlen(line); j++)
			{
				if(line[j] == '=')
					equal_present++;
			}
			if(equal_present != 1)
			{
				printf(NL VIOLET "[WARNING: malformed translation string on file \"%s\"\n"
					" at line %u: %u '=' characters found:\n"
					" there should be one and only one '=' per line!] " CLR
					, lang_filename, linecount, equal_present);
			}
			i++;
			allocsize += strlen(line) + 1; /* +1 for the '\0' */
		}
	}
	if(!rc)
	{
		printf(GRAY ", %.2fkB" CLR "]...", (allocsize/(float)1e3) );
	}
	fclose(fp);
	return nlines = counter;
}

char* translation(const char* eng)
{
	unsigned int i = 0, j, k;
	unsigned int backslash_pos = 0;
	char engline[MAXLANGLINELEN];
	
	memset(langline, 0, MAXLANGLINELEN);
	
	/* initialize return value to original english string,
	 * in case we do not find a matching translation.
	 */
	strncpy(langline, eng, MAXLANGLINELEN);
	
	while(i < nlines)
	{
		j = 0;
		backslash_pos = 0;
		if(lang_strings[i] == NULL)
			goto next;
		j = 0, k = 0;
		while(lang_strings[i][j] != '=' && lang_strings[i][j] != '\0'
				&& lang_strings[i][j] != '\n' && k < MAXLANGLINELEN-1 )
		{
			if(lang_strings[i][j] != '\\')
			{
				engline[k] = lang_strings[i][j];
				k++;
			}
			j++;
		}
		engline[j] = '\0'; /* terminate string */
		
		if(strcmp(eng, engline) == 0)
		{
			if(strlen(eng) == 1 && strlen(engline) != 1)
			{
				/* eng is made up of one character, while
				 * translation is not. Pass by.
				 */
			}
			else
			{
				j++; /* Pass '=' */
				k = 0;
				while(lang_strings[i][j] != '\0' && lang_strings[i][j] != '\n'
					&& k < MAXLANGLINELEN-1 )
				{
					langline[k] = lang_strings[i][j];
					j++;
					k++;
				}
				langline[k] = '\0';
				return langline; /* langline is static */
			}
		}
		next:	
		i++; /* Point to next line */
		//printf(RED "no match!! \"%s\"/\"%s\"" NL, engline, eng);
	}
	
	return langline;
}

/* Returns the translation of the char.
 * Remember that the user will type the char in
 * his own language, and so translation must be
 * inverted.
 */
char char_translation(char c)
{
	char ch_str[2];
	/* Build a simple string formed by the char c */
	ch_str[0] = c;
	ch_str[1] = '\0';
	
	return translation(ch_str)[0];
}

int free_lang_strings(void)
{
	if(lang_strings == NULL) /* not allocated */
		return 0;
	unsigned i = 0;
	while( i < nlines)
	{
		if(lang_strings[i] != NULL)
			free(lang_strings[i]);
		i++;
	}
	
	free(lang_strings);
	nlines = 0;
	return i;
}
