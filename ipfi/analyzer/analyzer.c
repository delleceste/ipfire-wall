#include "analyzer.h"

/* variabili globali */
struct anpacket * apvect;
struct anopts ops;
struct global_ustats ustats;

int errnotend = 0;

void signal_handler(int signum);

void signal_handler(int signum)
{
	printf(NL GREEN "signal_handler(): chiusura di analyzer.\n" NL);
	g_reset_term();
	exit(EXIT_SUCCESS);
}

void init_options(struct anopts* ops)
{
	strcpy(ops->infilename, "/var/log/ipfire.log");
	strcpy(ops->outfilename, "./analysis");
	strcpy(ops->tmpfilename, "./tmpan");
	ops->resolve = 1;
	ops->quiet = 0;
	ops->srvc_resolve = 1;
	ops->tcpflags = 0;
}

int get_options(int argc, char* argv[], struct anopts * ops)
{
	unsigned i = 1;
	while(i < argc)
	{
		if(strcmp(argv[i], "quiet") == 0)
			ops->quiet = 1;
		else if(strcmp(argv[i], "noresolve") == 0)
			ops->resolve = 0;
		else if(strcmp(argv[i], "nosvc") == 0)
			ops->srvc_resolve = 0;
		else if(strcmp(argv[i], "tcpflags") == 0)
			ops->tcpflags = 1;
		else if(strcmp(argv[i], "in" ) == 0)
		{
			if(argc <= i + 1)
			{
				printf(RED "Error: parameter %s must be followed by input filename" NL,
				       argv[i]);
				 exit(EXIT_FAILURE);
			}
			i++;
			/* leave 20 bytes free for suffix */
			strncpy(ops->infilename, argv[i], MAXFILENAMELEN-20);
		}
		else if(strcmp(argv[i], "out" ) == 0)
		{
			if(argc <= i + 1)
			{
				printf(RED "Error: parameter %s must be followed by output filename" NL,
				       argv[i]);
			}
			i++;
			strncpy(ops->outfilename, argv[i], MAXFILENAMELEN-20);
		}
		else
		{
			printf(RED "Parameter %s not valid!" NL NL, argv[i]);
			printf("Usage: %s in INPUT_LOGFILE out OUT_LOGFILE [quiet|nosvc|noresolve]"
					NL NL, argv[0]);
			exit(EXIT_FAILURE);
		}
		i++;
	}
	return i;
}

void print_options(const struct anopts* ops)
{
	printf(NL CYAN "--------------------------------------------------" NL);
	if(ops->quiet)
		printf("- Output will be directed only to file %s.\n",
		       ops->outfilename);
	if(ops->srvc_resolve == 0)
		printf("- Ports which could be resolved in service names will be left numeric.\n");
	if(ops->resolve == 0)
		printf("- Internet names won't be resolved\n(you don't need Internet connection).\n");
	
	printf("- Files: %s -> %s\n", ops->infilename, ops->outfilename);
	printf(CYAN "--------------------------------------------------" NL);
	printf(NL);
}

int get_nlines(const char* filename)
{
	int counter=0;
	char line[MAXLINELEN];
	FILE* fin;
	
	if( (fin = fopen(filename, "r") ) == NULL)
	{
		printf(RED "Error opening input file \"%s\" for reading" CLR, filename);
		perror("");
		return -1;
	}
	while(fgets(line, MAXLINELEN, fin) != NULL)
		counter ++;
	fclose(fin);
	return counter;
}

int clean_log(const struct anopts* ao)
{
	FILE* fin;
	FILE* ftmp;
	char line[MAXLINELEN];
	int counter = 0;
	
	if( (fin = fopen(ao->infilename, "r") ) == NULL)
	{
		printf(RED "Error opening input file \"%s\" for reading" CLR, ao->infilename);
		perror("");
		return -1;
	}
	if( (ftmp = fopen(ao->tmpfilename, "w") ) == NULL)
	{
		printf(RED "Error opening temp file \"%s\" in write mode" CLR, ao->infilename);
		perror("");
		return -1;
	}
	
	while(fgets(line, MAXLINELEN, fin) != NULL)
	{
		/* copy line if it starts with info useful to analyzer */
		if( (strncmp(line, "+", 1) == 0) |
				   (strncmp(line, "-", 1) == 0) |
				   (strncmp(line, "|", 1) == 0) )
		{
			fprintf(ftmp, "%s", line); 
			counter ++;
		}
		else
		{
			printf("\r                                                                              \r");
			if( (strlen(line) > 0) & (line[strlen(line) -1] == '\n') )
				line[strlen(line) - 1] = '\0';
			printf(VIOLET "\rRemoving line " CLR "%s", line );
			fflush(stdout);
		}
	}
	fclose(ftmp);
	fclose(fin);
	return counter;
}

int get_nchunks(const char* infile)
{
	FILE* ftmp;
	char line[MAXLINELEN];
	int chunks = 0;
	
	if( (ftmp = fopen(infile, "r") ) == NULL)
	{
		printf(RED "Error opening temp file \"%s\"" CLR,
		      infile);
		perror("");
		return -1;
	}
	while(fgets(line, MAXLINELEN, ftmp) != NULL)
	{
		if(strncmp(line, "+", 1) == 0)
			chunks ++;
	}
	fclose(ftmp);
	return chunks;
}

int get_date_and_time(const char* line, struct aninfo* ai)
{
	return sscanf(line, "+%d-%d-%d-%d/%d:%d:%d:%s\n",
		      &ai->tm.tm_wday, &ai->tm.tm_mday, &ai->tm.tm_mon,
		      &ai->tm.tm_year, &ai->tm.tm_hour, &ai->tm.tm_min, &ai->tm.tm_sec,
			ai->username);
}

int get_exit_info(const char* line, struct aninfo* ai)
{
	return sscanf(line, "-%d-%d-%d-%d/%d:%d:%d#TOT:%lu#LOST:%lu#%s\n",
		      &ai->tmexit.tm_wday, &ai->tmexit.tm_mday, &ai->tmexit.tm_mon,
		      &ai->tmexit.tm_year, &ai->tmexit.tm_hour, &ai->tmexit.tm_min, 
		      &ai->tmexit.tm_sec, &ai->total_packets, &ai->upackets_lost,
		      ai->username);    
}

int get_right_position(FILE* fp, int chunk, struct aninfo* ai)
{
	char line[MAXLINELEN];
	int chcount = 0; /* chunk count */
	unsigned long nline = 0;
	short start_found = 0;
	short end_found = 0;
	
	while(fgets(line, MAXLINELEN, fp) != NULL)
	{
		nline ++;
		if( ! strncmp(line, "+", 1) ) /* found a start marker */
		{
			/* il numero di chunk corrisponde */
			if(chunk == chcount)
			{
				if(get_date_and_time(line, ai) <= 0)
				{
					printf(RED "Error getting date" NL);
					return -1;
				}
				ai->begpos = nline;
				start_found = 1;
			}
			else
				/* ho trovato un nuovo start marker ma ancora 
				* chcount e' inferiore al numero richiesto */
				chcount ++;				
		}
		else if( (!strncmp(line, "-", 1) )& (start_found==1) )
		{
			/* found an ending delimiter */
			ai->endpos = nline;
			get_exit_info(line, ai);
			end_found = 0;
			return ai->begpos;
		}
	}
	if( (start_found) & (!end_found) )
	{
		ai->endpos = nline;
		printf(NL NL VIOLET UNDERL  "WARNING" CLR VIOLET ":\n"
				"LOG FILE DOES NOT END WITH CORRECT MARKER.\n"
				"SOME INFORMATION WILL BE WRONG!" NL);
		errnotend = 1;
		return ai->begpos;
	}
	return 0;
}

int get_packet_and_add_to_vector(int index, struct anpacket* anp, 
				 const char* line)
{
	int ret;

	/* get packet */
#ifdef ENABLE_RULENAME
	ret = sscanf(line,
		     "|%d|%d|%d|%d|%16[^|]|%16[^|]|%d|%lu|%16[^|]|%d|%16[^|]|%d|%d|%d|%d|%d|%d|%d|%20[^|]|\n",
		     &anp->nat, &anp->response, &anp->state, &anp->direction, anp->in_device,
		     anp->out_device, &anp->protocol, &anp->id, anp->saddr, &anp->sport, 
		     anp->daddr,  &anp->dport, &anp->syn, &anp->ack, &anp->fin, &anp->urg, 
		     &anp->psh, &anp->rst, &anp->rulename);	
#else
	ret = sscanf(line,
	"|%d|%d|%d|%d|%16[^|]|%16[^|]|%d|%lu|%16[^|]|%d|%16[^|]|%d|%d|%d|%d|%d|%d|%d|\n",
		     &anp->nat, &anp->response, &anp->state, &anp->direction, anp->in_device,
		     anp->out_device, &anp->protocol, &anp->id, anp->saddr, &anp->sport, 
		     anp->daddr,  &anp->dport, &anp->syn, &anp->ack, &anp->fin, &anp->urg, 
		     &anp->psh, &anp->rst);	
#endif
// 	printf("URG: %d, RST: %d, PSH:%d\n", anp->urg, anp->rst, anp->psh);	 
	/* inizializziamo anche i campi resolve */
	strncpy(anp->saddr_resolved, anp->saddr, INET_ADDRSTRLEN);
	strncpy(anp->daddr_resolved, anp->daddr, INET_ADDRSTRLEN);
	snprintf(anp->sport_res, 6, "%d", anp->sport );
	snprintf(anp->dport_res, 6, "%d", anp->dport );
	strcpy(anp->saddr_alias1, "");
	strcpy(anp->saddr_alias2, "");
	strcpy(anp->daddr_alias1, "");
	strcpy(anp->daddr_alias2, "");
	/* poniamo a 0 il contatore di occorrenze dell'anpacket */
	anp->counter = 0;
	/* add to vector */
	apvect[index] = *anp;
	return ret;
}

/* returns 1 if the number of bars "|" in line is correct,
 * 0 otherwise. This function avoids parsing unterminated
 * lines */
int expected_number_of_bars(const char* line)
{
	unsigned int i = 0;
	unsigned short int bars = 0;
	while( (i < strlen(line) ) & ( i < MAXLINELEN) )
	{
		if(line[i] == '|')
			bars ++;
		i++;
	}
	if(bars != 20)
		return 0;
	return 1;
}

int process_chunk(int chunk, const char* tmpfile, char* outfile)
{
	unsigned long int i = 0;
	int pos = 0;
	char suffix[20];
	FILE* fpin, *fpout;
	struct aninfo ai;
	char line[MAXLINELEN];
	struct anpacket anpa;
	char ofile[MAXFILENAMELEN];
	unsigned long int sum;
	int addr_resolved = 0;
	int ports_resolved = 0;
	unsigned long allocsize = 0;
	unsigned long alloc_elems = 0;
	float allocmeg = 0;
	short exp_numlines = 1;
	short last_line = 0;
	unsigned long linecnt = 0;
	
	memset(&ai, 0, sizeof(struct aninfo) );
	strncpy(ofile, outfile, MAXFILENAMELEN - 20);
	
	if( (fpin = fopen(tmpfile, "r") ) == NULL)
	{
		perror(RED "Error opening temporary file" CLR);
		return -1;
	}
	pos = get_right_position(fpin, chunk, &ai);
	ai.tm.tm_year = ai.tm.tm_year - 1900;
	ai.tmexit.tm_year = ai.tmexit.tm_year - 1900;
	printf(NL "Chunk %d begins at line %d of logfile, ends at line %d." 
			NL, chunk+1, pos, ai.endpos);
	
	/* allochiamo la memoria necessaria a contenere tutti i pacchetti */
	/* ci sarebbero end - beg + 1 righe, da cui pero' ne tolgo due
	* che sono quelle dei delimitatori */
	apvect = (struct anpacket*) malloc(sizeof(struct anpacket) * 
			(ai.endpos - ai.begpos + 1 - 2) );
	
	printf("Allocated %d spaces.\n", ai.endpos - ai.begpos + 1 -2);
	
	alloc_elems = ai.endpos - ai.begpos + 1 -2;
	allocsize = sizeof(struct anpacket) * alloc_elems;
	
	allocmeg =  (float) allocsize / (float) (1024 * 1024);
	
	
		printf(NL "Size needed to dynamically allocate memory for chunk %d\nis "
			RED "%.2f" CLR " KB, i.e. " RED "%.2f" CLR " MB.\n",
			chunk,
			 (float) allocsize / (float) 1024, 
			 allocmeg );
	if(allocmeg > 8)
	{
		printf("Do you want to continue [y | other]? ");
		if(g_getchar() != 'y')
		{
			return 0;
		}
	}
	/* apriamo il file di output corrispondente */
	snprintf(suffix, 20, ".%d.%d-%d.%d.%d", ai.tm.tm_mday,
		 ai.tm.tm_mon, ai.tm.tm_hour, ai.tm.tm_min,
		 ai.tm.tm_sec);
	
	strncat(ofile, suffix, 20);
	
	if( (fpout = fopen(ofile, "w") ) == NULL)
	{
		printf(RED "Error opening file \"%s\" in write mode" CLR, ofile);
		perror("");
		return -1;
	}
	
	/* abbiamo il file di output aperto e consciamo la riga di inizio e di fine
	 * delle informazioni utili */
	rewind(fpin);
	i = 0;
	while(fgets(line, MAXLINELEN, fpin) != NULL)
	{
		i++;
		if( i == ai.begpos)
			break;
	}
	i = 0;
	printf(NL "processing chunk %d.\n", chunk + 1);
	while(fgets(line, MAXLINELEN, fpin) != NULL)
	{
		/* trovato un end delimiter, possiamo uscire */
		if( ( (last_line = strncmp(line, "-", 1) == 0) ) | 
				   (! (exp_numlines = expected_number_of_bars(line) ) ) )
		{
			if( (! exp_numlines) & (!last_line) )
			{
				printf(VIOLET "Warning: line %lu of chunk %d is truncated!" NL, 
				       linecnt+1, chunk+1);
				printf(NL "- Press a key to go on, line will not be considered.\n");
				g_getchar();
				goto next;
			}
			goto analyze;
		}
		else
		{
			//printf("%s", line);
// 			printf("i:%d ", i);
			get_packet_and_add_to_vector(i, &anpa, line);
			i++;
		}
		next:
		linecnt ++;
	}
	
	analyze:
	/* analizziamo passando il puntatore al file che 
	* conterra' l'output */
	analyze(fpout, i);
	
	if(ops.resolve)
	{
		if( (addr_resolved = resolve_addresses(i) ) < 0)
			printf(RED "\nERROR RESOLVING INTERNET NAMES!" NL NL);
		else
			printf("Resolved " GREEN "%d" CLR " addresses!" NL,
			       addr_resolved);
	}
	else
		printf(VIOLET "Internet addresses will not be resolved." NL);
	
	if(ops.srvc_resolve)
	{
		if( (ports_resolved = resolve_ports(i) ) < 0)
			printf(RED "\nERROR RESOLVING SERVICE NAMES!" NL NL);
		else
			printf("Resolved " GREEN "%d" CLR " service names!" NL,
			       ports_resolved);
	}
	else
		printf(VIOLET "Service names will not be resolved." NL);
	
	memset(&ustats, 0, sizeof(ustats) );
	
	make_stats(i);
	
	printf(NL GRAY "- Packets processed: %lu, total packets: %lu.\n"
			"- Packets lost in kernel/user communication: %lu." NL NL,
	      		i, ai.total_packets, ai.upackets_lost);
	
	print_results(i);
	
	printf(NL BLUE "------------------------------------------------------------"NL);
	printf(YELLOW UNDERL "SUMMARY" CLR ":" NL);
	printf(GREEN "%lu" CLR " packets have been analyzed.\n", 
	       sum = sum_on_counters(i) );
	
	printf("%lu packets have been lost over %lu during kernel/user" NL
			"communication [" VIOLET "%.2f" CLR "%%]" NL, 
			ai.upackets_lost, sum, 
			((float) ai.upackets_lost / (float) sum ) * 100);
	
	calculate_percentages();
	print_ustats();
	print_time_info(&ai);
	printf( BLUE "------------------------------------------------------------"NL);
	
	if(errnotend)
		printf(NL NL VIOLET UNDERL  "WARNING" CLR VIOLET ":\n"
				"LOG FILE DOES NOT END WITH CORRECT MARKER.\n"
				"SOME INFORMATION WILL BE WRONG!" NL);
	
	printf(NL "Closing output file \"%s\"\nand freeing memory... ", ofile);
	fclose(fpin);
	fclose(fpout);
	free(apvect);
	printf("\t[" GREEN "OK" CLR ".]" NL NL);
	return 1;
}

unsigned long sum_on_counters(unsigned long int apnum)
{
	unsigned long int sum = 0;
	unsigned long int i = 0;
	while(i < apnum)
	{
		if(apvect[i].counter > 0)
			sum += apvect[i].counter;
		i++;
	}
	return sum;
}

void calculate_percentages(void)
{
	if(ustats.tot_in != 0)
	{
		ustats.perc_in_drop = ( (float) ustats.in_drop / (float) ustats.tot_in) * 100;
		ustats.perc_in_drop_impl = ( (float) ustats.in_drop_impl / 
				(float) ustats.tot_in) * 100;
	}
	if(ustats.tot_out != 0)
	{
		ustats.perc_out_drop = ( (float) ustats.out_drop /  (float) ustats.tot_out) * 100;
		ustats.perc_out_drop_impl =  ( (float) ustats.out_drop_impl /  
			(float)  ustats.tot_out) * 100;
	}
	
	if(ustats.tot_fwd != 0)
	{
		ustats.perc_fwd_drop = ( (float) ustats.fwd_drop / (float)  ustats.tot_fwd) * 100;
		ustats.perc_fwd_drop_impl =( (float) ustats.fwd_drop_impl /  
			(float) ustats.tot_fwd) * 100;
	}
}

void make_stats(unsigned long nelems)
{
	unsigned long i = 0;
	struct anpacket *anp;
	while(i < nelems)
	{
		anp = &apvect[i];
		switch(anp->direction)
		{
			case IN:
				ustats.tot_in ++;
				switch(anp->response)
				{
					case BOH:
						ustats.in_drop++;
						ustats.in_drop_impl ++;
						break;
					case DEN:
						ustats.in_drop ++;
						break;
					case PERM:
						ustats.in_acc ++;
						break;
					default:
						break;
				}
				break;
				
			case OUT:
				ustats.tot_out ++;
				switch(anp->response)
				{
					case BOH:
						ustats.out_drop++;
						ustats.out_drop_impl ++;
						break;
					case DEN:
						ustats.out_drop ++;
						break;
					case PERM:
						ustats.out_acc ++;
						break;
					default:
						break;
				}
				break;
				
			case FWD:
				ustats.tot_fwd ++;
				switch(anp->response)
				{
					case BOH:
						ustats.fwd_drop++;
						ustats.fwd_drop_impl ++;
						break;
					case DEN:
						ustats.fwd_drop ++;
						break;
					case PERM:
						ustats.fwd_acc ++;
						break;
					default:
						break;
				}
				break;
					
			case PRE:
				ustats.prerouted ++;
				break;
			case POST:
				ustats.postrouted ++;
				break;
		}
		if(anp->state)
			ustats.stateful ++;
		i++;
	}
}

void restore_color(int direction)
{
	switch(direction)
	{
		case IN:
			printf(GREEN);
			break;
		case OUT:
			printf(CYAN);
			break;
		case PRE:
			printf(MAROON);
			break;
		case POST:
			printf(MAROON);
			break;
		case FWD:
			printf(YELLOW);
			break;
	}
}

void print_anentry(const struct anpacket *anp)
{
	int i  =0;
	
	switch(anp->direction)
	{
		case IN:
			printf(GREEN "|IN|  ");
			break;
		case OUT:
			printf(CYAN "|OUT| ");
			break;
		case PRE:
			printf(MAROON "|PRE| ");
			break;
		case POST:
			printf(MAROON "|POST|");
			break;
		case FWD:
			printf(YELLOW "|FWD| ");
			break;
	}
	if(anp->direction == FWD)
		printf( CLR "[%s->%s] ", anp->in_device, anp->out_device);
	if(strcmp(anp->in_device, "n.a.") )
		printf(CLR "[%s] ", anp->in_device);
	if(strcmp(anp->out_device, "n.a.") )
		printf(CLR "[%s] ", anp->out_device);
	printf(MAROON);
	switch(anp->nat)
	{
		case SNAT:
			printf("|SNAT|");
			break;
		case DNAT:
			printf("|DNAT|");
			break;
		case MASQ:
			printf("|MASQ|");
			break;
	}
	if(anp->state)
		printf(YELLOW "|STATE|" CLR);
	
	restore_color(anp->direction);
	if( (ops.tcpflags) & (anp->protocol == TCP) )
	{
		printf(" ");
		if(anp->syn == SYN)
			printf("\e[1;46;37m" "SYN" CLR"|");
		if(anp->ack == ACK)
			printf("\e[1;46;37m" "ACK" CLR"|");
		if(anp->fin == FIN)
			printf("\e[1;46;31m" "FIN" CLR"|");
		if(anp->urg== URG)
			printf("\e[1;41;37m" "URG" CLR"|");
		if(anp->psh == PSH)
			printf("\e[1;41;33m" "PSH" CLR"|");
		if(anp->rst == RST)
			printf("\e[1;41;36m" "RST" CLR"|");	
		printf(" ");	
	}
	
	
	
	i = 0;
	if(ops.resolve)
	{
		printf("%s:%s --> %s:%s [%lu] ",
		       anp->saddr_resolved, anp->sport_res, 
		       anp->daddr_resolved, anp->dport_res,
		       anp->counter);
		if(anp->sunresolved)
			printf(RED "SRC UNRES" CLR "!  ");
		if(anp->dunresolved)
			printf(DRED "DST UNRES" CLR "!  ");
	}
	else
	{
		printf("%s:%d --> %s:%d [%lu] ",
	     	  anp->saddr, anp->sport, anp->daddr, anp->dport,
	     	  anp->counter);
	}
	if(anp->response == DEN)
	{
		printf(RED "X" );
#ifdef ENABLE_RULENAME
		printf(CLR "[" DRED "%s" CLR "]", anp->rulename);
#endif	
	}
	else if(anp->response == PERM)
	{
		printf(GREEN "OK");
#ifdef ENABLE_RULENAME
		printf(CLR "[" DGREEN "%s" CLR "]", anp->rulename);
#endif
	}
	else if(anp->response == BOH)
		printf(VIOLET "?" );
	printf(NL);
	if(ops.resolve)
	{
		if(! print_alias(anp) )
			; //printf(NL);
	}
	else if(anp->nat != EMPTY)
		printf(NL);
}

int print_alias(const struct anpacket* anp)
{
	int ret = 0;
	if(strlen(anp->saddr_alias1) > 0)
		printf(VIOLET "ALIAS: %s\t", anp->saddr_alias1);
	
	if(strlen(anp->daddr_alias1) > 0)
		printf(CLR " -->\t" DVIOLET "%s", anp->daddr_alias1);

	if( (strlen(anp->saddr_alias1) > 0 ) |
		     (strlen(anp->daddr_alias1) > 0) )
	{
		printf("\n");
		ret = 1;
	}
	
	/* 2nd alias */
	if(strlen(anp->saddr_alias2) > 0)
		printf(VIOLET "ALIAS 2: %s\t", anp->saddr_alias2);
	
	if(strlen(anp->daddr_alias2) > 0)
		printf(CLR " -->\t" DVIOLET "%s", anp->daddr_alias2);
	if( (strlen(anp->saddr_alias2) > 0 ) |
		    (strlen(anp->daddr_alias2) > 0) )
	{
		printf("\n");
		ret = 1;
	}	
	return ret;			
}

int print_results(unsigned long int nentries)
{
	int i = 0;
	while(i < nentries)
	{
		/* c'e' stata almeno un'occorrenza */
		if(apvect[i].counter > 0) 
		{
			print_anentry(&apvect[i]);
		}
		i++;
	}
	return 0;
}

void print_ustats(void)
{
	printf(NL UNDERL RED "%lu" CLR " " UNDERL RED "PACKETS" CLR ":" NL,
	      ustats.tot_in + ustats.tot_out + ustats.tot_fwd + 
			      ustats.prerouted + ustats.postrouted);
	printf("IN: %lu\t\tOUT: %lu\tFORWARDED:%lu\n"
			"PREROUTED: %lu\tPOST ROUTED: %lu" NL NL,
		ustats.tot_in, ustats.tot_out, ustats.tot_fwd, ustats.prerouted,
		ustats.postrouted);
	
	/* INPUT */
	if(ustats.tot_in != 0)
	{
		printf(RED "DROPPED" CLR 
			" IN PACKETS: %lu [%.1f%%], OF WHICH %lu IMPLICITLY [%.1f%%]."
			NL, ustats.in_drop, ustats.perc_in_drop, ustats.in_drop_impl,
		ustats.perc_in_drop_impl);
	
		printf(GREEN "ACCEPTED" CLR
			" IN PACKETS: %lu [%.1f%%]" NL NL, 
		ustats.tot_in - ustats.in_drop, (float) 100 - ustats.perc_in_drop);	
	}
	
	/* OUTPUT */
	if(ustats.tot_out > 0)
	{
		printf(RED "DROPPED" CLR 
			" OUT PACKETS: %lu [%.1f%%], OF WHICH %lu IMPLICITLY [%.1f%%]."
			NL, ustats.out_drop, ustats.perc_out_drop, ustats.out_drop_impl,
		ustats.perc_out_drop_impl);
	
		printf(GREEN "ACCEPTED" CLR
			" OUT PACKETS: %lu [%.1f%%]" NL NL, 
		ustats.tot_out - ustats.out_drop, (float) 100 - ustats.perc_out_drop);	
	}
	
	/* FORWARD */
	if(ustats.tot_fwd > 0)
	{
		printf(RED "DROPPED" CLR 
			" FORWARDED PACKETS: %lu [%.1f%%], OF WHICH"
				"%lu IMPLICITLY [%.1f%%]."
			NL, ustats.fwd_drop, ustats.perc_fwd_drop, ustats.fwd_drop_impl,
		ustats.perc_fwd_drop_impl);
	
		printf(GREEN "ACCEPTED" CLR
			" FORWARD PACKETS: %lu [%.1f%%]" NL NL, 
		ustats.tot_fwd - ustats.fwd_drop, (float) 100 - ustats.perc_fwd_drop);	
	}
			 
}

void print_time_info(struct aninfo* ai)
{
	char time[40];
	char time2[40];
	double dtime = 0;
	int min = 60;
	int hour = 60 * min;
	int day = 24 * hour;

	strncpy(time, asctime(&ai->tm), 40);
	strncpy(time2, asctime(&ai->tmexit), 40);
	time[strlen(time) -1] = '\0';
	time2[strlen(time2) -1] = '\0';
	
	printf(GRAY "Chunk time: " CLR "%s - %s " NL,
	       time, time2 );
	
	dtime = difftime(mktime(&ai->tmexit), mktime(&ai->tm));

	if(dtime < 0)
		return;
	
	printf(GRAY "Uptime: " CLR);
	if(dtime < min)
		printf("%d seconds.\n", (int) dtime);
	else if( (dtime >= min) & (dtime < hour) )
		printf("%dmin %dsec.\n", (int) dtime/min, (int) dtime % min); 
	else if( (dtime >= hour) & (dtime < day) )
		printf("%dh %dmin %dsec.\n",
		       (int) dtime/hour,  (int) dtime%hour/min, 
		       (int) dtime% hour % min); 
	else if( (dtime >= day) )
		printf("%dg %dh %dmin %dsec.\n", (int) dtime/day,
		       (int) dtime%day/hour,  (int) dtime%day%hour/min, 
		       (int) dtime%day % hour % min); 
}

int anentries_equal(const struct anpacket *a1, const struct anpacket* a2)
{
	if(ops.tcpflags)
	{
		return (a1->nat == a2->nat) & (a1->response == a2->response) &
			(a1->state == a2->state) & (a1->direction == a2->direction) &
			(a1-> protocol == a2->protocol) & (!strcmp(a1->in_device, a2->in_device) ) 
			& (!strcmp(a1->out_device, a2->out_device) ) 
			& (!strcmp(a1->saddr, a2->saddr)) & (!strcmp(a1->daddr, a2->daddr) )
			& (a1->sport == a2->sport) & (a1->dport == a2->dport) &
			(a1->syn == a2->syn) &
			(a1->ack == a2->ack) & (a1->fin == a2->fin) &
			(a1->urg == a1->urg) & (a1->psh == a2->psh) &
			(a1->rst == a2->rst);
	}
	else
		return (a1->nat == a2->nat) & (a1->response == a2->response) &
				(a1->state == a2->state) & (a1->direction == a2->direction) &
				(a1-> protocol == a2->protocol) & 
				(!strcmp(a1->in_device, a2->in_device) ) &
				(!strcmp(a1->out_device, a2->out_device) )
				& (!strcmp(a1->saddr, a2->saddr)) & (!strcmp(a1->daddr, a2->daddr) )
				& (a1->sport == a2->sport) & (a1->dport == a2->dport);
}

int lookup_equals(struct anpacket* anp, 
		  unsigned long int nelems, 
		  unsigned long int current_index)
{
	unsigned long int i = 0;
	while(i < nelems)
	{
		if(apvect[i].counter < 0) /* entry already found */
			goto next;
		if(i == current_index) /* confronto anp con se stessa */
			goto next;
// 		printf("URG1: %d, | RST1: %d, \n", apvect[i].urg, apvect[i].rst);
		if(anentries_equal(anp, &apvect[i]) ) /* equal */
		{
			/* sono uguali: aumento il contatore di anp, pongo
			* a -1 il contatore dell'altra struttura uguale */
			anp->counter ++;
			/* disabilito il confronto in futuro */
			apvect[i].counter = -1;
		} 
			
		next:
			i++;	
	}
	return 0;
}

/* legge il vettore mallocato e globale e fa tutti i calcoli..
 * scrivendo il risultato sul file puntato da fpout */
int analyze(FILE* fpout, unsigned long int nelems)
{
	unsigned long int i = 0;
	
	while(i < nelems)
	{
		if(apvect[i].counter >= 0)
		{
			lookup_equals(&apvect[i], nelems, i);
			/* ho trovato di certo un'occorrenza di me stessa */
			apvect[i].counter ++;
		}
		/* quelle entry con il contatore negativo le escludo */
		i++;
	}
		     
		     
	return 0;
}

int main(int argc, char* argv[])
{
	int i=0;
	int nchunks = 0;
	unsigned lgood = 0;
	unsigned loglnum = 0;
	int scelta = 0;
	int processed = 0;
	
	signal(SIGINT, signal_handler);
	g_save_term();
	
	init_options(&ops);
	get_options(argc, argv, &ops);
	print_options(&ops);
	
	loglnum = get_nlines(ops.infilename);
	
	printf("Cleaning logfile... ");
	if((lgood = clean_log(&ops) ) < 0)
	{
		printf(RED "Error in clean_log()." NL);
		exit(EXIT_FAILURE);
	}
	
	printf("\rok, %u good lines, %u lines removed.                            \n",
	       lgood, loglnum-lgood);
	fflush(stdout);
	
	if( (nchunks = get_nchunks(ops.tmpfilename) ) < 0)
	{
		printf(RED "Error getting information from file." NL);
		exit(EXIT_FAILURE);
	}
	
	while(i < nchunks)
	{
		memset(&ustats, 0, sizeof(ustats) );
		if(( processed = process_chunk(i, ops.tmpfilename, 
		     	ops.outfilename) ) < 0)
		{
			printf(RED "Error processing chunk %d!" NL NL, i+1);
			exit(EXIT_FAILURE);
		}
		else if(processed == 0)
		{
			printf(VIOLET "Operazione annullata per la sezione %d."
					NL NL, i);
			i++;
		}
		else
		{
			i++;
			if(nchunks > i)
			{
				printf(NL "IL BLOCCO DI LOG N. %d E' STATO ANALIZZATO;\n"
					"CI SONO %d BLOCCHI, "
					"VUOI ANALIZZARE IL PROSSIMO?\n"
					"[ESC o Q PER USCIRE] ",
					i, nchunks);
				scelta = g_getchar();
				if( (scelta == ESC) | (scelta == 'q') | (scelta == 'Q') )
				{
					printf("ALLA PROSSIMA!\n");
					goto exit;
				}
			}
		}
	}
	
	exit:
	g_reset_term();
	return 0;

}

inline void get_protocol(const int protocol, char* cproto)
{
	switch(protocol)
	{
		case TCP:
			strcpy(cproto, "tcp");
			break;
		case UDP:
			strcpy(cproto, "udp");
			break;
		case ICMP:
			strcpy(cproto, "icmp");
			break;
		default:
			strcpy(cproto, "unsupported");
			break;
	}
}

int resolve_ports(unsigned long int nents)
{
	struct servent* se;
	unsigned long int i = 0;
	char proto[16];
	unsigned long resolved = 0;
	
	while(i < nents)
	{
		if(apvect[i].counter > 0)
		{
			get_protocol(apvect[i].protocol, proto);
			se = getservbyport(htons(apvect[i].sport), proto);
			if(se != NULL)
			{
				strncpy(apvect[i].sport_res, se->s_name, SERVICENAMELEN -1);
				apvect[i].sport_res[SERVICENAMELEN-1] = '\0';
				resolved ++;
			}
			se = getservbyport(htons(apvect[i].dport), proto);
			if(se != NULL)
			{
				strncpy(apvect[i].dport_res, se->s_name, SERVICENAMELEN -1);
				apvect[i].dport_res[SERVICENAMELEN-1] = '\0';
				resolved ++;
			}
		}
		i++;	
	}
	return resolved;
}

int resolve_addresses(unsigned long int nents)
{
	struct hostent *he;
	struct in_addr srca;
	struct in_addr dsta;
	unsigned long int i = 0;
	int resolved = 0;
	int j = 0;

	while(i < nents)
	{
		j=0;

		if(apvect[i].counter > 0)
		{
			/* SORGENTE */
			if(inet_pton(AF_INET, apvect[i].saddr, (void*) &srca) <= 0)
			{
				printf(RED "resolve_addresses(): bad address %s -> skipped" CLR,
				       apvect[i].saddr);
				perror("");
			}
			else /* l'indirizzo e' valido */
			{
// 				printf("\rResolving " GREEN "%s" CLR "... "
// 						, apvect[i].saddr);
				he = gethostbyaddr((void* ) &srca, sizeof(srca), AF_INET );
				if(he == NULL)
					apvect[i].sunresolved = 1;

				else /* ok gethostbyname */
				{
					printf(GREEN "\r%s... -> " CYAN "%s" CLR
							 "                                   ",
					       apvect[i].saddr, he->h_name);
					strncpy(apvect[i].saddr_resolved, he->h_name, 
						MAXADDRLEN);
					look_for_alias(&apvect[i], he, SRC); 
					resolved ++;
				}
			}
			
			/* DESTINAZIONE */
			if(inet_pton(AF_INET, apvect[i].daddr, (void*) &dsta) <= 0)
			{
				printf(RED "resolve_addresses(): bad address %s -> skipped" CLR,
				       apvect[i].daddr);
				perror("");
			}
			else /* l'indirizzo e' valido */
			{
				he = gethostbyaddr((void* ) &dsta, sizeof(dsta), AF_INET );
				if(he == NULL)
					apvect[i].dunresolved = 1;
				else /* ok gethostbyname */
				{
					strncpy(apvect[i].daddr_resolved, he->h_name, 
						MAXADDRLEN);
					look_for_alias(&apvect[i], he, DEST); 
					resolved ++;
				}
			}
			   
		}
		i++;
	}
	return resolved;   
}

void look_for_alias(struct anpacket* anp, struct hostent* he, 
		    int direction)
{
	int i = 0;
	while(he->h_aliases[i] != NULL)
	{
		if(direction == SRC)
		{
			if(i == 0)
			{
				strncpy(anp->saddr_alias1, he->h_aliases[i],
					MAXADDRLEN -1);
				anp->saddr_alias1[MAXADDRLEN-1] = '\0';
			}
			else if(i == 1)
			{
				strncpy(anp->saddr_alias2, he->h_aliases[i],
					MAXADDRLEN - 1);
				anp->saddr_alias2[MAXADDRLEN-1] = '\0';
			}
			else
				break;
		}
		else
		{
			if(i == 0)
			{
				strncpy(anp->daddr_alias1, he->h_aliases[i],
					MAXADDRLEN -1);
				anp->daddr_alias1[MAXADDRLEN-1] = '\0';
			}
			else if(i == 1)
			{
				strncpy(anp->daddr_alias2, he->h_aliases[i],
					MAXADDRLEN - 1);
				anp->daddr_alias2[MAXADDRLEN-1] = '\0';
			}
			else
				break;
		}
		i++;
	}
}



