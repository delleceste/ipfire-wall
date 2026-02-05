/* main interface of the userspace packet filter. */
 
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


#include "includes/libnetl.h"
#include "includes/ipfire_userspace.h"
#include "includes/ipfire_structs.h"
#include "../g_getcharlib/g_getcharlib.h"
#include "includes/interface.h"
#include "includes/semafori.h"
#include "includes/mailer.h"
#include "includes/languages.h"
#include "includes/proc.h"

void signal_handler(int signum);
void sig1_handler(int signum);
void son_signal_handler(int signum);
void dnsres_handler(int signum);
void mailer_read_handler(int signum);

struct netl_handle *nh_control=NULL;
struct netl_handle *nh_data = NULL;
	
ipfire_rule* denial_rules = NULL;
ipfire_rule* accept_rules = NULL;
ipfire_rule* translation_rules = NULL;
int den_rules_num = 0;
int acc_rules_num = 0;
int transl_rules_num = 0;

/* pipe file descriptor */
int pipefd[2];
int mailpipefd[2];

struct cmdopts prog_ops;
struct userspace_opts uops;

struct netlink_stats nlstats;
	
command opts;

/* file pointer for log file */
FILE* fplog = NULL;

void free_messages(struct nlmsghdr* nlh_control, struct nlmsghdr* nlh_data);
void print_signal(int signum);
int listener(void);
int process_cmd_from_pipe(const char* com);

pid_t listener_pid;
pid_t resolver_pid;
pid_t mailer_pid;
int semid_lockfile = -1;
int num_lang_strings;
char upper_username[PWD_FIELDS_LEN];
time_t tp;
struct tm* t_m;

/* The output print filter: must be null if 
 * not used (not allocated!)
 */
ipfire_rule_filter *filter = NULL;

int main(int argc, char * argv[])
{
  pid_t otherpid;
  int ret, hellocode, son_status;
  command hellocmd;
  int res_status, rules_filenames_changed = 0;
  signal(SIGINT, signal_handler);
  signal(SIGTERM, signal_handler);
  signal(SIGSEGV, signal_handler);
  signal(SIGHUP, signal_handler);
  signal(SIGUSR2, dnsres_handler);
  signal(SIGUSR1, mailer_read_handler);
  /* Clear the terminal at startup, if not root */
//   if(getuid() != 0)
//   	system("clear");
  /* check that the directory .IPFIRE exists. If not,
   * create it and copy the default configuration files
   */
  if(setup_confdir() < 0)
  {
	  printf(RED);
	  printf("Failed to setup or check the needed configuration "
		"directory \".IPFIRE\" in your home.");
	  PNL, PNL;
	  exit(EXIT_FAILURE);
  }
  /* load kernel module, if root */
  if(getuid() == 0)
    {
//       printf(TR("Loading module \"%s\" ...\t"), MODULENAME);
		
      if( (ret = load_module() ) < 0)
	printf("Loading module \"%s\"...\t[" RED, MODULENAME), printf( "%s", TR("FAILED")), printf( CLR "]" NL);
//       else if(ret > 0)
// 	printf("module \"%s\"...\t[" GREEN, MODULENAME), printf(TR("ALREADY LOADED") ), printf(CLR "]" NL);
//       else
// 	printf("["GREEN "OK" CLR "]" NL);
    }
	
  printf(UNDERL "%s" CLR " %s \"%s\"" CLR "."
	 NL, USERFIRENAME, VERSION, CODENAME);

  /* get username and transform it to upper case */
  toupper_username(upper_username);
  /* initialize structures */
	
  memset(&uops, 0, sizeof(uops) );
  init_cmdopts(&prog_ops);
  init_useropts(&uops);
  init_command(&opts);		/* all fields put to 0 */
  init_command(&hellocmd);
  if(get_options(&opts, &uops, &prog_ops) < 0)
    printf( RED "Error getting options from file!" NL);
  /* command line options overwrite file options */
  if( parse_cmdline(&prog_ops, &uops, &opts, argc, argv, &rules_filenames_changed) < 0)
    {
      printf(NL RED UNDERL  "Errors in command line parameters." 
	     NL GREEN "Try \"%s -help\"" NL, argv[0] );
      exit(EXIT_FAILURE);
    }
  /* Load language strings, allocate_translation_strings prints
   * the language detected and the memory usage for translation strings.
   */
  if(! uops.rc)
  	printf("Loading language... ");
  num_lang_strings = allocate_translation_strings(uops.language_filename, uops.rc);
  if(num_lang_strings < 0 && !uops.rc)
	  printf(RED "\tfailed!" NL);
  else if(num_lang_strings < 0 && uops.rc)
	  printf(RED "\tfailed to load language strings!" NL);
  else if(!uops.rc)
  	  printf("\t" CLR "[" GREEN "ok" CLR "]." NL);
  /* save term? */
  if(!uops.justload && !uops.flush && !uops.rc)
    g_save_term();
  /* pipe */
  if(!uops.rc)
    printf(TR("Setting up interprocess communication... ")), fflush(stdout);
  if(pipe(pipefd) < 0)
    printf(RED), printf(TR("failed to open pipe") ), printf(NL);
  else if(!uops.rc)
    printf("\t[" GREEN "OK" CLR ".]" NL);
	
  /* Let's print the filenames of the rulesets only if we are
   * starting the full interface (i.e. not in `rc mode') or
   * if the user has specified a command line argument which
   * contains an alternative file name for one of the three
   * rulesets or the blacksites list. 
   * rules_filenames_changed is put != 0 by
   * parse_cmdline() if it detects a filename directive.
  */
  if( (!uops.rc) && rules_filenames_changed != 0 )
    {
      printf(NL);
      printf(UNDERL); printf(TR("CONFIGURATION FILES:")); printf(NL);
      printf(TR("Permission rules:") ); PTAB; 
      printf("\"%s\".", uops.permission_filename); printf(NL);
      printf(TR("Denial rules:")); PTAB, PTAB; 
      printf("\"%s\".", uops.blacklist_filename);
      printf(NL);
      printf(TR("Translation rules:")); PTAB, PTAB;
      printf("\"%s\".", uops.translation_filename);
      printf(NL);
      if(uops.dns_resolver)
	printf(TR("Blocked sites rules:")), PTAB,
	  printf("\"%s\".", uops.blacksites_filename),
		printf(NL NL);
      else
	printf(NL);
      /* 0 means not verbosely */
      print_cmd_options(&prog_ops, &uops, 0);
    }
  /* open log if necessary */
  if(uops.loglevel > NOLOG)
    if(openlog(&uops) < 0)
      exit(EXIT_FAILURE);
	
  /* should we run as a daemon? */
  if(prog_ops.daemonize)
    daemon(1, 1); /* don't chdir, nor redirect stxxx to null */
  else if(prog_ops.quiet_daemonize)
    daemon(1, 0); /* redirect stdxxx to /dev/null */
	 
  if( (build_option_command(&opts) < 0) || 
      (build_hello_command(&hellocmd, argv[0]) < 0) )
    {
      printf(RED "Error building the initial commands!" NL);
      exit(EXIT_FAILURE);
    }

  if( (semid_lockfile = create_semaphore(SEMVERDE) ) < 0)
    printf(RED), printf(TR( "Error creating semaphore.") ), printf(NL);
  /* allocate rules reading from allow and blacklist files */
  denial_rules = allocate_ruleset(DENIAL, &den_rules_num);
  accept_rules = allocate_ruleset(ACCEPT, &acc_rules_num);
//   printf(TR("There are %d denial, %d permission"), den_rules_num, acc_rules_num);
  /* read rules for network address translation, if user is root */
  if(getuid() == 0)
    {
      translation_rules = allocate_ruleset(TRANSLATION, &transl_rules_num);
//       printf(TR(" and %d translation rules."), transl_rules_num), printf(NL);
    }
//   else
//     printf(TR(" rules." ) ), printf(NL);
  /* send to kernel options and rules */
  /* create netlink control socket */
  nh_control = alloc_netl_handle(NETLINK_IPFI_CONTROL);
  /* send hello message to kernel */
  if(!nh_control || (hellocode = hello_handshake(&hellocmd) ) < 0)
    {
      PNL, PRED, printf(TR("Error sending hello to firewall.") ), PNL, PNL,
		printf("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -\n");
		printf(TR("Be sure that root has loaded IPFIRE module into the kernel!")), PNL,
		printf(TR("Type \"/sbin/lsmod\" on the console and look for \"ipfi_...\"")), PNL,
		printf(TR("modules in the list. If you don't see them, IPFIRE is not loaded")), PNL,
		printf(TR("into the kernel and so this error happened.")),
		printf("\n- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -\n");
		PNL;
      exit(EXIT_FAILURE);
    }
	else if( hellocode != HELLO_OK)
	{
		if(hellocode == IPFIRE_BUSY)
			PNL, PRED, printf(TR("ipfire is busy!")), PNL,
		printf("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -\n"),	  
		printf(TR("Another instance of an userspace interface seems to be running, ")),
		printf(TR("with pid %d!"),	 hellocmd.anumber), PNL,
		printf(TR("That instance should be terminated, e.g. with the command \"kill %d\"."),
			   hellocmd.anumber), PNL, 
		printf("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -\n");
		else
			print_hello_error(&hellocmd);
		/* send a simple goodbye to the kernel, so it can reset variables
		  * related to userspace firewall communication */
		if(send_simple_goodbye() < 0)
			PRED, printf(TR("Error sending a simple goodbye to firewall.") ), PNL;
		else
			PRED, printf(TR("Simple exit notified.")), PNL, PNL;
		printf("hello code: %d\n", hellocode);
		exit(EXIT_FAILURE);
	}
  /* send options to kernel */
  if(send_command_to_kernel(&opts) < 0)
    {
	  PNL, PRED, PUND;
      printf(TR("ERROR SENDING CONFIGURATION OPTIONS TO KERNEL!")), PNL,
	     PCL, PRED, printf(TR("BE SURE TO HAVE LOADED IPFI KERNEL MODULE!")), PNL;
      if(getuid() != 0)
		printf(TR("(YOU HAVE TO BE ROOT TO DO THAT :)" )), PNL;
      printf(NL);
      exit(EXIT_FAILURE);
    }
    if(!uops.rc && 0) /* disable this one at startup */
    	PGRN, printf(TR("- - Options accepted by kernel: - -")), PNL;
  if(read_command_from_kernel(&opts) < 0)
    {
      PRED, printf(TR("main() error receiving message from kernel firewall")), PNL;
      exit(EXIT_FAILURE);
    }
  else
    {
      if((otherpid = firewall_busy(&opts) ) < 0 )
		{
			PNL, PRED, printf(TR("ipfire is busy!")), PNL,
			printf("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -\n"),	  
			printf(TR("Another instance of an userspace interface seems to be running, ")),
	  		printf(TR("with pid %d!"),	-otherpid), PNL,
	  		printf(TR("That instance should be terminated, e.g. with the command \"kill %d\"."),
	  			-otherpid), PNL, 
	  	printf("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -\n");
	  	exit(EXIT_FAILURE);
		}
		if(!uops.rc && 0) /* Disable this print */
		print_command(&opts);
    }
  if(uops.flush)
    {
//       PVIO, printf(TR("- Flushing rules as requested...")), PNL;
      kill(getpid(), SIGINT);
    }
  /* send the rules in kernel space */
  //if(!uops.rc)
  //  printf(TR("Sending rules to kernel...") ), PNL;
  if(send_rules_to_kernel(denial_rules, den_rules_num) < 0)
    {
      PRED, printf(TR("Error sending denial rules to kernel space!")), PNL;
      exit(EXIT_FAILURE);
    }
  if(send_rules_to_kernel(accept_rules, acc_rules_num) < 0)
    {  /* eventually free pointer denial_rules... */
      PRED, printf(TR("Error sending permission rules to kernel space!") ), PNL;
      exit(EXIT_FAILURE);
    }
  if( (getuid() == 0) && (translation_rules != NULL) )
    {
      if(!uops.rc && 0)
		printf(TR("Sending ")), PUND, printf(TR("translation")), 
	  		PCL, printf(TR(" rules...")), PNL;
      if(send_rules_to_kernel(translation_rules, transl_rules_num) < 0)
		PRED, printf(TR("Error sending translation rules to kernel" )), PNL;
    }
  else if( (getuid() != 0) && (translation_rules != NULL) )
    PVIO, printf(TR("Warning: you are not root and cannot send translation rules to kernel!" )), PNL;
	
  /* proc entries for rmem_max and rmem_default and /proc/IPFIRE/policy */
  if(getuid() == 0)
  {
	  check_proc_entries(uops.policy, uops.proc_rmem_max, uops.proc_rmem_default);  
  }
  
  if( (uops.dns_resolver) && (!uops.flush) )
    {
      resolver_pid = start_resolver(uops.dns_refresh, uops.justload, semid_lockfile);
    }
	
    if(uops.justload) /* if '-rc' is given, both 'justload' and 'rc' are set. */
    {
      //printf("- Option \"justload\" [or \"rc\"] is set: exiting leaving rules in firewall."
      //si		NL);
      if(uops.dns_resolver == 1) 
	{
	  PVIO, printf(TR("Waiting for resolver to complete its task..." )), PNL;
	  if(waitpid(resolver_pid, &res_status, 0) < 0)
	    perror(RED "waitpid()" CLR);
	  if(WIFEXITED(res_status) )
	    {
	      printf(TR("Resolver correctly exited.")), PNL;
	      /* update rules now that file has been updated */
	      if(update_kernel_rules(DENIAL, RELOAD_FILE) < 0)
			PRED, printf(TR("Error updating blacklist rules!")), PNL;
	      else
			PGRN, printf(TR("Blacklist rules updated!" )), PNL;
	    }
	  else
	    PRED, printf(TR("Resolver exited abnormally!")), PNL, PNL;
			
	}
	if(uops.mail)
		PNL, PVIO, printf(TR("* Option \"-mailer\" ignored when \"-load\" is specified!" )), PNL, PNL;
      kill(getpid(), SIGINT);
    }
   if(uops.mail)
	{
		if(pipe(mailpipefd) < 0)
				PRED, perror(TR("Error opening pipe for mailer") ), PCL;
		if( (mailer_pid = fork() ) < 0)
		{
			PRED, perror(TR("main(): fork() for mailer failed" )), PCL;
			printf(TR("Exiting after fork() failure!")), PNL, PNL;
			exit(EXIT_FAILURE);
		}
		else if(mailer_pid == 0)
		{
			mailer(&uops);
		}
	}
  /* create a child process listening messages from kernel space, such as
   * accepted/dropped packets and any other messages for user
   */
  if( (listener_pid = fork() ) < 0)
    {
      PRED, perror(TR("main(): fork() failed" )), PCL;
      printf(TR("Exiting after fork() failure!")), PNL, PNL;
      exit(EXIT_FAILURE);
    }
  else if(listener_pid == 0)
    listener();
  else
    {
	    if(prog_ops.quiet_daemonize)
		waitpid(-1, &son_status, 0);
	    else
      	    	interaction(nh_control);
    }
  if(uops.mail)
  {
	  printf(TR("Stopping mailer... ") );
	  if(kill(mailer_pid, SIGINT) < 0)
    	PRED, perror(TR("main(): error shutting down mailer!" )), PNL;
  	  else
    	printf(GREEN "OK"  NL);
  }
  printf(TR("Stopping listener...  "));
  if(kill(listener_pid, SIGINT) < 0)
    PRED, perror(TR("main(): error shutting down listener!")), PNL;
  else
    printf(GREEN "OK"  NL);
  if(uops.dns_resolver)
  {
  	printf(TR("Stopping resolver...  ") );
  	if(kill(resolver_pid, SIGINT) < 0)
    	PRED, perror( TR("main(): error shutting down resolver!") ), PNL;
  	else
    	printf(GREEN "OK" CLR "." ), PNL, printf(TR("BYE!")), PNL;
  }	
  kill(getpid(), SIGINT);	
  return EXIT_SUCCESS;	
}

int quiet = 0;
struct ipfire_servent* svent = NULL;
	
int listener(void)
{
  /* listen on netlink socket */
  int bytes_read;
  int packs_lost;
  ipfire_info_t mes_from_kern;
  listener_message lmess;
  signal(SIGUSR1, sig1_handler);
  signal(SIGSEGV, signal_handler);
  signal(SIGINT, son_signal_handler);
  signal(SIGHUP, son_signal_handler);
  signal(SIGTERM, son_signal_handler);
  init_netlink_stats(&nlstats);
  listener_pid = getpid();
  quiet = prog_ops.quiet;
  time(&tp);
  t_m = localtime(&tp);
  if(uops.resolv_services)
    {
      /* allocate memory and copy services 
       * names according to /etc/services */
      svent = alloc_and_fill_services_list();
      if(svent == NULL)
	{
	  PRED, printf(TR("Failed to allocate space for port services. Disabling.")), PNL, PNL;
	  uops.resolv_services = 0;
	}
    }
  /* insert a line on log file to notify IPFIRE started */
  log_initialization(t_m, upper_username);
  /* create netlink data socket */
  nh_data = alloc_netl_handle(NETLINK_IPFI_DATA);
  /* tell kernel i'm up */
  lmess.message = STARTING;
  if(!nh_data || (send_to_kernel( (void*) &lmess, nh_data, LISTENER_DATA) < 0))
  {
    libnetl_perror(TR("listener(): error sending init message" ));
    exit(EXIT_FAILURE);
  }
  while(1)
    {
      if( (bytes_read = read_from_kern(nh_data, (unsigned char*) &mes_from_kern, 
				       sizeof(ipfire_info_t) ) ) < 0)
	{
	  PRED, libnetl_perror(TR( "listener(): error getting message from kernel!")), PNL;
	  /* Go on reading, do not exit. */
	}
      else if(bytes_read == 0)
		PRED, printf(TR("read 0 bytes!")), PNL;
      else
	{
	  /* update userspace-side counters */
	  switch(mes_from_kern.flags.direction)
	  {
	    case IPFI_INPUT: nlstats.in_rcv++; nlstats.last_in_rcv++; break;
	    case IPFI_OUTPUT: nlstats.out_rcv++; nlstats.last_out_rcv++; break;
	    case IPFI_FWD: nlstats.fwd_rcv++; nlstats.last_fwd_rcv++; break;
	    case IPFI_INPUT_PRE: nlstats.pre_rcv++; nlstats.last_pre_rcv++; break;
	    case IPFI_OUTPUT_POST: nlstats.post_rcv++; nlstats.last_post_rcv++; break;
	  }
	  if(quiet == 0)
	    print_packet(&mes_from_kern, svent, filter);
	  if(uops.loglevel > 0)
	    log_packet(&mes_from_kern, uops.loglevel);
	}
    }
  return 0;
}

int quiet_save; 
short switched;

void sig1_handler(int signum)
{
  char buf[MAXPIPESIZEMESS];
  if(signum == SIGUSR1)
    {
      /* read pipe */
      if(read(pipefd[0], buf, MAXPIPESIZEMESS) < 0)
		PRED, perror(TR("sig1_handler(): error reading from pipe" )), PCL;
      else
	{
	  if(process_cmd_from_pipe(buf) < 0)
	    PRED, printf(TR("sig1_handler(): error processing command \"%s\""), buf), PNL;
	}
    }
}

int filter_is_active()
{
	if(filter == NULL)
		return 0;
	return 1;
}

int process_cmd_from_pipe(const char* com)
{
  if(!strcmp(com, "quiet") )
    quiet = 1;
  else if(!strcmp(com, "verb") )
    quiet = 0;
  else if(!strcmp(com, "servcs") )
    {
      if( (uops.resolv_services == 0) && (svent == NULL) )
	{
	  printf(TR("Reading service names and creating dynamic tables...")), PTAB;
	  svent = alloc_and_fill_services_list();
	  if(svent == NULL)
	    {
	      PRED, printf(TR("Failed to allocate space for port services. Disabling.")),
			PNL;
	      uops.resolv_services = 0;
	    }
	  printf("[" GREEN "OK" CLR ".]" NL);
	  uops.resolv_services = 1;
	}
      else
		PNL, printf(TR("Service name resolution seems to be already active!")), PNL, PNL;
    }
  else if(!strcmp(com, "noservcs") )
    {
      if( (uops.resolv_services) && (svent != NULL) )
	{
	  printf(TR("Freeing memory for service tables...")), PTAB;
	  free(svent);
	  svent = NULL;
	  uops.resolv_services = 0;
	  printf("[" GREEN "OK" CLR ".]" NL);
	}
      else
		PNL, printf(TR("Service name resolution seems to be already disabled!") ), PNL, PNL;
    }
  else if(! strcmp(com, "netlink_stats") )
    {
      quiet = 1;
      print_stats(&nlstats);
    }
  else if(! strncmp(com, "filter:", 7) )
  {
	  quiet = 1;
	  /* If a filter has been already allocated, free it and 
	   * substitute with a new one.
	   */
	  if(filter != NULL)
	  {
		  PVIO, printf(TR("Warning: deleting the old filter and creating a new one...\t") ), PCL;
		  free_filter_rule(filter);
	  }
	  
	  filter = setup_filter(com + 7);
	  PGRN, printf(TR("done") ), PCL, printf("."), PNL;
	  
	  quiet = 0;
	  
  }
  else if(! strcmp(com, "remove_filter") )
  {
	  printf(TR("Removing the filter..."));
	  quiet = 1;
	  
	  if(filter != NULL)
	  {
	  	free_filter_rule(filter);
		filter = NULL; /* Important! Disables fitering */
		PGRN, printf(TR("done") ), PNL;
	  }
	  else
		  printf(TR("No filter was loaded!")), PNL, PNL;
  }
  else if(! strcmp(com, "print_filter") )
  {
  	quiet = 1;
	print_filter(filter);
  }
  else
    return -1;
  return 0;
}

void son_signal_handler(int signum)
{
  if(signum != SIGSEGV)
    {
      PYEL, printf(TR("Listener exiting.")), PNL;
      if(uops.loglevel > NOLOG)
	{
	  time(&tp);
	  t_m = localtime(&tp);
	  log_exiting(t_m, upper_username, &nlstats);
	  PNL, printf(TR("Closing logfile..."));
	  if(closelog() < 0)
	    PRED, PTAB, printf(TR("FAILED")), PNL;
	  else 
	    printf("\t["), PGRN, printf(TR("done")), PCL, printf(".]" NL);
	  if( (uops.resolv_services) && (svent!= NULL) )
	    {
	      printf(TR("Freeing memory for service names tables..."));
	      free(svent);
	      printf("\t[" GREEN "OK" CLR ".]" NL);
	    }
	}
      exit(EXIT_SUCCESS);
    }
  else if(signum == SIGSEGV)
    {
      printf(TR("Listener exiting for a fatal error!") ), PNL;
      exit(EXIT_FAILURE);
    }
}

void dnsres_handler(int signum)
{
  int rules_updated = -1;
  if(signum == SIGUSR2)
    {
      PYEL, printf(TR("Updating kernel denial rules after updating blocked sites list.")),
		PNL;
      if( (rules_updated = update_kernel_rules(DENIAL, RELOAD_FILE) ) < 0)
		PRED, printf(TR("Error updating blacklist rules!" )), PNL;
      else
		PGRN, printf(TR("Blacklist rules updated [%d rules]!" ), rules_updated), PNL;
    }
}

void mailer_read_handler(int signum)
{
	struct kernel_stats firestats;
		
	if(signum == SIGUSR1)
	{
		memset(&firestats, 0, sizeof(firestats) );
		if(request_kstats() < 0)
	 		 PRED, printf(TR("Failed to send statistics request to kernel firewall!")), PNL;
		if(receive_kstats(&firestats) < 0)
	 		 PRED, printf(TR("Failed to read statistics from kernel firewall!")), PNL, PNL;
		printf(TR("WRITING TO PIPE")), PNL;
		if(write(mailpipefd[1], (void*) &firestats, sizeof(firestats) ) < 0)
   			PRED, perror(TR("mailer_read_handler(): failed to write to pipe for mailer!" )), PCL;
	}
}

void signal_handler(int signum)
{
  int rules_freed = 0;
  command exit_response;
	
  if(!uops.justload && !uops.flush)
    g_reset_term();
  /* only parent process executes cleaning operations */
  if(getpid() != listener_pid)
    {
      if(!uops.rc)
	{
	  printf(TR("Signal handler... "));
	  print_signal(signum);
	}
      if(!uops.rc)
		printf(TR("Removing rules inserted... "));
      if( (rules_freed = send_goodbye(nh_control) ) < 0)
	{
	  PRED, printf(TR( "Error sending goodbye message!" )), PNL;
	  goto free_mem;
	}
      else if(!uops.rc)
		printf(GREEN "OK" CLR);
      if(read_from_kern(nh_control, (unsigned char*) &exit_response, 
			sizeof(command) )  < 0)
		libnetl_perror(TR("main(): error reading options"));
      else
	print_kernel_userspace_exit_status(&exit_response, uops.rc);
    free_mem:
      if(!uops.rc)
		printf(TR("Freeing memory if necessary... "));
      if(nh_control != NULL)
		netl_free_handle(nh_control);
      if(nh_data != NULL)
		netl_free_handle(nh_data);
      if(!uops.rc)
	      printf(TR("Closing pipe..."));
      if( (close(pipefd[0]) < 0) | (close(pipefd[1]) < 0) )
		PRED, printf(TR(" FAILED")), PNL;
      else if(!uops.rc)
		printf("\t["),  PGRN, printf(TR("done")), printf(CLR ".]" NL);
      if(uops.dns_resolver)
		{
	  		printf(TR("Removing semaphore...")), PTAB,PTAB,PTAB,PTAB;
	  		if(rimuovi_semaforo(semid_lockfile) < 0)
	    		printf("[" RED),  printf(TR("FAILED")), printf( CLR ".]\n");
	  		else
	    		printf("[" GREEN "OK" CLR ".]\n");
		}
   if( (getuid() == 0) & (! prog_ops.noflush_on_exit) )
	{
	  if(uops.rmmod)
	    {
	      printf(TR("Unloading %s kernel module..."), MODULENAME), PTAB;
	      if(unload_module() < 0)
			printf("[" RED), printf(TR("FAILED")), printf(CLR "]" NL);
	      else
			printf("[" GREEN "OK" CLR "]" NL);
	    }
	  else
	  {
	    PNL, printf(TR("Kernel module will not be unloaded: the default")); PNL;
		printf(TR("policy specified at module loading time will be applied.")); 
		PNL; PNL;
		printf("\e[37;41;1m" UNDERL); printf(TR("WARNING") );
		printf(CLR RED); 
		printf(TR(": the firewall has been stopped but the kernel module wasn't unloaded.") );
		PNL;
		printf(TR("         If the firewall policy was to drop packets which do not match any") ); PNL;
		printf(TR("         rule, then many applications could stop working until you remove") ); PNL;
		printf(TR("         IPFIRE module from the kernel or restart IPFIRE itself.") );
		printf("\e[00m\n\n");
	  }
	}
      //if(!uops.rc)
		// printf("Freeing language strings... ");
      num_lang_strings = free_lang_strings();	
      // if (!uops.rc)
      	// printf("[%d entries freed]\n", num_lang_strings);	
      if(!uops.rc)
	printf(NL);
    } 
  exit(EXIT_SUCCESS);
}

void free_messages(struct nlmsghdr* nlh_control, struct nlmsghdr* nlh_data)
{
  if(nlh_control != NULL)
    netl_free_nlmess(nlh_control);
  else
    printf(TR("control: not necessary... "));
  if(nlh_data != NULL)
    netl_free_nlmess(nlh_data);
  else
    printf(TR("  data: not necessary.") );
  printf("\n");
}

void print_signal(int signum)
{
  switch(signum)
    {
    case SIGINT:
      printf(GREEN UNDERL "SIGINT" NL);
      break;
    case SIGHUP:
      printf(GREEN UNDERL "SIGHUP" NL);
      break;
    case SIGTERM:
      printf(GREEN UNDERL "SIGTERM" NL);
      break;
    case SIGSEGV:
      printf(NL RED UNDERL "SIGSEGV" CLR "!" NL);
	  printf(TR("FATAL ERROR! Report to ")); printf(UNDERL "delleceste@gmail.com" NL);
      printf(TR("Trying to communicate last goodbye to kernel firewall..." )), PNL;
      break;
    }
}

int get_quiet_state(void)
{
  return prog_ops.quiet;
}
