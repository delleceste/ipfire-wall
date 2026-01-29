#include "includes/ipfire_userspace.h"
#include "includes/mailer.h"
#include "includes/interface.h"
#include "includes/languages.h"
 
#define FPNL (fprintf(fp, "\n") ) 
/* IPFIRE mailer. It uses "SMTPclient -- simple SMTP client"
 * by SMTPclient -- simple SMTP client, written by
 * Ralf S. Engelschall and Davide Libenzi.
 * The program is required to be built and installed to
 * allow ipfire to send emails.
 */
    
/*
 *  SMTPclient: 
 *  Copyright (c) 1997 Ralf S. Engelschall, All rights reserved.
 *  Copyright (c) 2000, 2001 Davide Libenzi <davidel@xmailserver.org>, All rights reserved.
 */
    
/* IPFIRE mailer:
 * Copyright (C) 2005 Giacomo Strangolino 
 * delleceste@gmail.com
 * jacum@libero.it
 * giacomo.strangolino@elettra.trieste.it
 */
    
extern int mailpipefd[2];
unsigned int mails_sent = 0;
unsigned int mails_failed = 0;

char time_userspace_started[128];
    
void init_mailopts(struct mailer_options* m)
{
  char home[PWD_FIELDS_LEN] = ""; /* 64 chars */
  get_user_info(HOMEDIR, home);
  strcpy(m->messbody_file, "");
  strcpy(m->mailer_path, "");
  
  strcpy(m->subject, TR("MAIL FROM IPFIRE"));
  strcpy(m->mail_intro, TR("Mail sent from IPFIRE-wall"));
  strcpy(m->to, "");
  strcpy(m->from, "");
  strcpy(m->cc, "");
  /* Body file: give a valid default */
  strcat(m->messbody_file, home);
  strcat(m->messbody_file, "/.IPFIRE/mailer/body");
  strcpy(m->attach_file, "");
  strcpy(m->smtp_host, "");
  /* Mailer path */
  strcat(m->mailer_path, home);
  strcat(m->mailer_path, "/.IPFIRE/mailer/SMTPclient");
  strcpy(m->zip_path, "/usr/bin/bzip2");
  m->smtp_port = 25;
  m->attach = 0;
  m->maxmails = 0;
}
    
int check_mail_options(struct mailer_options* mo)
{
  if(
     strlen(mo->to) == 0 ||
     strlen(mo->from) == 0 || strlen(mo->smtp_host) == 0 ||
     strlen(mo->mailer_path) == 0)
    {
      PRED;
      printf(TR("Fields 'to', 'from', 'smtp host' and 'mailer path' must be specified!"));
      PNL;
      return -1;
    }
  else
    return 0;
}
    
int print_mail_options(const struct mailer_options *mo,
		      struct userspace_opts* uop)
{
  printf(TR("MAILER OPTIONS:")), PNL;
  printf("FROM: \"%s\"" NL
	 "TO:  \"%s\"" NL
	 "CC:  \"%s\"" NL, mo->from, mo->to, mo->cc);
  printf(TR("SUBJECT:  \"%s\""),  mo->subject), PNL;
  printf(TR("MAIL INTRODUCTION: \"%s\""), mo->mail_intro), PNL;
  printf(TR("MESSAGE BODY FILE:  \"%s\""), mo->messbody_file); PNL;
  printf(TR("SMTP HOST:  \"%s\""), mo->smtp_host); PNL;
  printf(TR("SMTP PORT: %u"), mo->smtp_port); PNL;
  printf("MAILER:  \"%s\"" NL
	     "BZIP2:  \"%s\"" NL NL,
		    mo->mailer_path, mo->zip_path);
  printf(TR("A MAIL IS SENT EVERY "));
	 print_seconds_to_dhms(uop->mail_time);
	 printf("\n\n");
  if(mo->attach == 1)
    {
      printf(TR("ATTACHMENT ENABLED: "));
      if(strlen(mo->attach_file) > 0)
		printf(TR("ATTACHMENT FILE: \"%s\""), mo->attach_file), PNL;
      else
		printf(TR("ATTACHMENT FILE: COMPRESSED LOGFILE")), PNL;
    }
  else
    printf(TR("ATTACHMENT DISABLED.")), PNL;
  
  if(mo->maxmails > 0)
      printf(TR("MAXIMUM NUMBER OF MAILS TO SEND: %u."),
	     mo->maxmails), PNL;
                            
  return 0;
}
    
    
int get_mail_options(const char* mail_opt_filename, 
		     struct mailer_options* mops)
{
  FILE* fp;
  /* Initialize */
  mops->attach = 0;
  mops->smtp_port = 25;
  char line[MAXMAILLINELEN];
  if( (fp = fopen(mail_opt_filename, "r") ) == NULL)
    {
      PRED, printf(TR("Error opening mail filename \"%s\"!"),
	     mail_opt_filename), PCL;
      perror("");
      return -1;
    }
  while(fgets(line, MAXMAILLINELEN, fp) != NULL)
    {
      if(strncmp(line, "FROM=", 5) == 0)
	get_string_n(mops->from, line, MAXMAILLINELEN);
      else if(strncmp(line, "TO=", 3) == 0)
	get_string_n(mops->to, line, MAXMAILLINELEN);
      else if(strncmp(line, "CC=", 3) == 0)
	get_string_n(mops->cc, line, MAXMAILLINELEN);
      else if(strncmp(line, "SUBJECT=", 8) == 0)
	get_string_n(mops->subject, line, MAXMAILLINELEN);
      else if(strncmp(line, "MAIL_INTRO=", 11) == 0)
	get_string_n(mops->mail_intro, line, MAXMAILLINELEN);
      else if(strncmp(line, "MESS_BODY_FILE=", 15) == 0)
	get_string_n(mops->messbody_file, line, MAXMAILLINELEN);
      else if(strncmp(line, "ATTACH_ENABLED=YES", 18) == 0)
	mops->attach = 1;
      else if(strncmp(line, "ATTACH_FILENAME=", 16) == 0)
	get_string_n(mops->attach_file, line, MAXMAILLINELEN);
      else if(strncmp(line, "SMTP_HOST=", 10) == 0)
	get_string_n(mops->smtp_host, line, MAXMAILLINELEN);
      else if(strncmp(line, "MAILER_PATH=", 12) == 0)
	get_string_n(mops->mailer_path, line, MAXMAILLINELEN);
      else if(strncmp(line, "BZIP2_PATH=", 11) == 0)
	get_string_n(mops->zip_path, line, MAXMAILLINELEN);
      else if(strncmp(line, "SMTP_PORT=", 10) == 0)
	mops->smtp_port = (unsigned int) get_integer(line);
      else if(strncmp(line, "MAXMAILS=", 9) == 0)
	  mops->maxmails = (unsigned int) get_integer(line);	
      	
    }
  fclose(fp);
  return check_mail_options(mops);
}
    
int mailer(struct userspace_opts* uops)
{
  struct mailer_options mopts;
  struct kernel_stats krnstats;
  time_t tp;
                    
  char compressed_filename[MAXMAILLINELEN];
  time(&tp);
  strncpy(time_userspace_started, (const char*) ctime(&tp), 128);
  printf(TR("Starting mailer...[" ));
  print_seconds_to_dhms(uops->mail_time);
  printf("]. ");
  printf(TR("Type '")); printf(YELLOW "m" CLR "'"); 
  printf(TR("to see mailer options.")); 
  PNL;
            
  signal(SIGINT, mailer_handler);
            
  while(1)
    {
      sleep(uops->mail_time);
      /* Initialize mailer oprions: each time settings will be reloaded 
       * from the configuration file. 
       */
      init_mailopts(&mopts);
      if(get_mail_options(uops->mailer_options_filename, &mopts) < 0)
        {
	  		PNL, PRED, printf(TR("Error getting options from filename \"%s\"."),
				uops->mailer_options_filename); PNL;
		    printf(TR("Returning to sleep... Meanwhile try to repair such file :)")),
		    PNL;
	  		mails_failed ++;
        }
      else
        {
	  		kill(getppid(), SIGUSR1);
	  		/* Read from pipe */
	  		if(read(mailpipefd[0], &krnstats, sizeof(krnstats) ) < 0)
	    		perror(RED "sig1_handler(): error reading from pipe" CLR);
	 	 	else
            {
	      		printf(NL NL);
                                    
	      if(mopts.attach == 1)
                {
		  if(strlen(mopts.attach_file) == 0)
                    {
		      /* No attach filename specified: compress and attach logfile */
		      printf(YELLOW "Compressing logfile \"%s\"...", uops->logfile_name);
		      strncpy(mopts.attach_file, uops->logfile_name, MAXMAILLINELEN);
		      if(compress_logfile(uops->logfile_name, &mopts) < 0)
                        {
			  printf(RED "FAILED" CLR "." NL);
			  printf("Be sure to have write permission on output file!\n");
			  printf(VIOLET "Mail will be sent anyway, but without attachment!"
				 NL);
			  mopts.attach = 0;
                        }
		      else
                        {
			  				printf(GREEN "\t\tdone" CLR "." NL);
			  				/* Add suffix ".bz2" to filename. */
			  				snprintf(compressed_filename, MAXMAILLINELEN, "%s.bz2", 
				   				mopts.attach_file);
			  				/* Copy compressed filename into attachment filename */
			  				strncpy(mopts.attach_file, compressed_filename, MAXMAILLINELEN);	
                        }	
                    }
		  else
		    printf(VIOLET "An attachment file has been specified: "
			   "\"%s\":\nlogfile will not be sent and attachment\n"
			   "will not be compressed.\n" CLR, mopts.attach_file);
                }
	      printf(YELLOW "Writing email...\t\t\t\t");
	      if(write_email(&mopts, &krnstats, uops->mail_time ) < 0)
                {
		  printf(RED "Error writing email!" NL);
		  printf("Going back to sleep...\n");
		  mails_failed ++;
		  continue;
                }
	      else
		printf(GREEN "done" YELLOW "." NL);
                                    
	      printf(YELLOW "Sending email to \"%s\"..." NL, mopts.to);
	      if(send_email(&mopts) < 0)
                {
		  printf(RED "Error sending email!" NL);
		  printf("Returning to sleep...\n");
		  mails_failed ++;
		  continue;
                }
	      else
	      {
		printf(GREEN "done" CLR "." NL);
		mails_sent ++;
		if(mails_sent == mopts.maxmails)
		{
		    printf(YELLOW "Maximum mail number has been reached: %u:\n"
			    "Mailer will be stopped now..." NL, mails_sent);
		    if(kill(getpid(), SIGINT) < 0)
			perror(RED "Error stopping mailer!" CLR);
		    else
			printf(GREEN "Mailer stopped" NL NL);
		}
	      }
            }	
        }
    } /* while */
  return 0;
}
    
void mailer_handler(int signum)
{
	printf(MAROON); printf(TR("Stopping mailer.")), PNL;
	printf(MAROON); printf(TR( "Closing mailer pipe..."));
  if( (close(mailpipefd[0]) < 0) || (close(mailpipefd[1]) < 0) )
	  PRED, printf(TR(" FAILED")),  PNL;
  else 
      printf(GREEN "\tok" CLR ".\n");
  exit(EXIT_SUCCESS);
}
    
/* Compress attachment */
int compress_logfile(const char* filename, struct mailer_options* mo)
{
  char* argv[5];
  int status;
  char *keep = "-k";  /* keep existing file */
  char *force = "-f"; /* force overwrite of output files */
    
  switch (fork()) {
  case 0:
    argv[0] = (char *)mo->zip_path;
    argv[1] = (char *)filename;
    argv[2] = (char*)keep;
    argv[3] = (char*)force;
    argv[4] = NULL;
    execv(argv[0], argv);
    perror("execv() failed");
    printf("errno: %d\n", errno);
    /* not usually reached */
    exit(1);
  case -1:
    perror("Fork failed");
    return -1;
    
  default: /* parent */
    /* wait suspends execution of process until one of its children
     * terminates. */
    wait(&status);
  }
  /* WIFEXITED says if son exited normally (true), WEXITSTATUS
   * returns the exit status of the child, to use if WIFEXITED returned
   * true */
  if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
    return 0;
            
  return -1;
}
    
int write_email(struct mailer_options* mo, struct kernel_stats* k,
	       unsigned long interval)
{
  /* Write the body message on file mo->body */
  FILE* fp;
  time_t tp;
  float perc_in_drop = 0, perc_out_drop = 0, perc_fwd_drop = 0;
  unsigned long long total = k->in_rcv + k->out_rcv + k->fwd_rcv +
    k->pre_rcv + k->post_rcv;
  unsigned int mail_no = mails_sent + mails_failed + 1;
            
  if( (fp = fopen(mo->messbody_file, "w") ) == NULL)
    {
      printf(TR("Error opening message body file for writing: \"%s\""),
	     mo->messbody_file), PCL;
      perror("");
      return -1;
    }
  time(&tp);
  if(strlen(mo->mail_intro) == 0)
    fprintf(fp, "\nIPFIRE-wall email sent on %s", ctime(&tp) );
  else
    fprintf(fp, "\n%s %s\n", mo->mail_intro, ctime(&tp) );
  
  /* Percentages */
  if(k->in_rcv != 0)
  	perc_in_drop = (float) k->in_drop / (float) k->in_rcv * 100;
  if(k->out_rcv != 0)
  	perc_out_drop = (float) k->out_drop / (float) k->out_rcv * 100;
  if(k->fwd_rcv != 0)
 	 perc_fwd_drop = (float) k->fwd_drop / (float) k->fwd_rcv * 100;
  
  fprintf(fp, "\n- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - \n");
            
  fprintf(fp, "%s", TR("Kernel module was loaded at %s"), ctime(&k->kmod_load_time) );
  fprintf(fp, "\n");
  fprintf(fp, "%s", TR("Userspace IPFIRE-wall started on %s"),
	  time_userspace_started);
  FPNL;
  fprintf(fp, "%s", TR("Version: %s %s \"%s\" by %s [mailto:%s]."),
  		USERFIRENAME, VERSION, CODENAME, AUTHOR, AUTHOR_MAIL); 
  FPNL;
  fprintf( fp, TR("Description: %s."), DESCRIPTION); FPNL;
  fprintf( fp, TR("Developed between %s."), FIREDATE); FPNL;
  
  fprintf(fp, "%s", TR("Mailer \"SMTPclient\" by Ralf S. Engelschall and Davide Libenzi."));
  fprintf(fp,  "(C) 1997, 2000, 2001.\n");
  fprintf(fp, "\n\t\t");
  fprintf(fp, "%s", TR("KERNEL STATISTICS."));
  fprintf(fp, "\n\n");
  fprintf(fp, "%s", TR("Input packets filtered:"));
  fprintf(fp,"\t\t\t%llu.\n",k->in_rcv);
  fprintf(fp, "%s",TR("Output packets filtered:"));
  fprintf(fp, "\t\t\t%llu.\n", k->out_rcv);
  fprintf(fp, "%s", TR("Pre routing packets filtered:"));
  fprintf(fp,  "%s","\t\t%llu.\n", k->pre_rcv);
  fprintf(fp, "%s",TR("Post routing packets filtered:"));
  fprintf(fp, "\t\t%llu.\n", k->post_rcv);
  fprintf(fp, "%s", TR("Forward packets filtered:"));
  fprintf(fp, "\t\t\t%llu.\n", k->fwd_rcv);
  fprintf(fp, "- - -\n");
  fprintf(fp, "%s", TR("Total packets filtered:"));
  fprintf(fp, "\t\t\t%llu.\n\n", total);
  fprintf(fp, "%s", TR("Packets lost in kernel/user communication:"));
  fprintf(fp, "\t\t%llu.\n", k->total_lost);
  fprintf(fp, "%s", TR("Packets sent to userspace:"));
  fprintf(fp,"\t\t\t\t\t%llu.\n", k->sent_tou);
  fprintf(fp, "%s", TR("Packets unsent to usersp. (because of loglevel):"));
  fprintf(fp, "\t%llu.\n", k->not_sent);
  
  fprintf(fp, "\n\t\t");  
  fprintf(fp, "%s", TR("Verdicts.") );
  FPNL; FPNL;
  fprintf(fp, "%s", TR("Default policy being applied to packets not matching any rule: "));
  if(k->policy == 0)
      fprintf(fp, "%s", TR("drop.")), FPNL, FPNL;
  else
      fprintf(fp, "%s", TR("accept.")), FPNL, FPNL;
  fprintf(fp, "%s", TR("Input packets accepted:"));
  fprintf(fp, "\t\t\t%llu \t[%.1f%%].\n", k->in_acc, (float)100 - perc_in_drop);
  fprintf(fp, "%s", TR("Input packets dropped:"));
  fprintf(fp, "\t\t\t%llu \t[%.1f%%].\n", k->in_drop, perc_in_drop );
  fprintf(fp, "%s", TR("Input packets implicitly accepted:"));
  fprintf(fp, "\t%llu\n", k->in_acc_impl);
  fprintf(fp, "%s", TR("Input packets implicitly dropped:"));
  fprintf(fp, "\t%llu.\n\n", k->in_drop_impl);
  
  fprintf(fp, "%s", TR("Output packets accepted:"));
  fprintf(fp, "\t\t%llu \t[%.1f%%].\n", k->out_acc, (float) 100 - perc_out_drop);
  fprintf(fp, "%s", TR("Output packets dropped:"));
  fprintf(fp, "\t\t\t%llu \t[%.1f%%].\n", k->out_drop, perc_out_drop);
  fprintf(fp, "%s", TR("Output packets implicitly accepted:"));
  fprintf(fp, "\t%llu\n", k->out_acc_impl); 
  fprintf(fp, "%s", TR("Output packets implicitly dropped:"));
  fprintf(fp, "\t%llu.\n\n", k->out_drop_impl);

  fprintf(fp, "%s", TR("Forward packets accepted:"));
  fprintf(fp, "\t\t%llu \t[%.1f%%].\n", k->fwd_acc, (float) 100 - perc_fwd_drop);
  fprintf(fp, "%s", TR("Forward packets dropped:"));
  fprintf(fp, "\t\t%llu \t[%.1f%%].\n", k->fwd_drop, perc_fwd_drop);
  fprintf(fp, "%s", TR("Forward packets implicitly accepted:"));
  fprintf(fp, "\t%llu\n", k->fwd_acc_impl);
  fprintf(fp, "%s", TR("Forward packets implicitly dropped:"));
  fprintf(fp, "\t%llu.\n\n", k->fwd_drop_impl);
  FPNL;                                          
  fprintf(fp, "%s", TR("Nat checksum checks found %u bad arriving packets."),
	  k->bad_checksum_in);
  FPNL;FPNL;FPNL;FPNL;
  fprintf(fp, "%s", TR("This is mail number %u."), mail_no);
  fprintf(fp, "%s", TR("Since %s%u mails have been successfully sent, and %u failed."),
	        time_userspace_started, mails_sent, mails_failed), FPNL;
  fprintf(fp, "%s", TR("The time interval between a mail and the subsequent is %lu seconds."),
	  interval), FPNL;
  /* +1 because at this point counter is not already incremented */
  if(mo->maxmails > 0 && mails_sent + 1 < mo->maxmails)
      fprintf(fp, "%s", TR("Other %u mails will be sent."), mo->maxmails-mails_sent), FPNL, FPNL;
  else if(mo->maxmails > 0 && mails_sent + 1 == mo->maxmails)
      fprintf(fp, "%s", TR("This is the last mail (%u) sent in this ipfire userspace session."),
 		mails_sent+1), FPNL, FPNL;
  
      
                                    
  fprintf(fp, "\n- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - \n");
            
  fclose(fp);
  return 0;
}
    
/* Send the email */
int send_email(struct mailer_options* mo)
{
  char* argv[20];
  char port[6];
  char subject[MAXMAILLINELEN+2];
  int status, i;
  /* send_mail command line options */
  char 
    *sub = "-s", *from = "-f", *carbon = "-c",
    *smtp_h = "-S", *smtp_p = "-P", *body = "-b",
    *attach = "-a", *verbose = "-v";
    
  switch (fork()) {
  case 0:
    /* Prepare command line arguments */
    snprintf(port, 6, "%u", mo->smtp_port);
    snprintf(subject, MAXMAILLINELEN+2, "\"%s\"", mo->subject);
    argv[0] = (char *)mo->mailer_path;
    argv[1] = (char*)verbose;
    argv[2] = (char *)sub;
    argv[3] = (char *)subject;
    argv[4] = (char *)from;
    argv[5] = (char *)mo->from;
    argv[6] = (char *)smtp_h;
    argv[7] = (char *)mo->smtp_host;
    argv[8] = (char *)smtp_p;
    
    argv[9] = (char *)port;
    argv[10] = (char *)body;
    argv[11] = (char *)mo->messbody_file;
    i = 12;
    if(mo->attach == 1)
      {
	argv[i] = (char *)attach;
	argv[i+1] = (char *)mo->attach_file;
	i = i + 2;
      }
            
    if(strlen(mo->cc) > 3) /* cc at least a@b */
      {
	argv[i] = (char*) carbon;
	argv[i+1] = (char*) mo->cc;
	i = i + 2;
      }
    
    argv[i] = (char*) mo->to;
    i++;
    argv[i] = (char*)NULL;
    
    printf("Executing: ");
    for(i = 0; i < 16 && argv[i] != NULL; i++)
      printf(" %s", argv[i]);
    printf(NL);
    execv(argv[0], argv);
    perror("execv() failed");
    printf("errno: %d\n", errno);
    /* not usually reached */
    exit(1);
  case -1:
    perror("Fork failed");
    return -1;
    
  default: /* parent */
    /* wait suspends execution of process until one of its children
     * terminates. */
    wait(&status);
  }
  /* WIFEXITED says if son exited normally (true), WEXITSTATUS
   * returns the exit status of the child, to use if WIFEXITED returned
   * true */
  if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
    return 0;
            
  return -1;
}
