#include "ipfire_userspace.h"

#ifndef MAILER_H
#define MAILER_H

#define MAXSUBJLEN				256
#define MAXMAILLINELEN		512
#define ALEN							128

struct mailer_options
{
	char subject[MAXMAILLINELEN];
	char mail_intro[MAXMAILLINELEN];
	char line[MAXMAILLINELEN];
	char to[MAXMAILLINELEN];
	char cc[MAXMAILLINELEN];
	char from[MAXMAILLINELEN];
	char messbody_file[MAXMAILLINELEN];
	char attach_file[MAXMAILLINELEN];
	char smtp_host[MAXMAILLINELEN];
	char mailer_path[MAXMAILLINELEN];
	char zip_path[MAXMAILLINELEN];
	unsigned int smtp_port;
	/* Maximum number of mails to send 
	 * successfully, then exit. 
	 */
	unsigned int maxmails; /* 0 means no limit */
	short attach;
};

void mailer_handler(int signum);

void init_mailopts(struct mailer_options* m);

int get_mail_options(const char* mail_opt_filename, 
			struct mailer_options* mops);

int mailer(struct userspace_opts* uops);
	
int print_mail_options(const struct mailer_options *mo,
		      struct userspace_opts* uops);

/* Compress attachment */
int compress_logfile(const char* filename, struct mailer_options* mo);

int write_email(struct mailer_options* mo, struct kernel_stats* k, 
		unsigned long interval);

/* Send the email */
int send_email(struct mailer_options* mo);

#endif
