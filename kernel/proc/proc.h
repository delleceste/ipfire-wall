#ifndef IPFIRE_PROC_H
#define IPFIRE_PROC_H

#include <linux/proc_fs.h>

#define PROCDIR "IPFIRE"
#define PROCENT "policy"
#define PROCENTRY_DATA_LEN 100

/* proc entry */
int init_procentry(const char* name, const char *value);

void set_procentry_values(void);

int proc_write_ipfire(struct file *file, const char *page,
			     unsigned long count, void *data);
			     
int proc_read_ipfire(char *page, char **start, off_t off,
		     int count, int *eof, void *data);
		     
void clean_proc(void);

void set_policy(const char* def_policy);

#endif

