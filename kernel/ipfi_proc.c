#include "includes/ipfi_proc.h"
#include <linux/module.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
  #include <linux/uaccess.h> /* for copy_from_user */
#else
  #include "includes/ipfi_netl.h"
#endif

static struct proc_dir_entry *ipfire_procent, *procdir;
static char procentry_line[PROCENTRY_DATA_LEN];

int init_procentry(const char *name, const char *value)
{
	procdir = proc_mkdir(PROCDIR, NULL);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,30)
	procdir->owner = THIS_MODULE;
#endif
	ipfire_procent = create_proc_entry(name, 0644, procdir);
	if (ipfire_procent == NULL)
	{
		printk("IPFIRE: error creating proc entry!\n");
		return -ENOMEM;
	}
	strncpy(procentry_line, value, PROCENTRY_DATA_LEN);
	ipfire_procent->data = procentry_line;
	return 0;
}

void set_procentry_values(void)
{
	ipfire_procent->read_proc = &proc_read_ipfire;
	ipfire_procent->write_proc = &proc_write_ipfire;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,30)
	ipfire_procent->owner = THIS_MODULE;
#endif
}

int proc_read_ipfire(char *page, char **start, off_t off,
		int count, int *eof, void *data)
{
	int len;

	/* cast the void pointer of data to char* */
	char *ipfire_policy = (char *) data;

	/* use sprintf to fill the page array with a string */
	len = sprintf(page, "IPFIRE default behaviour when a packet"
			" does not match: %s\n", ipfire_policy);

	return len;
	return 0;
}

int proc_write_ipfire(struct file *file, const char *page,
		unsigned long count, void *data)
{
	int len;

	/* do a range checking, don't overflow buffers in kernel modules */
	if (count > PROCENTRY_DATA_LEN)
		len = PROCENTRY_DATA_LEN;
	else
		len = count;

	/* use the copy_from_user function to copy page data to
	 * to our char. */
	if (copy_from_user(procentry_line, page, len))
	{
		return -EFAULT;
	}

	/* zero terminate procentry_line */
	procentry_line[len] = '\0';
	set_policy(procentry_line);
	return len;
}

void clean_proc()
{
  remove_proc_entry(PROCENT, procdir);
  remove_proc_entry(PROCDIR, NULL);
}

