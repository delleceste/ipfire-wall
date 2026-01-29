#include "includes/ipfi_proc.h"
#include <linux/module.h>
#include <linux/version.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
  #include "includes/ipfi_netl.h"
#endif

static struct proc_dir_entry *ipfire_procent, *procdir;
static char procentry_line[PROCENTRY_DATA_LEN];

static ssize_t ipfire_proc_read(struct file *file, char __user *buf,
			      size_t count, loff_t *ppos)
{
	char *data = pde_data(file_inode(file));
	char msg[PROCENTRY_DATA_LEN + 64];
	int len;

	if (!data)
		return 0;

	len = snprintf(msg, sizeof(msg), "IPFIRE default behaviour when a packet does not match: %s\n", data);

	return simple_read_from_buffer(buf, count, ppos, msg, len);
}

static ssize_t ipfire_proc_write(struct file *file, const char __user *buf,
			       size_t count, loff_t *ppos)
{
	int len;
	
	if (count > PROCENTRY_DATA_LEN)
		len = PROCENTRY_DATA_LEN;
	else
		len = count;

	if (copy_from_user(procentry_line, buf, len))
		return -EFAULT;

	procentry_line[len] = '\0';
	/* strip newline if present */
	if (len > 0 && procentry_line[len-1] == '\n')
		procentry_line[len-1] = '\0';
		
	set_policy(procentry_line);
	return len;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,6,0)
static const struct proc_ops ipfire_proc_ops = {
	.proc_read = ipfire_proc_read,
	.proc_write = ipfire_proc_write,
	.proc_lseek = default_llseek,
};
#else
static const struct file_operations ipfire_proc_ops = {
	.owner = THIS_MODULE,
	.read = ipfire_proc_read,
	.write = ipfire_proc_write,
	.llseek = default_llseek,
};
#endif

int init_procentry(const char *name, const char *value)
{
	procdir = proc_mkdir(PROCDIR, NULL);
	if (!procdir) {
		printk("IPFIRE: error creating proc dir!\n");
		return -ENOMEM;
	}

	strncpy(procentry_line, value, PROCENTRY_DATA_LEN);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,6,0)
	ipfire_procent = proc_create_data(name, 0644, procdir, &ipfire_proc_ops, procentry_line);
#else
	ipfire_procent = proc_create_data(name, 0644, procdir, &ipfire_proc_ops, procentry_line);
#endif

	if (ipfire_procent == NULL)
	{
		printk("IPFIRE: error creating proc entry!\n");
		remove_proc_entry(PROCDIR, NULL);
		return -ENOMEM;
	}
	return 0;
}

void set_procentry_values(void)
{
	/* Deprecated/Removed functionality - no-op */
}

void clean_proc(void)
{
  if (ipfire_procent)
      remove_proc_entry(PROCENT, procdir);
  if (procdir)
      remove_proc_entry(PROCDIR, NULL);
}
