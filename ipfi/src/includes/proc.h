#ifndef PROC_H
#define PROC_H

/* returns -1 if fails, the value read on success */
int read_rmem_default();

/* returns -1 if fails, the value read on success */
int read_rmem_max();

/* < 0 failed, 1 accept, 0 deny */
short int read_policy();

/* returns -1 if fails, 0 otherwise */
int write_rmem_default(unsigned int n);

/* returns -1 if fails, 0 otherwise */
int write_rmem_max(unsigned int n);

/* returns -1 if fails, 0 otherwise.
 * accepts 0 for drop, > 0 for accept.
 */
int write_policy(unsigned short p);

int check_proc_entries(short policy, unsigned proc_rmem_max, unsigned proc_rmem_default);

#endif

