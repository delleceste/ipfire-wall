#ifndef IPFI_STATE_MACHINE_H
#define IPFI_STATE_MACHINE_H

#include "ipfi_machine.h"
#include "ipfi.h"

/* Stateful machine implementatione. Not intended to be exhaustive! */
int state_machine(const ipfire_info_t *info, int current_state, short reverse);

/* Applies the state given by the state_machine() inside the table structure. */
int set_state(ipfire_info_t* info, struct state_table* entry, short reverse);

#endif
