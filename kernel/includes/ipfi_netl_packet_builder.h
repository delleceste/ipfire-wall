#ifndef NETLINK_PACKET_BUILDER_H
#define NETLINL_PACKET_BUILDER_H

#include "ipfi.h"
#include "ipfi_machine.h"
#include "ipfi_translation.h"

struct sk_buff *build_packet(void *buf, int numbytes);

struct sk_buff* build_command_packet(const command *cmd);

struct sk_buff* build_info_t_packet(const ipfire_info_t *info);

struct sk_buff* build_dnat_t_packet(const struct dnatted_table *dt);

struct sk_buff* build_snat_t_packet(const struct snatted_table *dt);

struct sk_buff* build_dnat_info_packet(const struct dnat_info *dni);

struct sk_buff* build_snat_info_packet(const struct snat_info *sni);

struct sk_buff* build_state_packet(const struct state_table *st);

struct sk_buff* build_state_info_packet(const struct state_info *sti);

struct sk_buff* build_kstats_packet(const struct kernel_stats *kst);

struct sk_buff* build_kstats_light_packet(const struct kstats_light *kstl);

struct sk_buff* build_ktable_info_packet(const struct ktables_usage* ktu);

#endif
