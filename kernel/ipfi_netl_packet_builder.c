#include "includes/ipfi_netl_packet_builder.h"

struct sk_buff *build_packet(void *buf, int numbytes)
{
  struct sk_buff *skb_to_user;
  struct nlmsghdr *nlh;
  void *data;
  int len = NLMSG_SPACE(numbytes);
  
  skb_to_user = alloc_skb(len, GFP_ATOMIC);
  
  if(skb_to_user == NULL)
    return NULL;

  nlh = nlmsg_put(skb_to_user, 0, 0, 0, numbytes, 0);

  if(NLMSG_OK(nlh, NLMSG_LENGTH(numbytes)))
  {
    nlh->nlmsg_len = NLMSG_LENGTH(numbytes);
    data = NLMSG_DATA(nlh);
    memcpy(data, buf, numbytes);
  }
  else
  {
    printk("IPFIRE: NLMSG_OK failed: NLMSG_LENGTH(%d) is %d, NLMSG_SPACE(numbytes %d) is %d in build_packet(), "
      "ipfi_netl_packet_builder.c\n", len, NLMSG_LENGTH(len),  numbytes, NLMSG_SPACE(numbytes));
    return NULL;
  }
  return skb_to_user;
  
  nlmsg_failure:
  
  printk("IPFIRE: nlmsg failure in build_packet() - NLMSG_SPACE:%dbytes - netlink header:%dbytes - data length:%dbytes - NLMSG_LENGTH(data len): %dbytes - ipfi_netl_packet_builder.c\n", len, sizeof(struct nlmsghdr), numbytes, NLMSG_LENGTH(numbytes));
  return NULL;
}

struct sk_buff *build_command_packet(const command *cmd)
{
  struct sk_buff* skb_to_user = NULL;
  skb_to_user = build_packet((void *) cmd, sizeof(command));
  return skb_to_user;
}

struct sk_buff *build_info_t_packet(const ipfire_info_t *info)
{
  struct sk_buff* skb_to_user = NULL;
  skb_to_user = build_packet((void *) info, sizeof(ipfire_info_t));
  return skb_to_user;
}

struct sk_buff *build_dnat_t_packet(const struct dnatted_table *dt)
{
  struct sk_buff* skb_to_user = NULL;
  skb_to_user = build_packet((void *) dt, sizeof(*dt));
  return skb_to_user;
}

struct sk_buff *build_snat_t_packet(const struct snatted_table *st)
{
  struct sk_buff* skb_to_user = NULL;
  skb_to_user = build_packet((void *) st, sizeof(*st));
  return skb_to_user;
}

struct sk_buff *build_snat_info_packet(const struct snat_info *sni)
{
  struct sk_buff* skb_to_user = NULL;
  skb_to_user = build_packet((void *) sni, sizeof(*sni));
  return skb_to_user;
}

struct sk_buff *build_dnat_info_packet(const struct dnat_info *dni)
{
  struct sk_buff* skb_to_user = NULL;
  skb_to_user = build_packet((void *) dni, sizeof(*dni));
  return skb_to_user;
}

struct sk_buff *build_state_packet(const struct state_table *st)
{
  struct sk_buff* skb_to_user = NULL;
  skb_to_user = build_packet((void *) st, sizeof(*st));
  return skb_to_user;
}

struct sk_buff* build_ktable_info_packet(const struct ktables_usage* ktu)
{
  struct sk_buff* skb_to_user = NULL;
  skb_to_user = build_packet((void *) ktu, sizeof(*ktu));
  return skb_to_user;
}

struct sk_buff *build_state_info_packet(const struct state_info *sti)
{
  struct sk_buff* skb_to_user = NULL;
  skb_to_user = build_packet((void *) sti, sizeof(*sti));
  return skb_to_user;
}

struct sk_buff* build_kstats_packet(const struct kernel_stats *kst)
{
  struct sk_buff* skb_to_user = NULL;
  skb_to_user = build_packet((void *) kst, sizeof(*kst));
  return skb_to_user;
}

struct sk_buff* build_kstats_light_packet(const struct kstats_light *kstl)
{
  struct sk_buff* skb_to_user = NULL;
  skb_to_user = build_packet((void *) kstl, sizeof(*kstl));
  return skb_to_user;
}







