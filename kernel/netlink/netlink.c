/* netlink/netlink.c: Netlink socket management for ipfire-wall */

#include <linux/module.h>
#include <linux/netlink.h>
#include <net/sock.h>
#include <linux/version.h>
#include "ipfi.h"
#include "ipfi_netl.h"
#include "globals.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
static void nl_receive_control(struct sk_buff* skb);
static void nl_receive_data(struct sk_buff* skb);
#else
static void nl_receive_control(struct sock *sk, int len);
static void nl_receive_data(struct sock *sk, int len);
#endif

static int create_control_socket(void)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,14)
    sknl_ipfi_control =
            netlink_kernel_create(NETLINK_IPFI_CONTROL,
                                  nl_receive_control);

#elif LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22) 
    sknl_ipfi_control = netlink_kernel_create(NETLINK_IPFI_CONTROL, 0, nl_receive_control, THIS_MODULE);

#elif LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
    sknl_ipfi_control = netlink_kernel_create(NETLINK_IPFI_CONTROL, 0,
                                              nl_receive_control, NULL, THIS_MODULE);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(3,6,0)
    sknl_ipfi_control = netlink_kernel_create(&init_net, NETLINK_IPFI_CONTROL, 0, nl_receive_control, NULL, THIS_MODULE);
#else
    struct netlink_kernel_cfg netlink_cfg;
    netlink_cfg.groups = 0;
    netlink_cfg.flags = 0;
    netlink_cfg.input = nl_receive_control;
    netlink_cfg.bind = NULL;
    sknl_ipfi_control = netlink_kernel_create(&init_net, NETLINK_IPFI_CONTROL, &netlink_cfg);

#endif

    userspace_control_pid = 0;
    if (sknl_ipfi_control == NULL)
    {
        IPFI_PRINTK("IPFIRE: create_socket(): failed to create netlink control socket\n");
        return -1;
    }
    return 0;
}

static int create_data_socket(void)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,14)
    sknl_ipfi_data =
            netlink_kernel_create(NETLINK_IPFI_DATA, nl_receive_data);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22)
    sknl_ipfi_data =
            netlink_kernel_create(NETLINK_IPFI_DATA, 0, nl_receive_data,
                                  THIS_MODULE);

#elif LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)

    sknl_ipfi_data = netlink_kernel_create(NETLINK_IPFI_DATA, 0, nl_receive_data, NULL, THIS_MODULE);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(3,6,0)
    sknl_ipfi_data = netlink_kernel_create(&init_net, NETLINK_IPFI_DATA, 0, nl_receive_data, NULL, THIS_MODULE);
#else
    struct netlink_kernel_cfg netlink_cfg;
    netlink_cfg.groups = 0;
    netlink_cfg.flags = 0;
    netlink_cfg.input = nl_receive_data;
    netlink_cfg.bind = NULL;
    sknl_ipfi_data = netlink_kernel_create(&init_net, NETLINK_IPFI_DATA, &netlink_cfg);
#endif

    userspace_data_pid = 0;
    if (sknl_ipfi_data == NULL)
    {
        printk ("IPFIRE: create_socket(): failed to create netlink data socket\n");
        return -1;
    }
    return 0;
}

static int create_gui_notifier_socket(void)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,14)
    sknl_ipfi_gui_notifier =
            netlink_kernel_create(NETLINK_IPFI_GUI_NOTIFIER, NULL);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22)
    sknl_ipfi_gui_notifier = netlink_kernel_create(NETLINK_IPFI_GUI_NOTIFIER, 0, NULL,  THIS_MODULE);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)

    sknl_ipfi_gui_notifier = netlink_kernel_create(NETLINK_IPFI_GUI_NOTIFIER, 0, NULL,  NULL, THIS_MODULE);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(3,6,0)
    sknl_ipfi_gui_notifier = netlink_kernel_create(&init_net, NETLINK_IPFI_GUI_NOTIFIER, 0, NULL,  NULL, THIS_MODULE);
#else
    struct netlink_kernel_cfg netlink_cfg;
    netlink_cfg.groups = 0;
    netlink_cfg.flags = 0;
    netlink_cfg.input = NULL;
    netlink_cfg.bind = NULL;
    sknl_ipfi_gui_notifier = netlink_kernel_create(&init_net, NETLINK_IPFI_GUI_NOTIFIER, &netlink_cfg);
#endif
    userspace_data_pid = 0;
    if (sknl_ipfi_gui_notifier == NULL)
    {
        IPFI_PRINTK("IPFIRE: create_socket(): failed to create netlink gui notifier socket\n");
        return -1;
    }
    return 0;
}

int send_data_to_user(struct sk_buff *skb, pid_t destination_pid, struct sock *socket) {
    int ret = -1;
    if(socket != NULL && skb != NULL) {
        NETLINK_CB(skb).portid = 0;	/* kernel sending */
        NETLINK_CB(skb).dst_group = 0;
        ret = netlink_unicast(socket, skb, destination_pid, MSG_DONTWAIT);
        if(ret < 0)
            IPFI_PRINTK("IPFIRE: netlink_unicast() to pid %d failed with error %d. Errnos in asm-generic/errno-base.h\n", destination_pid, ret);
    }
    else
        IPFI_PRINTK("socket or sk_buff null in send_data_to_user(): socket: 0x%p skb: 0x%p\n", socket, skb);
    return ret;
}

pid_t get_sender_pid(const struct sk_buff *skbff)
{
    int ret = 0;
    pid_t header_pid, credentials_pid;
    struct nlmsghdr *nlh = nlmsg_hdr(skbff);
    if(nlh == NULL)  {
        IPFI_PRINTK("IPFIRE: get_sender_pid(): error extracting nlmsghdr from socket buffer. Cannot determine header pid\n");
        ret = 0;
    }
    else
    {
        header_pid =  nlh->nlmsg_pid;
        if(1)
        {
            credentials_pid = NETLINK_CB(skbff).portid;
            if(credentials_pid != header_pid)
            {
                IPFI_PRINTK("IPFIRE: PID mismatch! Did you try to fool me? :)\nIPFIRE: CREDENTIALS PID: %u, HEADER PID: %u\n",
                            credentials_pid, header_pid);
                ret = 0;
            }
            else
                ret = header_pid;
        }
    }
    return ret;
}

static void nl_receive_control(struct sk_buff* skb)
{
    pid_t pid;

    pid = get_sender_pid(skb);
    userspace_uid = from_kuid(&init_user_ns, NETLINK_CREDS(skb)->uid);
    if ((userspace_control_pid != 0) &&
            (pid != userspace_control_pid))
        send_back_fw_busy(pid);
    else
    {
        userspace_control_pid = pid;
        process_control_received(skb);
    }
}

static void nl_receive_data(struct sk_buff *skb)
{
    userspace_data_pid = get_sender_pid(skb);
    process_data_received(skb);
}

void init_ruleset_heads(void)
{
    /* initialize lists */
    INIT_LIST_HEAD(&in_drop.list);
    INIT_LIST_HEAD(&out_drop.list);
    INIT_LIST_HEAD(&fwd_drop.list);
    INIT_LIST_HEAD(&in_acc.list);
    INIT_LIST_HEAD(&out_acc.list);
    INIT_LIST_HEAD(&fwd_acc.list);
    INIT_LIST_HEAD(&translation_pre.list);
    INIT_LIST_HEAD(&translation_out.list);
    INIT_LIST_HEAD(&translation_post.list);
    INIT_LIST_HEAD(&masquerade_post.list);
}

int init_netl(void)
{
    int ctrl_so, data_so, gui_so;
    data_so = 0, ctrl_so = 0, gui_so = 0;
    ctrl_so = create_control_socket();
    data_so = create_data_socket();
    gui_so = create_gui_notifier_socket();

    memset(moderate_print, 0, sizeof(unsigned int) * MAXMODERATE_ARGS);
    memset(moderate_print_limit, 0, sizeof(unsigned int) * MAXMODERATE_ARGS);
    moderate_print_limit[PRINT_PROTO_UNSUPPORTED] = 10000;

    memset(&kslight, 0, sizeof(kslight));
    if (ctrl_so == 0 && data_so == 0 && gui_so == 0)
        return 0;
    else
        return -1;
}

void fini_netl(void)
{
    IPFI_PRINTK("IPFIRE: Closing netlink sockets: control... ");
    if (sknl_ipfi_control != NULL)
    {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
        sock_release(sknl_ipfi_control->sk_socket);
#else
        netlink_kernel_release(sknl_ipfi_control);
#endif
    }
    else
        IPFI_PRINTK("IPFIRE: NULL control netlink socket!\n");

    IPFI_PRINTK("data... ");

    if (sknl_ipfi_data != NULL)
    {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
        sock_release(sknl_ipfi_data->sk_socket);
#else
        netlink_kernel_release(sknl_ipfi_data);
#endif
    }
    else
        IPFI_PRINTK("IPFIRE: NULL data netlink socket!\n");

    IPFI_PRINTK("GUI notifier.\n");

    if (sknl_ipfi_gui_notifier != NULL)
    {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
        sock_release(sknl_ipfi_gui_notifier->sk_socket);
#else
        netlink_kernel_release(sknl_ipfi_gui_notifier);
#endif
    }
    else
        IPFI_PRINTK("IPFIRE: the gui notifier socket is already NULL (disabled)!\n");
}
