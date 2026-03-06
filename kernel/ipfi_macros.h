/* macros in ip_input.c, ip_output.c, ip_forward.c */
 
#define IPFI_INPUT_FUNCTION()  \
ipfi_packet_input_counter ++; \
	if(ipfi_input_processing != NULL) /* pre routing processing */ \
{ \
	printk("INPUT: LOCAL_DELIVER()  [LOCAL_IN]: %lu\n", ipfi_packet_input_counter); 	\
	if( ipfi_input_processing(skb, ipfi_packet_input_counter, IPFI_INPUT) == IPFI_DROP)	\
		return IPFI_DROP;	\
}	\
	else	\
{	\
	if(ipfi_packet_input_counter % PRINTK_WARN_IPFI_DISABLED == 0)	\
		printk("IPFI: WARNING: FIREWALL DISABLED [input packet n. %lu]\n",	\
		       ipfi_packet_input_counter);	\
}	\


#define IPFI_PRE_FUNCTION() \
ipfi_packet_pre_counter ++;	\
if(ipfi_pre_processing != NULL) /* pre routing processing */	\
{	\
	printk("INPUT: IP_RCV [LOCAL_PRE]: %lu\n", ipfi_packet_pre_counter);	\
	if( ipfi_pre_processing(skb, ipfi_packet_pre_counter, IPFI_INPUT_PRE) == IPFI_DROP)	\
		return IPFI_DROP;	\
}	\
	else	\
{	\
	if(ipfi_packet_pre_counter % PRINTK_WARN_IPFI_DISABLED == 0)	\
		printk("IPFI: WARNING: FIREWALL DISABLED [input pre packet n. %lu]\n",	\
		       ipfi_packet_pre_counter);	\
}	

#define IPFI_OUTPUT_FUNCTION()	\
ipfi_packet_output_counter ++;	\
	\
if(ipfi_output_processing != NULL) /* pre routing processing */	\
{	\
	if(ipfi_output_processing(skb, ipfi_packet_output_counter, IPFI_OUTPUT) 	\
		  == IPFI_DROP)	\
		return IPFI_DROP;	\
}	\
	else	\
{	\
	if(ipfi_packet_output_counter % PRINTK_WARN_IPFI_DISABLED == 0)	\
		printk("IPFI: WARNING: FIREWALL DISABLED [output packet n. %lu]\n",	\
		       ipfi_packet_output_counter);	\
}

#define IPFI_POST_FUNCTION()	\
ipfi_post_packet_counter++;	\
	printk("IPFI_FINISH_OUTPUT() [POSTROUTING]: %lu\n", ipfi_post_packet_counter);	\
	if(ipfi_post_processing == NULL)	\
{	\
	if(ipfi_post_packet_counter % PRINTK_WARN_IPFI_DISABLED == 0)	\
		printk("IPFI: WARNING FIREWALL DISABLED [output post packet n.%lu]\n",	\
		       ipfi_post_packet_counter);	\
}	\
	else	\
{	\
	if(ipfi_post_processing(skb, ipfi_post_packet_counter, IPFI_OUTPUT_POST) == IPFI_DROP)	\
		return IPFI_DROP;	\
}

#define IPFI_FWD_FUNCTION() 	\
ipfi_packet_forward_counter ++;	\
if(ipfi_forward_processing != NULL) /* pre routing processing */	\
{	\
	if( ipfi_forward_processing(skb, ipfi_packet_forward_counter, IPFI_FWD) == IPFI_DROP)	\
		return IPFI_DROP;	\
}	\
else	\
{	\
	if(ipfi_packet_forward_counter % PRINTK_WARN_IPFI_DISABLED == 0)	\
		printk("IPFI: WARNING: FIREWALL DISABLED [forward packet n. %lu]\n",	\
		       ipfi_packet_forward_counter);	\
}
