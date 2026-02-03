#include "includes/ipfi_state_machine.h"

int state_machine(const struct sk_buff *skb, int current_state, short reverse)
{
	unsigned short protocol;
	unsigned short syn, ack, rst, fin;
	int state = IPFI_NOSTATE;

	syn = ack = fin = rst = 0;

        protocol = skb->protocol;

        struct iphdr *iph;
        iph = ip_hdr(skb);
        protocol = iph->protocol;

        if (protocol == IPPROTO_TCP)
        {
            struct tcphdr *th = (struct tcphdr *)((void *)iph + iph->ihl * 4);
            syn = th->syn;
            ack = th->ack;
            rst = th->rst;
            fin = th->fin;
        }
          else if(protocol == IPPROTO_UDP)
          {
		/* A minimal state machine for udp datagrams:
		* 1st packet seen (UDP_NEW) and then established
		*/

		/* The first UDP packet seen */
		if(current_state == IPFI_NOSTATE) /* entry initialized */
			state = UDP_NEW;

		else if(current_state == UDP_NEW)
			state = UDP_ESTAB;

		else if(current_state == UDP_ESTAB)
			state = UDP_ESTAB;
		else
			state = UDP_UNKNOWN;

		return state;

          }
	else if(protocol == IPPROTO_ICMP)
	{
		state = ICMP_STATE;
		return state;
	}
	else if(protocol == IPPROTO_IGMP)
	{
		state = IGMP_STATE;
		return state;
	}
	else if(protocol == IPPROTO_GRE)
	{
	  state = GRE_STATE;
	  return state;
	}
	else if(protocol == IPPROTO_PIM)
	{
	  state = PIM_STATE;
	  return state;
	}
	else
	{
		state = NOTCP;
		return state;
	}
	/* TCP */
	/* Established case which remains established: most frequent case. */
	if (current_state == ESTABLISHED && ack && !syn && !rst
			&& !fin)
	{
		return ESTABLISHED;	  
	}
	else if(current_state == FTP_NEW && syn && !ack)
	  state = SYN_SENT;
	else if (current_state == IPFI_NOSTATE)
	{
		/* SYN/ACK as first packet: guess setup confirmation */
		if (!rst && !fin && syn && ack)
		{
			state = GUESS_SYN_RECV;
		}
		/* Take care that a TCP connection is initiated properly */
		else if (syn && !ack)
		{
			state = SYN_SENT;
		}
		/* Already started connections are allowed */
		else if ((!rst) && (!fin) && (!syn))
		{
			state = GUESS_ESTABLISHED;
		}
		/* Final steps: don't know if first or second fin.  */
		else if (!rst && fin && !syn && ack)
		{
			state = GUESS_CLOSING;
		}
		else
			state = INVALID_STATE;
	}

	/* A: SYN sent state: we expect a SYN/ACK. If we receive a RST, connection
	* is aborted, if another SYN appears, it can be a retransmission */
	/* 1. Expecting syn/ack reverse must be 1: SYN/ACK must be received 
	* from the other host. */
	else if ((current_state == SYN_SENT) && (syn == 1)
			&& (ack == 1) && (reverse == 1) && (!rst) && (!fin))
		state = SYN_RECV;
	else if ((current_state == SYN_SENT) && (rst))	/* 2. RST received */
		state = CLOSED;
	/* A syn has been sent and retrasmitted */
	else if ((current_state == SYN_SENT) && (syn) && (!ack))
		state = SYN_SENT;
	else if (current_state == SYN_SENT)	/* SYN sent but no SYN/ACK */
		state = INVALID_STATE;

	/* B: SYN RECV  STATE */
	/* we are in SYN RECV and _we_ send a SYN/ACK: we enter in established. */
	else if (((current_state == SYN_RECV) ||
				(current_state == GUESS_SYN_RECV))
			&& (!rst) && (!fin) && (!syn) && (reverse == 0) && (ack))
		state = ESTABLISHED;
	/* we sent a SYN and we send another one or we received a SYN and
	* we receive another one */
	else if (((current_state == SYN_RECV) ||
				(current_state == GUESS_SYN_RECV))
			&& (syn) && (!reverse))
		state = SYN_RECV;
	/* syn-syn/ack and rst: stealth scannin'? */
	else if ((current_state == SYN_RECV) && (rst))
		state = CLOSED;
	/* Not usual, but we can receive a FIN here */
	else if ((current_state == SYN_RECV) && (fin))
		state = FIN_WAIT;
	else if (current_state == SYN_RECV)	/* SYN RECV but not ack */
		state = INVALID_STATE;

	/* C: ESTABLISHED state: we can continue communication or receive a FIN
	* or a RST */
	else if ((current_state == ESTABLISHED) && (rst))
		state = CLOSED;
	else if ((current_state == ESTABLISHED) && (fin))	/* first FIN seen */
		state = FIN_WAIT;
	/* We think we are in ESTABLISHED but another SYN/ACK is seen */
	else if ((current_state == ESTABLISHED) && (syn == 1)
			&& (ack == 1) && (reverse == 1) && (!rst) && (!fin))
		state = ESTABLISHED;
	/* D: FIN WAIT */
	else if (current_state == GUESS_CLOSING)
	{
		if (syn)
			state = INVALID_STATE;
		else if (rst)
			state = CLOSED;
		else
			state = GUESS_CLOSING;	  
	} 
	else if ((current_state == FIN_WAIT) && (ack) && (fin)
			&& (reverse))
		state = LAST_ACK;
	else if ((current_state == FIN_WAIT) && (ack))	/* ACK seen (after FIN) */
		state = CLOSE_WAIT;
	/* Another FIN: we remain in the same state. */
	else if ((current_state == FIN_WAIT) && (fin))
		state = FIN_WAIT;
	/* E: CLOSE WAIT */
	else if ((current_state == CLOSE_WAIT) && (fin))	/* FIN seen (after FIN) */
		state = LAST_ACK;
	/* another ack in response to first FIN: remain in close wait */
	else if ((current_state == CLOSE_WAIT) && (ack))
		state = CLOSE_WAIT;
	/* F: LAST ACK */
	else if ((current_state == LAST_ACK) && (ack))	/* last ACK seen */
		state = IPFI_TIME_WAIT;
	/* duplicate FIN */
	else if ((current_state == LAST_ACK) && (fin))
		state = LAST_ACK;
	/* G: TIME WAIT: we remain here. */
	else if (current_state == IPFI_TIME_WAIT)
		state = IPFI_TIME_WAIT;
	/* bad cases */
	else if ((current_state == ESTABLISHED) && (syn))
		state = INVALID_STATE;
	else if (!syn && !ack && !rst && !fin)
		state = NULL_FLAGS;
	else if ((syn && rst) || (syn && fin) || (fin && rst))
		state = INVALID_FLAGS;
	/* Anyway reset causes connection abort */
	else if (rst)
		state = CLOSED;

        }
	return state;

}

/* Sets the state inside the state structure. */
int set_state(const struct sk_buff* skb, struct state_table *entry, short reverse)
{
	int state;
	/* Get the state */
    state = state_machine(skb, entry->state.state, reverse);
	/* Set the state */
	if(state == GUESS_CLOSING)
		entry->state.state = CLOSED;
	else if(state == GUESS_SYN_RECV)
		entry->state.state = SYN_RECV;
	else if(state == GUESS_ESTABLISHED)
		entry->state.state = ESTABLISHED;
	else
		entry->state.state = state;
    return state;
}



