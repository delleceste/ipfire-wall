#include "iqftextedit.h"
#include "qtextline_formatter.h"

#include <QSettings>
#include <QVariant>
#include <QtDebug>

#include <errno.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>

extern "C" /* Taken from ipfi/src/includes/utils.h */
{

/* given a protocol, two strings and two ports
 * in network byte order, copies service name 
 * as in etc/services in corresponding strings.
 * If no match is found, strings are empty ( "" )
 */
int resolv_ports(const struct ipfire_servent* ipfise,
	const unsigned short protocol, 
	char* srcserv, char* dstserv,
	__u16 sport, __u16 dport);
								
			
int filter_packet_to_print(const ipfire_info_t* p, const ipfire_rule_filter* f);
			
char* translation(const char* eng);	
#define TR(eng) (translation(eng) )
}

void IQFTextEdit::LoadColors()
{
	QSettings s;
	in_color = Qt::green;
	out_color = Qt::cyan;
	pre_color = Qt::yellow;
	post_color = Qt::blue;
	fwd_color = Qt::darkYellow;
 	acc_color = Qt::green;
	den_color = Qt::red;
	unkn_color = Qt::magenta;
	state_color = Qt::blue;
	tcp_color = Qt::darkGreen;
	udp_color = Qt::darkYellow;
	icmp_color = Qt::darkRed;
}


QString IQFTextEdit::fireinfo_line_formatter(const ipfire_info_t *pack)
{
	struct in_addr source_addr;
	struct in_addr dest_addr;
	char src_address[INET_ADDRSTRLEN];
	char dst_address[INET_ADDRSTRLEN];
	char sport_res[16] = "";
	char dport_res[16] = "";
	source_addr.s_addr = pack->iphead.saddr;
	dest_addr.s_addr = pack->iphead.daddr;
	
	QString newline = ""; /* Initialize */

	/* See if we have to filter out the packet to print */
	/* Pass NULL as filter for now... it will return 0 */
	if(filter_packet_to_print(pack, NULL) < 0)
		return newline;
	
	inet_ntop(AF_INET, (void*)  &source_addr, src_address, 
					INET_ADDRSTRLEN);
	inet_ntop(AF_INET, (void*)  &dest_addr, dst_address, 
					INET_ADDRSTRLEN);
	
	if( (pack->nat) & (!pack->snat) )
	{
		ColDnat
		insertPlainTextDummy("[DNAT]");
		newline += "[DNAT]";
		goto direction;
	}
	else if( (pack->snat) )
	{
		ColDnat
		insertPlainTextDummy("[SNAT]");
		newline += "[SNAT]";
		goto direction;
	}
	
	if(pack->badsum)
	{
		ColRed insertPlainTextDummy(TR("CKSUM ERR!"));
		newline += "CKSUM ERR!";
	}
	else if(pack->response < 0)
	{
		ColDen insertPlainTextDummy(QString("[X %1] ").arg(-pack->response));
		newline += QString("[X %1] ").arg(-pack->response);
	}
	else if(pack->response > 0)
	{
		ColAcc insertPlainTextDummy(QString("[OK %1] ").arg(pack->response) );
		newline += QString("[OK %1] ").arg(pack->response);
	}
	else
	{
		ColUnk insertPlainTextDummy("[?X] ");
		newline += "[?X] ";
	}
	
	direction:
	switch(pack->direction)
	{
		case IPFI_INPUT:
			ColIn
			insertPlainTextDummy("IN:  ");
			newline += "IN:  ";
		break;
		case IPFI_OUTPUT:
			ColOut
			insertPlainTextDummy("OUT: ");
			newline += "OUT: ";
		break;
		case IPFI_FWD:
			ColFwd
			insertPlainTextDummy("FWD: ");
			newline += "FWD: ";
		break;
		case IPFI_INPUT_PRE:
			ColPre
			insertPlainTextDummy("PRE: ");
			newline += "PRE: ";
		break;
		case IPFI_OUTPUT_POST:
			ColPost
			insertPlainTextDummy("POST:");
			newline += "POST";
		break;
	}
	
	QString dir;
	if(pack->direction == IPFI_FWD)
	{	
		insertPlainTextDummy( (dir = QString("[%1->%1] ").arg(pack->devpar.in_devname)
				.arg(pack->devpar.out_devname) ) );
		newline += dir;
	}
	else
	{
		if(strcmp(pack->devpar.in_devname, "n.a.") )
		{
			insertPlainTextDummy( (dir = QString("[%1] ").arg(pack->devpar.in_devname) ) );
			newline += dir;
			if(strlen(pack->devpar.in_devname) == 2) /* lo */
			{
				newline += "  ";
				insertPlainTextDummy("  "); /* just to align print */
			}
		}
		
		if(strcmp(pack->devpar.out_devname, "n.a.") )
		{		
			insertPlainTextDummy( (dir = QString("[%1] ").arg(pack->devpar.out_devname) ) );
			newline += dir;
			if(strlen(pack->devpar.out_devname) == 2) /* lo */
			{
				newline += "  ";
				insertPlainTextDummy("  "); /* just to align print */
			}
		}
	} /* Direction done */
	
	if(svent != NULL)
	{		
		resolv_ports(svent, 
			pack->protocol, sport_res, dport_res,
			pack->transport_header.tcphead.source,
			pack->transport_header.tcphead.dest);
	}
	
	QString info, flagset;
	switch(pack->protocol)
	{
		
		case IPPROTO_TCP:
			insertPlainTextDummy( (info = QString("|TCP| %1:").arg(src_address) ) );
			newline += info;

		if(strlen(sport_res) > 0)
		{
			insertPlainTextDummy( (info = QString("%1").arg(sport_res) ) );
			newline += info;
		}
		else
		{
			insertPlainTextDummy( (info = QString("%1").arg(ntohs
				(pack->transport_header.tcphead.source) ) ) );
			newline += info;
		}
		
		/* Separate source from dest */
		Bold insertPlainTextDummy("-->"); NoBold
		newline += "-->";	
		
		insertPlainTextDummy( (info = QString("%1:").arg(dst_address) ) );
			newline += info;

		if(strlen(dport_res) > 0)
		{
			insertPlainTextDummy( (info = QString("%1").arg(dport_res) ) );
			newline += info;
		}
		else
		{
			insertPlainTextDummy( (info = QString("%1 |").arg(ntohs
				(pack->transport_header.tcphead.dest) ) ) );
			newline += info;
		}
		
		
	    	if(pack->transport_header.tcphead.fin)
	    	{
			insertPlainTextDummy("F|");
			flagset += "F|";
	    	}
		if(pack->transport_header.tcphead.syn)
	    	{
			insertPlainTextDummy("S|");
			flagset += "S|";
	    	}
		if(pack->transport_header.tcphead.rst)
		{
#ifdef QTEXT_COLOR
			QColor c = textColor();
			ColRed
#endif
			insertPlainTextDummy("R|");
#ifdef QTEXT_COLOR
			setTextColor(c);
#endif
			flagset += "R|";
			insertPlainTextDummy("|");
		}
		if(pack->transport_header.tcphead.psh)
		{
			insertPlainTextDummy("P|");
			flagset += "P|";
	    	}
		if(pack->transport_header.tcphead.ack)
		{
			insertPlainTextDummy("A|");
			flagset += "A|";
	    	}
		if(pack->transport_header.tcphead.urg)
		{
#ifdef QTEXT_COLOR
			QColor c = textColor();
			ColRed
#endif
			insertPlainTextDummy("U|");
#ifdef QTEXT_COLOR
			setTextColor(c);
#endif
			flagset += "U|";
		}
		newline += flagset;
		break;
		

		case IPPROTO_UDP:

		insertPlainTextDummy( (info = QString("|UDP| %1:").arg(src_address) ) );
		newline += info;
		
		if(strlen(sport_res) > 0)
		{
			insertPlainTextDummy( (info = QString("%1").arg(sport_res) ) );
			newline += info;
		}
		else
		{
			insertPlainTextDummy( (info = QString("%1").arg(ntohs
				(pack->transport_header.tcphead.source) ) ) );
			newline += info;
		}
		
		/* Separate source from dest */
		Bold insertPlainTextDummy("-->"); NoBold
		newline += "-->";
		
		insertPlainTextDummy( (info = QString("%1:").arg(dst_address) ) );
			newline += info;

		if(strlen(dport_res) > 0)
		{
			insertPlainTextDummy( (info = QString("%1").arg(dport_res) ) );
			newline += info;
		}
		else
		{
			insertPlainTextDummy( (info = QString("%1 |").arg(ntohs
				(pack->transport_header.tcphead.dest) ) ) );
			newline += info;
		}	
		break;
		
		case IPPROTO_ICMP:
		insertPlainTextDummy( (info = QString("|ICMP| SRC:%1 --> DST:%2 |").arg(
		src_address).arg(dst_address) ) );	
		newline += info;
		insertPlainTextDummy( (info = QString("TYPE:%1|CODE: %2|").arg(
			pack->transport_header.icmphead.type).arg(
			pack->transport_header.icmphead.code) ) );
		break;
		
		default:
		insertPlainTextDummy("PROTO ");
		newline += "PROTO ";
		ColGray
		QString protocol;
		switch(pack->protocol)
		{
			case IPPROTO_IGMP:
				insertPlainTextDummy( (protocol = "IGMP" ));
			break;
			case IPPROTO_IPIP:
				insertPlainTextDummy( (protocol = "IPIP [TUNNELS]"));
			break;
			case IPPROTO_EGP:
				insertPlainTextDummy(  (protocol = "\"EXTERIOR GATEWAY\""));
			break;
			case IPPROTO_PUP:
				insertPlainTextDummy( (protocol = "PUP"));
			break;
			
			case IPPROTO_IDP:
				insertPlainTextDummy( (protocol = "XNS IDP"));
			break;
			case IPPROTO_RSVP:
				insertPlainTextDummy( (protocol = "RSVP"));
			break;
			case IPPROTO_GRE:
				insertPlainTextDummy(  (protocol = "\""  "CISCO GRE (RFC 1701, 1702)"  "\""));
			break;
			case IPPROTO_IPV6:
				insertPlainTextDummy( (protocol = "\""  "IPv6-in-IPv4 tunnelling"  "\"" ));
			break;
			
			case IPPROTO_ESP:
				insertPlainTextDummy( (protocol = "\""  "ENCAPSULATION SECURITY PAYLOAD [ESP]"  "\"" ));
			break;
			case IPPROTO_AH:
				insertPlainTextDummy( (protocol = "\""  "AUTHENTICATION HEADER"  "\"" ));
			break;
			case IPPROTO_PIM:
				insertPlainTextDummy( (protocol =  "\""  "INDEPENDENT MULTICAST"  "\"[" 
					 "PIM"  "]"));
			break;
			case IPPROTO_COMP:
				insertPlainTextDummy( (protocol = "\""  "COMPRESSION HEADER"  "\"") );
			break;
			
			case IPPROTO_SCTP:
				insertPlainTextDummy(  (protocol = "STREAM CONTROL TRASPORT PROTOCOL") );
			break;
			case IPPROTO_RAW:
				insertPlainTextDummy(  (protocol =  "RAW"  ));
			break;
		}
		
		insertPlainTextDummy( (protocol = " not supported!"));
		newline += protocol;
		break;
	}
	
	/* State */
	
	if( (pack->state) && (pack->response > 0) )
	{
		
			if(pack->st.state == SYN_SENT)
				insertPlainTextDummy( info = "SETUP" );
			else if(pack->st.state == SYN_RECV)
				insertPlainTextDummy(  info = "SETUP OK" );
			else if(pack->st.state == ESTABLISHED)
				insertPlainTextDummy(  info =  "EST" ); 
			else if(pack->st.state == LAST_ACK)
				insertPlainTextDummy(  info = "LAST ACK" );
			else if(pack->st.state == CLOSE_WAIT)
				insertPlainTextDummy(  info = "CLOSE WAIT" );
			else if(pack->st.state == INVALID)
				{ColRed insertPlainTextDummy(  info = "?" );}
			else if(pack->st.state == FIN_WAIT)
				insertPlainTextDummy(  info = "FIN WAIT" );
			else if(pack->st.state == IPFI_TIME_WAIT)
				insertPlainTextDummy(  info = "TIME WAIT" );
			else if(pack->st.state == NOTCP)
				    { ColYellow insertPlainTextDummy( info = "???" );}
			else if(pack->st.state == UDP_NEW)
			       { ColYellow insertPlainTextDummy( info = "NEW" );}
			else if(pack->st.state == UDP_ESTAB)
				       {ColYellow  insertPlainTextDummy( info = "STREAM" );}
			else if(pack->st.state == ICMP_STATE)
				       { ColRed  insertPlainTextDummy( info = "ICMP" );}
			     
			else if(pack->st.state == GUESS_ESTABLISHED)
				{ColViolet insertPlainTextDummy( info = "EST?" );}
			else if(pack->st.state == CLOSED)
				insertPlainTextDummy( info =  "CLOSED" );
			else if(pack->st.state == NOTCP)
				insertPlainTextDummy( info =  "S" );
			else if(pack->st.state == GUESS_CLOSING)
				{ColViolet insertPlainTextDummy( info =  "CLOSING?" );}
			else if(pack->st.state == INVALID_FLAGS)
				{ColRed insertPlainTextDummy(info = "INVALID FLAGS!" );}
			else if(pack->st.state == NULL_FLAGS)
				{ColRed insertPlainTextDummy( info = "NULL syn fin rst ack FLAGS!" );}
			else if(pack->st.state == GUESS_SYN_RECV)
				{ColViolet insertPlainTextDummy(info = "SETUP OK?" );}
			else 
				insertPlainTextDummy(info = QString("STATE: %1").arg( pack->st.state) );
			
	}
	else
		insertPlainTextDummy(info = "  ");
	
	newline += info;
	#ifdef ENABLE_RULENAME
	/* finally, print rule name */
	if(strlen(pack->rulename) > 0)
	{
		if(pack->response > 0)
		{
			ColGreen
			insertPlainTextDummy("[");
			ColGray
			insertPlainTextDummy(QString("%1").
				arg(pack->rulename));
			ColGreen
			insertPlainTextDummy("]");
		}
		else if(pack->response < 0)
		{
			ColRed
			insertPlainTextDummy("[");
			ColGray
			insertPlainTextDummy(QString("%1").
				arg(pack->rulename));
			ColRed
			insertPlainTextDummy("]");
			
		}
		else
			insertPlainTextDummy(QString("[ %1 ]").arg( pack->rulename));
		
		newline += QString("[%1]").arg(pack->rulename);
	}	
	#endif
	if(filter != NULL) /* if we are here we have passed the filter */
	{
		 insertPlainTextDummy(" ");
		 ColViolet
		 insertPlainTextDummy("F" );
	}
	insertPlainTextDummy("\n");
	//newline += "\n";
	//qDebug() << toHtml();
	//qDebug() << "----------------------------------------------";

	//insertPlainText(lastline);
	//qDebug() << "non inserisco " << newline;
	return newline;
	
	
}







