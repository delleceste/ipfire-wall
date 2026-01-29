#include <iqfpopup_notifier.h>
#include "iqfwidgets.h"
#include "rule_builder.h"
#include "iqf_utils.h"
#include "iqfpolicy.h"
#include "ignored_packets_set.h"
#include "colors.h"
#include "iqflog.h"
#include "resolver_proxy.h"

#include <QHBoxLayout>
#include <QButtonGroup>
#include <QLabel>
#include <QHeaderView>
#include <QStringList>
#include <QMessageBox>
#include <QMouseEvent>
#include <QDir>
#include <QFile>
#include <QMenu>
#include <arpa/inet.h> /* for inet_ntoa */
#include <netdb.h>
#include <unistd.h>
#include <sys/socket.h>       /* for AF_INET (in gethostbyaddr() ) */

IQFPendingTreeItem::IQFPendingTreeItem(QTreeWidget *treewidget, ipfire_info_t* info, bool enable_resolve) 
	:  IQFTreeWidgetItem(treewidget), has_ignored(false)

{
	resolve_enabled = enable_resolve;
	/* copy information in ipfire_info_t myinfo.
	 * Remeber that the caller (the system tray calls addInfo passing
	 * the pointer to info, addInfo calls us, then the system tray
	 * deletes info!
	 */
	memcpy(&myinfo, info, sizeof(myinfo));
	
	_policy = IGNORE_PACKET_FOREVER;
	
	setFlags(Qt::ItemIsSelectable | Qt::ItemIsEditable | Qt::ItemIsEnabled);
	
	QStringList itemElems = infoToItemStringList(info);
	
	setText(0, itemElems[0]);
	setText(1, itemElems[1]);
	setText(2, itemElems[2]);
	setText(4, itemElems[4]);
	setText(5, itemElems[5]);
	setText(6, itemElems[6]);
	setText(7, itemElems[7]);
	setText(8, itemElems[8]);
	
	setObjectName(QString("Popup tree item for rule named \"%1\"").arg(text(7)));
	
	setToolTip(3, QString("Source port is usually ignored. Anyway it was %1\n"
		"If you want you can click and set it!").arg(itemElems[3]));
	setText(3, "-"); /* hide the source port */
	
	setToolTip(7, "Click to change the name");
	setStoredItems(toStringList());
	if(resolve_enabled)
	{
		resolve();
	}
}


IQFPendingTreeItem::IQFPendingTreeItem(QTreeWidget *widget, IgnoredPacket& ign, bool enable_resolve)
	: IQFTreeWidgetItem(widget), myignored(ign)
{
	struct in_addr ina;
	has_ignored = true;
	resolve_enabled = enable_resolve;
	
	memset(&myinfo, 0, sizeof(myinfo));
	setFlags(Qt::ItemIsSelectable | Qt::ItemIsEditable | Qt::ItemIsEnabled);
	if(ign.ips)
	{
		ina.s_addr = ign.sip;
		setText(2, inet_ntoa(ina));
	}
	else
		setText(2, "-");
	
	if(ign.ipd)
	{
		ina.s_addr = ign.dip;
		setText(4, inet_ntoa(ina));
	}
	else
		setText(4, "-");
	
	switch(ign.direction)
	{
		case IPFI_INPUT:
			setText(0, "IN");
			setText(7, QString("in from %1").arg(text(2)));
			break;
		case IPFI_OUTPUT:
			setText(0, "OUT");
			setText(7, QString("out to %1").arg(text(4)));
			break;
		case IPFI_FWD:
			setText(0, "FWD");
			break;
		default:
			setText(0, "INVALID");
			break;
	}
	
	if(ign.prot == 0)
		setText(1, "-");
	else
	{
		switch(ign.protocol)
		{
			case IPPROTO_TCP:
				setText(1, "TCP");
				break;
			case IPPROTO_UDP:
				setText(1, "UDP");
				break;
			case IPPROTO_ICMP:
				setText(1, "ICMP");
				break;
			case IPPROTO_IGMP:
				setText(1, "IGMP");
				break;
			default:
				setText(1, QString("UNSUPPORTED: %1").arg(ign.protocol));
				break;
		}
	}

	if(ign.pts)	
	{
		setText(3, QString("%1").arg(ntohs(ign.sport)));
	}
	else
		setText(3, "-");
	
	if(ign.ptd)	
	{
		setText(5, QString("%1").arg(ntohs(ign.dport)));
	}
	else
		setText(5, "-");
	
	if(ign.interface)
		setText(6, ign.iface);
	else
		setText(6, "-");

	setText(8, "NO"); /* notify */
	setObjectName(QString("Popup tree item for rule named \"%1\"").arg(text(7)));

	if(resolve_enabled)
	{
		/* setup the tooltips with the resolved names */
		resolve();
	}
}

void IQFPendingTreeItem::setPolicy(int p)
{
	_policy = p;
}

void IQFPendingTreeItem::applyPolicyColour(int policy)
{
	QBrush brush;
	switch(policy)
	{
		case ACCEPT:
			brush.setColor(KDARKGREEN);
			break;
		case DENIAL:
			brush.setColor(KDARKRED);
			break;
		case IGNORE_PACKET:
			brush.setColor(KDARKGRAY);
			break;
		case  IGNORE_PACKET_FOREVER:
		default:
			brush.setColor(Qt::white);
			break;
	}
	colourItem(brush);
}

void IQFPendingTreeItem::resolve()
{
	unsigned int sip = 0, dip = 0;
	unsigned short sport = 0, dport = 0;
	bool ok;
	unsigned short test;
	
	if(text(2).startsWith("!"))
	  text(2).remove("!");
	if(text(3).startsWith("!"))
	  text(3).remove("!");
	if(text(4).startsWith("!"))
	  text(4).remove("!");
	if(text(5).startsWith("!"))
	  text(5).remove("!");
	
	if(!text(2).contains('-') && !text(2).contains('/'))
	{
		struct in_addr add;
		if(inet_pton(AF_INET, text(2).toStdString().c_str(), &add) > 0)
			sip = add.s_addr;
	}
	if(!text(4).contains('-') && !text(4).contains('/'))
	{
		struct in_addr add;
		if(inet_pton(AF_INET, text(4).toStdString().c_str(), &add) > 0)
			dip = add.s_addr;
	}
	
	if(text(3).toUShort(&ok) != 0 && ok)
		sport = htons(text(3).toUShort());
	else
		sport = socketPairFromInfo(info())[2];
	
	test = text(5).toUShort(&ok);
	if(!text(5).contains('-') && ok)
		dport = htons(test);
	
	setToolTip(2, text(2));
	setToolTip(3, text(3));
	setToolTip(4, text(4));
	setToolTip(5, text(5));

	quadKey = QString("%1%2%3%4").arg(sip).arg(dip).arg(sport).arg( dport);
	connect(IQFResolverProxy::resolver(), SIGNAL(resolved(const QString&, const QStringList&)), this, 
		SLOT(resolved(const QString&, const QStringList&)));
	IQFResolverProxy::resolver()->resolve(sip, dip, sport, dport);
}

void IQFPendingTreeItem::resolved(const QString& key, const QStringList& res)
{
      struct in_addr testAddr;
      bool ok;
	if(key == quadKey)
	{
		QStringList tooltips = res;
		if(tooltips.size() == 4)
		{
			/* set resolved tooltip only if there's a valid IP string in the column.
			 * This avoids "0.0.0.0" when commas or hyphen are present
			 */
			if(inet_pton(AF_INET, text(2).toStdString().c_str(), &testAddr) > 0)
			  setToolTip(2, tooltips[0]);
			if((text(3).toUShort(&ok) && ok) || text(3) == "-")
			  setToolTip(3, tooltips[2]);
			if(inet_pton(AF_INET, text(4).toStdString().c_str(), &testAddr) > 0)
			  setToolTip(4, tooltips[1]);
			if((text(5).toUShort(&ok) && ok) || text(3) == "-")
			  setToolTip(5, tooltips[3]);
			emit itemResolved();
		}
	}
}


QList<unsigned int> IQFPendingTreeItem::socketPairFromInfo(const ipfire_info_t& info)
{
	QList <unsigned int> ret;
	ret << info.iphead.saddr;
	ret << info.iphead.daddr;
	if(info.protocol == IPPROTO_TCP)
	{
		ret << (unsigned int) info.transport_header.tcphead.source;
		ret << (unsigned int) info.transport_header.tcphead.dest;
	}
	else if(info.protocol == IPPROTO_UDP)
	{
		ret << (unsigned int) info.transport_header.udphead.source;
		ret << (unsigned int) info.transport_header.udphead.dest;
	}
	else
		ret << (unsigned int) 0 << (unsigned int) 0;
	
	return ret;
}

QStringList IQFPendingTreeItem::infoToItemStringList(const ipfire_info_t *info)
{
	QStringList ret;
	struct in_addr soaddr, deaddr;
	
	QString sport, dport, saddr, daddr;
	QString name;
	int i;

	for(i = 0; i < 9; i++)
		ret << "-";

	soaddr.s_addr = info->iphead.saddr;
	deaddr.s_addr = info->iphead.daddr;
	saddr = QString(inet_ntoa(soaddr));
	daddr = QString(inet_ntoa(deaddr));

	ret[2] = saddr;
	ret[4] = daddr;
	
	if(info->protocol == IPPROTO_TCP)
	{
		ret[1] = "TCP";
		/* Port */
		sport = QString("%1").arg(ntohs(info->transport_header.tcphead.source));
		d_hiddenSourcePort = info->transport_header.tcphead.source;
		dport = QString("%1").arg(ntohs(info->transport_header.tcphead.dest));
		ret[3] = sport;
		ret[5] = dport;
	}
	else if(info->protocol == IPPROTO_UDP)
	{
		ret[1] =  "UDP";
		sport = QString("%1").arg(ntohs(info->transport_header.udphead.source));
		d_hiddenSourcePort = info->transport_header.udphead.source;
		dport = QString("%1").arg(ntohs(info->transport_header.udphead.dest));
		ret[3] = sport;
		ret[5] = dport;
	}
	else if(info->protocol == IPPROTO_ICMP)
	{
		ret[1] = "ICMP";
		ret[3] = "-";
		ret[5] = "-";
	}
	else if(info->protocol == IPPROTO_IGMP)
	{
		ret[1] = "IGMP";
		ret[3] = "-";
		ret[5] = "-";
	}
	else 
	{
		ret[1] = QString("%1 (UNSUPPORTED)").arg(info->protocol);
		ret[3] = "-";
		ret[5] = "-";
	}
	
	
	switch(info->direction)
	{
		case IPFI_INPUT:
			ret[0] = "IN";
			ret[6] = QString(info->devpar.in_devname);
			name = QString("In from %1").arg(saddr);
			break;
		case IPFI_OUTPUT:
			ret[0] = "OUT";
			ret[6] = QString(info->devpar.out_devname);
			name = QString("Out to %1:%2").arg(daddr).arg(dport);
			break;
		default:
			break;
	}
	if(name.length() >= RULENAMELEN - 1)
	{
		name.truncate(RULENAMELEN -1);
		name[RULENAMELEN - 2] = '.';
		name[RULENAMELEN - 3] = '.';
	}
	ret[7] = name;
	/* notify set to no by default */
	ret[8] = "NO";
	
	return ret;
}

QStringList IQFPendingTreeItem::toStringList()
{
	QStringList ret;
	QString sourceP;
	if(text(3) == "-")
		sourceP = QString().number(ntohs(d_hiddenSourcePort));
	else
		sourceP = text(3);
	ret << text(0) << text(1) << text(2) << sourceP << text(4) << text(5) 
		<< text(6) << text(7) << text(8);
	return ret;
}

ipfire_rule IQFPendingTreeItem::itemToRule()
{
	ipfire_rule r;
	memset(&r, 0, sizeof(r));
	RuleBuilder rb;
	rb.init();
	
	if(policy() == DENIAL || policy() == ACCEPT)
	{
		rb.setPolicy(policy());
		rb.setDirection(text(0));
		rb.setProtocol(text(1));
		rb.setSip(text(2));
		rb.setSport(text(3));
		rb.setDip(text(4));
		rb.setDport(text(5));
		if(text(0).contains("IN"))
			rb.setInDevname(text(6));
		else if(text(0).contains("OUT"))
			rb.setOutDevname(text(6));
			
		rb.setOwner(getuid());
		rb.setState("YES");
		rb.setName(text(7));
		rb.setNotify(text(8));
// 		qDebug() << "aggiungo regola " << text(7);
		if(rb.ruleValid())
		{
			memcpy(&r, rb.Rule(), sizeof(ipfire_rule));
			setRuleValid();
			for(int i = 0; i < columnCount(); i++)
				setBackground(i, myBrush());
			
		}
		else
		{
			for(int i = 0; i < columnCount(); i++)
				setBackground(i, QBrush(KRED));
			IQFUtils::utils()->htmlDialog(rb.failuresHtmlRepresentation());
			emit ruleBuildingFailed();
			setRuleInvalid();
			memset(&r, 0, sizeof(r));
		}
	}
	return r;

}

bool IQFPendingTreeItem::checkColumnChanged(int col)
{
	IQFUtils* ut = IQFUtils::utils();

	bool valid = true;
	
	switch(col)
	{
		case 0:
			valid = ut->checkDir(text(col));
			if(!valid)
				_invalidReason = "invalid direction";
			break;
		case 1:
			valid = ut->checkProto(text(col));
			if(!valid)
				_invalidReason = "Invalid protocol";
			break;
		case 2:
		case 4:
			if(policy() == IGNORE_PACKET_FOREVER)
			{
				valid = ut->checkIP(text(col));
				if(!valid)
					_invalidReason = "Invalid IP address. "
					"Remember that for <strong>ignored</strong> packets"
							" you can specify just one IP address"
					" or <strong>\"-\"</strong>, meaning <em>\"any\"</em>"
					" <em>Intervals</em> or <em>\"not\"</em>"
					" specifier (\"!\") are not allowed. "
					"Instead, if you select a firewall <strong>policy "
					"</strong> below (\"accept\" or "
					"\"drop\"), you are allowed to set an ip interval or to use the "
					"\"!\" specifier";
			}
			else if(policy() == IPFI_ACCEPT || policy() == IPFI_DROP)
			{
				valid = ut->checkGenericIP(text(col));
				if(!valid)
					_invalidReason = "Invalid IP address. ";
			}
			break;
		case 3:
		case 5:
			if(policy() == IGNORE_PACKET_FOREVER)
			{
				valid = ut->checkPort(text(col));
				if(!valid)
					_invalidReason = "Invalid port number. "
					"Remember that for <strong>ignored</strong> packets"
					" you can specify just one port"
					" or <strong>\"-\"</strong>, meaning <em>\"any\"</em> port number."
					" <em>Intervals</em> or <em>\"not\"</em>"
					" specifier (\"!\") are not allowed. "
					"Instead, if you select a firewall <strong>policy "
					"</strong> below (\"accept\" or "
					"\"drop\"), you are allowed to set a port interval or to use the "
					"\"!\" specifier";
			}
			else if(policy() == IPFI_ACCEPT || policy() == IPFI_DROP)
			{
				valid = ut->checkPortOrInterval(text(col));
				if(!valid)
					_invalidReason = "Invalid port number or interval. "
					"Remember that valid port numbers are those from 1 to 65535.";
			}
			break;
		case 6:
			valid = ut->checkDev(text(col));
	}
	if(!valid)
	{
		setBackground(col, QBrush(KRED));
		setSelected(false);
	}
	else
	{
		setBackground(col, myBrush());
	}
	
	setItemValid(valid);
	return valid;
}


IQFPendingTreeItem::~IQFPendingTreeItem()
{
	if(resolve_enabled)
		disconnect(IQFResolverProxy::resolver());
}
	







