#include <iqfpopup_notifier.h>

#include "iqfwidgets.h"
#include "rule_builder.h"
#include "iqfpolicy.h"
#include "iqfire.h" /* for ICON_PATH macro */

#include "iqf_pending_tree_item.h"
#include "iqf_message_proxy.h"
#include "ignored_packet.h"
#include "ignored_packets_set.h"
#include "iqf_utils.h"

#include <QGridLayout>
#include <QFrame>
#include <QHBoxLayout>
#include <QButtonGroup>
#include <QLabel>
#include <QHeaderView>
#include <QStringList>
#include <QMessageBox>
#include <QCloseEvent>
#include <arpa/inet.h>


IQFPopup::IQFPopup(QWidget *p) : QWidget(p)
{
	QSettings s;
	popup_enabled = s.value("POPUP_ENABLE", true).toBool();
	popup_on_match = s.value("POPUP_ON_MATCH", true).toBool();
	buffer_size = s.value("POPUP_BUFFER_SIZE", 10).toInt();
	info_count = 0;
	setWindowFlags(Qt::Tool|Qt::WindowStaysOnTopHint);
	setAttribute(Qt::WA_QuitOnClose, false);
	radios = new QWidget(this);
	QFont buttonFont("", 9);
	int fontSize = s.value("POPUP_NOTIFIER_FONT_SIZE", 8).toInt();
	QFont popupFont("", fontSize);
	setFont(popupFont);
	label = new QLabel("The following connections were detected:", this);
	bAccept = new IQFPushButton(this);
	bAccept->setText("Ignore All");
	bAccept->setObjectName("pbNotifApply");
	bAccept->setFont(buttonFont);
	bAccept->setFlat(true);
	bAccept->setSizePolicy(QSizePolicy(QSizePolicy::Preferred, QSizePolicy::Fixed));
	
	
	radioAcc = new IQFRadioButton(radios);
	radioDen = new IQFRadioButton(radios);
	radioIgn = new IQFRadioButton(radios);
	radioIgnForever = new IQFRadioButton(radios);
	radioAcc->setText("Allow");
	radioAcc->setObjectName("rbNotifApply");
	radioDen->setText("Block");
	radioDen->setObjectName("rbNotifBlock");
	radioIgn->setText("Ask again");
	radioIgn->setObjectName("rbNotifAskAgain");
	radioIgnForever->setText("Ignore");
	radioIgnForever->setObjectName("rbNotifIgnore");
	radioIgnForever->setToolTip("Ignore the packet and remember decision");
	radioAcc->setFont(buttonFont);
	radioDen->setFont(buttonFont);
	radioIgn->setFont(buttonFont);
	radioIgnForever->setFont(buttonFont);
	radioIgn->setChecked(true);
	
	IQFCheckBox* cb = new IQFCheckBox(radios);
	cb->setText("All");
	cb->setToolTip("Select all the items");
	cb->setObjectName("cbNotifSelectAll");
	
	
	QHBoxLayout* hlayout = new QHBoxLayout(radios);
	QGridLayout *glayout = new QGridLayout(this);
	
	setWindowIcon(QIcon(ICON_PATH + "pending_rules.png"));
	
	tree = new IQFPendingTree(this);
	tree->setObjectName("Popup notifier tree");
	
	/* Layout the three radio buttons */
	hlayout->setMargin(2);
	hlayout->setSpacing(4);
	hlayout->addWidget(cb);
	hlayout->addWidget(radioIgn);
	hlayout->addWidget(radioAcc);
	hlayout->addWidget(radioDen);
	hlayout->addWidget(radioIgnForever);
	
	/* when no item is selected, these r disabled */
	radioAcc->setDisabled(true);
	radioDen->setDisabled(true);
	radioIgn->setDisabled(true);
	radioIgnForever->setDisabled(true);
	
	glayout->setMargin(2);
	glayout->setSpacing(2);
	glayout->addWidget(label, 0, 0, 1, 10);
	glayout->addWidget(tree, 1, 0, 7, 10);
	glayout->addWidget(bAccept, 8, 9, 1, 1);
	glayout->addWidget(radios, 8, 0, 1, 7);
	
	
	resolve_enabled = s.value("NOTIFIER_RESOLVE_ENABLE", true).toBool();
	
	notify_listening_only = s.value("POPUP_NOTIFY_LISTEN_ONLY", true).toBool();
	
	if(notify_listening_only)
		setWindowTitle("New packet(s) without a rule (active services option)");
	else
		setWindowTitle("New packet(s) without a rule");
	
	connect(radioAcc, SIGNAL(clicked()), this, SLOT(aRadioClicked()));
	connect(radioDen, SIGNAL(clicked()), this, SLOT(aRadioClicked()));
	connect(radioIgn, SIGNAL(clicked()), this, SLOT(aRadioClicked()));
	connect(radioIgnForever, SIGNAL(clicked()), this, SLOT(aRadioClicked()));
	connect(bAccept, SIGNAL(clicked()), this, SLOT(ok()));
	connect(cb, SIGNAL(toggled(bool)), this, SLOT(selectAll(bool)));
	
	connect(tree, SIGNAL(itemActivated(QTreeWidgetItem*, int)),this, SLOT(itemSelected(
		QTreeWidgetItem *, int)));
	
}

IQFPopup::~IQFPopup()
{
	
}

void IQFPopup::enterEvent(QEvent *e)
{
	IQFHelpBrowser::helpBrowser()->setHtml(IQFMessageProxy::msgproxy()->getHelp(
		"unknownPacketsPopup"));
	QWidget::enterEvent(e);
}

void IQFPopup::showEvent(QShowEvent *e)
{
	radioAcc->setDisabled(true);
	radioDen->setDisabled(true);
	radioIgn->setDisabled(true);
	radioIgnForever->setDisabled(true);
	radioIgn->setChecked(true);
	bAccept->setText("Ignore All");
	label->setText("The following connections were detected:");
	QWidget::showEvent(e);
	/* Connections inside the popup widget */
	connect(tree, SIGNAL(itemClicked(QTreeWidgetItem *, int)), this, 
		SLOT(itemSelected(QTreeWidgetItem *, int)));
	
}

void IQFPopup::setUserResizableHeaders()
{
	QHeaderView *hview = tree->header();
	hview->setResizeMode(QHeaderView::Interactive);
}

/* NOTE: info is going to be deleted after this call 
 * addInfo is called by 
 * void IQFSysTray::notify(ipfire_info_t *info)
 * which then deletes it!
 */
void IQFPopup::addInfo(ipfire_info_t *info)
{
	if(!tree->itemAlreadyPresent(info))
	{
		IQFPendingTreeItem *item = tree->addItem(info, resolve_enabled); 
		info_count++;
		connect(item, SIGNAL(itemResolved()), tree, SLOT(anItemWasResolved()));
		Q_UNUSED(item);
		if(!notify_listening_only)
			setWindowTitle(QString("%1 new packet(s) without a rule").arg(info_count));
		else
			setWindowTitle(QString("%1 new packet without a rule (active services option)").
				arg(info_count));
		tree->scrollToItem(item);
	}
	
	if(itemCount() == maxItemCount())
	{
		label->setText(QString("The following connections were detected: (%1 entries listed, maximum reached)").
			arg(buffer_size));
		label->setToolTip(QString("There is an upper limit on the maximum number\n"
			"of items that can be displayed in this window.\n"
			"It is set to %1. You can change the value in the settings.\n").arg(maxItemCount()));
			
		setWindowTitle(windowTitle() + " (limit reached) ");
	}
}

void IQFPopup::disablePopups()
{
	setPopupEnabled(false);
}

void IQFPopup::setPopupEnabled(bool en)
{
	QSettings s;
	s.setValue("POPUP_ENABLE", en);
	popup_enabled = en;
	emit popupsDisabled();
}

void IQFPopup::itemSelected(QTreeWidgetItem *it, int col)
{
	Q_UNUSED(col);
	IQFPendingTreeItem * pit = dynamic_cast<IQFPendingTreeItem *>(it);
	if(pit == NULL)
	{
		qDebug() << "! error: cannot convert QTreeWidgetItem into IQFPendingTreeItem "
				" in IQFPopup::itemSelected()";
		return;
	}
	/* then enable the widgets for the user interaction */
	if(!radioAcc->isEnabled())
	{
		radioAcc->setEnabled(true);
		radioDen->setEnabled(true);
		radioIgn->setEnabled(true);
		radioIgnForever->setEnabled(true);
		radioIgnForever->setChecked(true);
		bAccept->setText("Apply");
	}
	switch(pit->policy())
	{
		
		case IGNORE_PACKET:
			radioIgn->setChecked(true);
			break;
		case ACCEPT:
			radioAcc->setChecked(true);
			break;
		case DENIAL:
			radioDen->setChecked(true);
			break;
		case IGNORE_PACKET_FOREVER:
		default:
			radioIgnForever->setChecked(true);
			break;	
	}
	
}

void IQFPopup::aRadioClicked()
{
	int i;
	QList<QTreeWidgetItem *> selected_items = tree->selectedItems();
	if(selected_items.size() == 0)
	{
		QMessageBox::information(this, "Warning", "You must select at least one element");
	}
	else
	{
		bAccept->setText("Apply");
		for(i = 0; i < selected_items.size(); i++)
		{
			IQFPendingTreeItem *pip = dynamic_cast<IQFPendingTreeItem *>( selected_items[i]);
			if(pip != NULL)
			{
				if(radioAcc->isChecked())
					pip->setPolicy(ACCEPT);
				else if(radioDen->isChecked())
					pip->setPolicy(DENIAL);
				else if(radioIgn->isChecked())
					pip->setPolicy(IGNORE_PACKET);
				else 
					pip->setPolicy(IGNORE_PACKET_FOREVER);
				
				pip->applyPolicyColour(pip->policy());
				pip->setModified(true);
				/* now that the policy has changed, we look for errors.
			 	* This is necessary because for instance for the IPs and ports,
			 	* intervals are allowed for accept and denial, but not for
			 	* ignore_forever.
			 	*/
				pip->reviseForErrors();
			}
			else
				Log::log()->appendFailed("failed to dynamic cast to IQFPendingTreeItem!\n[IQFPopup::aRadioClicked()]");
		}
	}
}

void IQFPopup::setPopupBuffer(int size)
{
	QSettings s;
	buffer_size = size;
	s.setValue("POPUP_BUFFER_SIZE", size);
}

void IQFPopup::closeEvent( QCloseEvent * event )
{
	/* Throw away all information */
	tree->deleteAllItems();
	info_count = 0;
	event->accept();
}

void IQFPopup::ok()
{
	info_count = tree->parseTreeForRules();
	if(info_count == 0)
		hide();
}

void IQFPopup::setNotifyListeningOnly(bool en)
{
	notify_listening_only = en; 
}


bool IQFPopup::toBeIgnored(const ipfire_info_t *info)
{
	int i;
	unsigned short destPort;
	bool listen = false;
	QSettings s;
	
	QList<IgnoredPacket> ign_packets = IgnoredPacketsSet:: instance()->list();
	for(i = 0; i < ign_packets.size(); i++)
	{
		last_ignored_packet = ign_packets[i];
		if(info->protocol == ign_packets[i].protocol &&
			info->direction == ign_packets[i].direction)
		{
			if(ign_packets[i].ips) /* source IP */
				if(info->iphead.saddr != ign_packets[i].sip)
					continue; /* Source ip comparison required but different ips */
			/* else: we do not care about source IP: go on */
			
			if(ign_packets[i].ipd) /* Destination IP */
				if(info->iphead.daddr != ign_packets[i].dip)
					continue;
			
			if(info->protocol == IPPROTO_ICMP || info->protocol == IPPROTO_IGMP)
			{
					return true;
			}
			else if(info->protocol == IPPROTO_TCP)
			{
				if(ign_packets[i].pts)
					if(info->transport_header.tcphead.source != ign_packets[i].sport)
						continue;
				
				if(ign_packets[i].ptd)
					if(info->transport_header.tcphead.dest != ign_packets[i].dport)
						continue;
				return true;
				
			}
			else if(info->protocol == IPPROTO_UDP)
			{
				if(ign_packets[i].pts)
					if(info->transport_header.udphead.source != ign_packets[i].sport)
						continue;
				
				if(ign_packets[i].ptd)
					if(info->transport_header.udphead.dest != ign_packets[i].dport)
						continue;
				return true;
				
			}
			else /* unsupported protocol: ignore and do not popup! */
			{
				qDebug() << "(I) iqFirewall:: unsupported protocol " << info->protocol;
				qDebug() << "(I)              ignoring packet (will not popup).";
				return true; /* ignore */
			}
				
		}
	}
	/* the item is not in the list of the packets to be ignored.
	 * For INCOMING packets, the user might want to be notified only
	 * when the destination port of the incoming packet is directed to
	 * a service which IS ACTIVE AND LISTENING in our machine.
	 */
	if(notify_listening_only && info->direction == IPFI_INPUT
		 && (info->protocol == IPPROTO_TCP || info->protocol == IPPROTO_UDP))
	{
		/* - "POPUP_NOTIFY_LISTEN_ONLY" must be true 
		 * - packet must be INCOMING (remember that Forward is not notified
		 * - protocols TCP and UDP have sockets in a state which could be listen
		 */
		if(info->protocol == IPPROTO_TCP)
		{
			destPort = ntohs(info->transport_header.tcphead.dest);
			/* if in listen state, the packet is to be ignored (return true) */
			listen =  IQFUtils::utils()->tcpPortListen(destPort);
// 			if(listen)
// 				qDebug() << "The port " << destPort << " is in a state of TCP listen: do popup";
// 			else
// 				qDebug() << "The port " << destPort << " is NOT in a state of TCP listen: do not popup";
		}
		if(info->protocol == IPPROTO_UDP)
		{
			destPort = ntohs(info->transport_header.udphead.dest);
			/* if in listen state, the packet is to be ignored (return true) */
			listen = IQFUtils::utils()->udpPortListen(destPort);
// 			if(listen)
// 				qDebug() << "The port " << destPort << " is in a state of UDP listen: do  popup";
// 			else
// 				qDebug() << "The port " << destPort << " is NOT in a state of UDP listen: do not popup";
		}
		return !listen;
	}
	return false;
}

void IQFPopup::selectAll(bool en)
{
	if(! en)
	{
		QList<QTreeWidgetItem *> items = tree->selectedItems();
		for(int i = 0; i < items.size(); i++)
			items[i]->setSelected(false);
	}
	else /* get all items */
	{
		QList<QTreeWidgetItem *> items = tree->findItems("*", Qt::MatchWildcard);
		for(int i = 0; i < items.size(); i++)
			if(!items[i]->isSelected())
				items[i]->setSelected(true);
		radioAcc->setEnabled(true);
		radioDen->setEnabled(true);
		radioIgn->setEnabled(true);
		radioIgnForever->setEnabled(true);
	}
}




