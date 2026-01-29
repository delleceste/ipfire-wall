#include "iqf_pending_tree.h"
#include <iqfpopup_notifier.h>
#include "iqfwidgets.h"
#include "rule_builder.h"
#include "iqf_utils.h"
#include "iqfpolicy.h"
#include "iqfruletree.h" /* for the static method itemSelected() */
#include "ignored_packets_set.h"
#include "colors.h"
#include "iqflog.h"
#include "iqf_item_delegate.h"

#include <QHBoxLayout>
#include <QButtonGroup>
#include <QLabel>
#include <QHeaderView>
#include <QStringList>
#include <QSettings>
#include <QMessageBox>
#include <QMouseEvent>
#include <QDir>
#include <QFile>
#include <QMenu>
#include <arpa/inet.h> /* for inet_ntoa */
#include <netdb.h>
#include <unistd.h>
#include <sys/socket.h>       /* for AF_INET (in gethostbyaddr() ) */


IQFPendingTree::IQFPendingTree(QWidget *parent) : IQFTreeWidget(parent)
{
	QSettings s;
	setHeaderLabels(QStringList() << "DIR. " << "PROTO" << "SOURCE IP ADDR" <<
			"S.PORT" << "DESTIN. IP ADDR" << "D.PORT" << "DEV." << "RULE NAME" << "NOTIFY");
	setRootIsDecorated(false);
	QHeaderView *hview = header();
	hview->setResizeMode(QHeaderView::ResizeToContents);
	setSelectionMode(QAbstractItemView::ExtendedSelection);
	setMouseTracking(true);
	/* connections for item clicked, double clicked, entered and
	* currentItemChanged already setup by the base class
	*/
	IQFLineEditIPItemDelegate* id = new IQFLineEditIPItemDelegate(this);
	setItemDelegateForColumn(2, id);
	setItemDelegateForColumn(4, id);
	IQFComboBoxProtoItemDelegate *cbid = new IQFComboBoxProtoItemDelegate(this);
	setItemDelegateForColumn(1, cbid);
	IQFLineEditPortItemDelegate* pid = new IQFLineEditPortItemDelegate(this);
	setItemDelegateForColumn(3, pid);
	setItemDelegateForColumn(5, pid);
	IQFComboBoxYesNoItemDelegate *ynd = new IQFComboBoxYesNoItemDelegate(this);
	setItemDelegateForColumn(8, ynd);
	IQFLineEditGenericStringItemDelegate *gsid = new IQFLineEditGenericStringItemDelegate(this);
	setItemDelegateForColumn(7, gsid);
	/* connect() signals and slots (iqf_tree_widget.h ) */
	enableConnections();
}
		
IQFPendingTreeItem* IQFPendingTree::addItem(ipfire_info_t *info, bool resolve)
{
	IQFPendingTreeItem* newItem = new IQFPendingTreeItem(this, info, resolve);
	return newItem;
}
		
IQFPendingTreeItem* IQFPendingTree::addItem(IgnoredPacket& ign, bool resolve)
{
	IQFPendingTreeItem* newItem = new IQFPendingTreeItem(this, ign, resolve);
	return newItem;
}
		
IQFPendingTree::~IQFPendingTree()
{
	QList<QTreeWidgetItem *> items = findItems("*", Qt::MatchWildcard);
	
}

void IQFPendingTree::deleteAllItems()
{
	IQFPendingTreeItem *pip;
	QList<QTreeWidgetItem *> items = findItems("*", Qt::MatchWildcard);
	for(int i = 0; i < items.size(); i++)
	{
		pip = dynamic_cast<IQFPendingTreeItem *> (items[i]);
		if(pip != NULL)
			deleteItem(pip);
		else
			Log::log()->appendFailed( "! IQFPendingTree::deleteAllTree(): )"
			"unable to dynamic cast tree items.");
	}
}

/* returns the remained items, i.e. the wrong ones */
int IQFPendingTree::parseTreeForRules()
{
	int remain;
	ipfire_rule newrule;
	ipfire_rule zeroRule;
	memset(&zeroRule, 0, sizeof(zeroRule));
	QList<QTreeWidgetItem *> items = findItems("*", Qt::MatchWildcard);
	IQFPendingTreeItem *pip;
	
	for(int i = 0; i < items.size(); i++)
	{
		pip = dynamic_cast<IQFPendingTreeItem *> (items[i]);
		if(pip != NULL)
		{
			pip->reviseForErrors();
			if(pip->columnsWithErrors().size() > 0)
			{
				QMessageBox::information(this, QString("Syntax error in element %1").
					arg(i + 1), QString("The item \"%1\" has %2 columns with errors!\n"
					"Correct them and then click on \"Apply\" again.").arg(
					pip->text(7)).arg(pip->columnsWithErrors().size()));
				/* do not return a value different form the number of items really present.
				 * Otherwise, the behaviour of the tree might be affected (e.g. more than 
				 * maximum allowed packets could arrive */
				return items.size();
			}
		}
	}
	
	remain = items.size();
	for(int i = 0; i < items.size(); i++)
	{
		pip = dynamic_cast<IQFPendingTreeItem *> (items[i]);
	
		if(pip != NULL && (pip->policy() == DENIAL || pip->policy() == ACCEPT))
		{
			newrule = pip->itemToRule();
			Policy *iqpolicy = Policy::instance();
			iqpolicy->appendRule(newrule);
			iqpolicy->notifyRulesChanged();
		}
		else if(pip != NULL && pip->policy() == IGNORE_PACKET_FOREVER)
		{
			IgnoredPacket ignp(pip);
			if(ignp.isValid() && !alreadyPresent(ignp) )
			{
				IgnoredPacketsSet *ign_set = IgnoredPacketsSet::instance();
				ign_set->add(ignp);
			
			}
// 			else
// 				qDebug() << "IGNOREREI regola, ma e` sbagliata o gia` presente! " << pip->text(7);
		}
		/* call IQFTreeWidget deleteItem() to safely delete an item */
		if(pip != NULL)
			deleteItem(pip);	
		remain--;	
		
	}
	return remain;
}

bool IQFPendingTree::alreadyPresent( IgnoredPacket &other)
{
	int i;
	IgnoredPacketsSet *ign_set = IgnoredPacketsSet::instance();
// 	qDebug() << "lista ignorati: " << ign_set->list().size();
	for(i =0; i < ign_set->list().size(); i++)
	{
// 		qDebug() << "***** COMPARO " << ign_set->list()[i].toReadableString()
// 				<< "con " << other.toReadableString();
		if(ign_set->list()[i] == other)
		{
			
			
			return true;
		}
	}
	return false;
}

extern "C"
{
	int check_stats(struct netlink_stats* ns, const ipfire_info_t* msg);
	int print_packet(const ipfire_info_t *pack, 
			 const struct ipfire_servent* ipfi_svent,
    const ipfire_rule_filter *filter);
	int print_lostpack_info(const struct  netlink_stats* nls);
}

bool IQFPendingTree::itemAlreadyPresent(const ipfire_info_t* info)
{
	int i;
	QList<QTreeWidgetItem *> treeitemlist = findItems("*", Qt::MatchWildcard);
// 	qDebug() << "size del tree:" << treeitemlist.size();
	//print_packet(info, NULL, NULL);
	for(i = 0; i < treeitemlist.size(); i++)
	{
		if(((IQFPendingTreeItem *)treeitemlist[i])->infoToItemStringList(info) 
				   == ((IQFPendingTreeItem *)treeitemlist[i])->toStringList())
		{
// 			qDebug() << "item gia presente:" <<((IQFPendingTreeItem *)treeitemlist[i])->toStringList()
// 				<<  ((IQFPendingTreeItem *)treeitemlist[i])->infoToItemStringList(info);
			return true;
		}
	}
// 	qDebug() << "item non presente";
	return false;
}

void IQFPendingTree::mouseReleaseEvent(QMouseEvent *e)
{
	if(e->button() == Qt::RightButton)
	{
		QMenu *menu = new QMenu(this);
		QString message;
		switch(last_column_over)
		{
			case 1:
				message = "Any protocol";
				break;
			case 2:
				message = "Any source IP";
				break;
			case 3:
				message = "Any source port";
				break;
			case 4:
				message = "Any destination IP";
				break;
			case 5:
				message = "Any destination port";
				break;	
			case 6:
				message = "Any network device";
				break;
				
		}
		if(last_column_over > 0 && last_column_over < 7)
		{
			menu->addAction(message, this, SLOT(setAny()));
			menu->exec(QCursor::pos());
		}
		
	}
	QTreeWidget::mouseReleaseEvent(e);
}

void IQFPendingTree::setAny()
{
	int i;
	QList<QTreeWidgetItem *> items = selectedItems();
	
	for(i = 0; i < items.size(); i++)
		items[i]->setText(last_column_over, "any");
}

void IQFPendingTree::itemColumnChanged(QTreeWidgetItem *it, int col)
{
	IQFPendingTreeItem *pit = dynamic_cast<IQFPendingTreeItem *>(it);
	if(pit != NULL)
	{
		if(pit->resolveEnabled())
		{
			if(pit->text(col) != "-")
				pit->resolve();
			else
				pit->setToolTip(col, "any");
		}
		/* check for errors in the item modified */
		pit->checkColumnChanged(col);
		if(!IQFRuleTree::itemSelected() && isActiveWindow())
			buildItemInfoAndEmit(pit, col);
	}
	else
		Log::log()->appendFailed("\e[1;31m! error IQFPendingTree::itemColumnChanged():\n"
				"could not convert a QTreeWidgetItem to a"
				"IQFPendingTreeItem by means of a dynamic_cast.\n"
				"Contact the author\n");
}

void IQFPendingTree::treeItemClicked(QTreeWidgetItem *it, int col)
{
	/* disable info and help updates on the tree globally
	* when an item is selected
	*/
	setMouseTracking(false);
	buildItemInfoAndEmit(it, col);	
}

void IQFPendingTree::treeItemPressed(QTreeWidgetItem *it , int col)
{
	Q_UNUSED(it);
	last_column_over = col; /* for the context menu on right click */
}

/* Reimplementation of the base method in IQFTreeWidget */
void IQFPendingTree::treeItemEntered(QTreeWidgetItem *it , int col)
{
	buildItemInfoAndEmit(it, col);
}

void IQFPendingTree::anItemWasResolved()
{
	IQFPendingTreeItem *pit = qobject_cast<IQFPendingTreeItem *>( sender());
	if(pit != NULL)
	{
		if(pit->isSelected())
			buildItemInfoAndEmit(pit, 0);
	}
}

void IQFPendingTree::showEvent(QShowEvent *e)
{
	setMouseTracking(true);
	QList<QTreeWidgetItem *> items = findItems("*", Qt::MatchWildcard);
	for(int i = 0; i < items.size(); i++)
		if(items[i]->isSelected())
			items[i]->setSelected(false);
	QWidget::showEvent(e);
}

void IQFPendingTree::buildItemInfoAndEmit(QTreeWidgetItem *it, int col)
{
	Q_UNUSED(col);
	bool itemValid = true;
	QString s, h;
	
	/* if the user has selected an item and some caller wants to
	 * build and emit info about an item which is not selected, we
	 * prevent this behaviour.
	 * This avoids that when a user selects an item to read its info
	 * the info is not overwritten..
	 */
	QList<QTreeWidgetItem*> items = selectedItems();
	if(items.size() > 0) /* one or more items selected */
	{
		int i;
		for(i = 0; i < items.size(); i++)
			if(items[i] == it)
				break;
		if(i == items.size()) /* the item is not among those selected */
		{
// 			qDebug() << "EVITO DI AGGIORNARE INFO PER NUOVO PACCHETTO";
			return;
		}
	}
	
	
	IQFPendingTreeItem *ptitem = dynamic_cast<IQFPendingTreeItem*> (it);
	if(ptitem)
		itemValid = ptitem->itemValid();
	else
		qDebug() << "! IQFPendingTree::buildItemInfoAndEmit(): cannot convert "
				"QTreeWidgetItem * into IQFPendingTreeItem *";
	
	h = "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n"
			"<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.1//EN\""
			"\"http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd\">\n";
		
	h += "<html xmlns=\"http://www.w3.org/1999/xhtml\">";
		
	h += "<style type=\"text/css\">";
	
	h += "html, p, li, a, .error, .resolved { font-family:\"Tahoma sans-serif sans\"; }";
	h += "p { font-size:9pt; margin:2px; padding:2px; }";
	h += "li { font-size:8pt; margin:2px; padding:2px; }";
	h += ".list_title { font-size:8pt; margin:2px; padding:2px; font-weight:bold; }";
	h += ".errorBackground { background-color:rgb(255,150,150); }";
	h += ".error { text-decoration:line-through; color:rgb(255,150,150); }";
	h += "a { font-size:8pt; text-align:right; margin:3px; padding:2px; }";
	h += ".resolved { color:rgb(100, 100, 255); }";
	h += "</style>";
		
	s = "<body><p align=\"center\">";
		
	if(itemValid)
	{
		s += QString("<h4>New packet detected</h4>");
		s += "<p>";
	}
	else
	{
		s += "<h4 class=\"error\">Invalid fields in the item</h4>";
		s += "<p class=\"errorBackground\">";
	}

	s += "<ul>";
	s += QString("<li>Proposed name:<strong>\"%1\"</strong>;</li>").arg(it->text(7));
	s += QString("<li>direction:<strong>%1</strong>;</li>").arg(it->text(0));
	s += QString("<li>protocol:<strong>%1</strong>;</li>").arg(it->text(1));
		
	/* sip */
	s += "<li>";
	if(it->toolTip(2) != "-")
		s += QString("source IP:<strong class=\"resolved\">\"%1\"</strong><br/>(<em>%2</em>)")
				.arg(it->toolTip(2)).arg(it->text(2));
	else
		s += QString("source IP:<strong>%1</strong>").arg(it->text(2));	
	s += ";</li>";
		
		/* sport It requires some attention because usually it is not set in the 
		* notifier item */
		
	QString sport;
	int sourcePort;
	/* the source port is not included as information in the text(3) */
		/* But if the user clicks and modifies the source port field in the
	* popup item, then (else branch) we show it
		*/
	if(it->text(3).contains("-") || it->text(3).toUInt() == 0)
	{
		IQFPendingTreeItem* iqfit = dynamic_cast<IQFPendingTreeItem *>(it);
		if(iqfit != NULL && !iqfit->hasIgnoredPacket())
		{
			sourcePort = ntohs(iqfit->socketPairFromInfo(iqfit->info())[2]);
			sport = QString("%1").arg(sourcePort);
		}
		else
			sport = "-";
	}
	else 
		sport = it->text(3);
		
	s += "<li>";
	if(it->toolTip(3) != sport && sport != "-")
		s += QString("source port:<strong class=\"resolved\">\"%1\"</strong> (<em>%2</em>)")
				.arg(it->toolTip(3)).arg(sport);
	else
		s += QString("source port:<strong>\"%1\"</strong>").arg(it->text(3));	
	s += ";</li>";
		
	/* dip */
	s += "<li>";
	if(it->toolTip(4) != "-")
		s += QString("destination IP:<strong class=\"resolved\">"
				"\"%1\"</strong><br/>(<em>%2</em>)")
				.arg(it->toolTip(4)).arg(it->text(4));
	else
		s += QString("destination IP:<strong>%1</strong>").arg(it->text(4));	
	s += ";</li>";
		
	/* destination port */
	s += "<li>";
	if(it->toolTip(5) != it->text(5))
		s += QString("destination port:<strong class=\"resolved\">\"%1\"</strong> (<em>%2</em>)")
				.arg(it->toolTip(5)).arg(it->text(5));
	else
		s += QString("destination port:<strong>\"%1\"</strong>").arg(it->text(5));	
	s += ";</li>";
		
	s += QString("<li>network device:<strong>%1</strong>;</li>").arg(it->text(6));
		
	s += "</ul>";
	s += "</p>";
				
	if(!itemValid)
	{
		s += "<h4 class=\"error\">There is an error in your syntax:</h4>";
		s += "<p>";
		if(ptitem != NULL)
			s += ptitem->invalidReason();
		s += "</p>";
	}
		
	
	s += "</body>";
		
	h += s;
		
	h += "\n</html>";

	IQFInfoBrowser::infoBrowser()->setHtml(h);
}
