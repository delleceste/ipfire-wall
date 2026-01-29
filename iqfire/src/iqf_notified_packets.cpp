#include "iqf_notified_packets.h"
#include "iqfwidgets.h"
#include "iqfire.h" /* icon path */
#include "iqf_message_proxy.h" /* for insertIntoHtmlHeader() */
#include <QStringList>
#include <QHeaderView>
#include <QShowEvent>
#include <QtDebug>

IQFNotifiedPackets::IQFNotifiedPackets(QWidget *parent) : QTreeWidget(parent)
{
	setMouseTracking(true);
	header()->setResizeMode(QHeaderView::ResizeToContents);
	connect(this, SIGNAL(itemEntered(QTreeWidgetItem *, int)), this, SLOT(setHelp(QTreeWidgetItem *, int)));
	connect(this, SIGNAL(itemEntered(QTreeWidgetItem *, int)), this, SLOT(setInfo(QTreeWidgetItem *, int)));
	connect(this, SIGNAL(itemClicked(QTreeWidgetItem *, int)), this, SLOT(itemSelected(QTreeWidgetItem *, int)));
}
			
void IQFNotifiedPackets::removeSelectedItems()
{
	QList<QTreeWidgetItem *> items = selectedItems();
	for(int i = 0; i < items.size(); i++)
		delete items[i];
}
			
void IQFNotifiedPackets::addItem(QTreeWidgetItem *it)
{
	QSettings s; /* for ICON_PATH macro */
	QStringList itemRepr = itemRepresentation(it);
	if(!alreadyPresent(it))
	{
		addTopLevelItem(it);
		if(columnCount() >= 10 && it->text(10).contains("ACCEPT"))
			it->setIcon(0, QIcon(ICON_PATH + "ok_green.png"));
		else if(columnCount() >= 10 && it->text(10).contains("DROPPED"))
			it->setIcon(0, QIcon(ICON_PATH + "stop.png"));
		else
			it->setIcon(0, QIcon(ICON_PATH + "help.png"));
		for(int i = 0; i < columnCount(); i++)
		{
			QFont f = it->font(i);
			f.setBold(true);
			it->setFont(i, f);
		}
	}
	else
	{
		delete it;
	}
		   
	
}
		
void IQFNotifiedPackets::showEvent(QShowEvent* e)
{
	header()->setResizeMode(QHeaderView::Interactive);
	return QTreeWidget::showEvent(e);
}
	
bool IQFNotifiedPackets::alreadyPresent(const QTreeWidgetItem *it)
{
	int i;
	QList<QTreeWidgetItem *> itemlist = this->findItems("*", Qt::MatchWildcard);
	for(i = 0; i < itemlist.size(); i++)
	{
		if(itemRepresentation(itemlist[i]) == itemRepresentation(it))
		{
			return true;
		}
	}
	return false;
}
		
QStringList IQFNotifiedPackets::itemRepresentation(const QTreeWidgetItem *it) const
{
	QStringList sl;
	/* text(0) contains the date and the date is not considered */
	sl << it->text(1) << it->text(2) << it->text(3) << it->text(4) << 
			it->text(5) << it->text(6) << it->text(7) << it->text(8) << it->text(9) 
			<< it->text(10);
	return sl;
}

void IQFNotifiedPackets::setInfo(QTreeWidgetItem *it, int col)
{
	Q_UNUSED(col);
	QString html;
	QString s;
	
	s = QString("<h3>Packet received on <strong>%1</strong>:</h3>").arg(it->text(0));
	
	s += "<body>";
	s += "<p>";
	s += "<ul class=\"notified_connections\">";
	
	s += QString("<li><cite>Direction</cite> %1</li>").arg(it->text(1));
	s += QString("<li><cite>Protocol</cite> %1</li>").arg(it->text(2));
	
	if(it->text(3) != "-")
		s += QString("<li><cite>Input network interface</cite> %1</li>").arg(it->text(3));
	
	
	s += QString("<li><cite>Source IP</cite> %1</li>").arg(it->text(4));
	s += QString("<li><cite>Source port</cite> %1</li>").arg(it->text(5));
	
	if(it->text(6) != "-")
		s += QString("<li><cite>Output network interface</cite> %1</li>").arg(it->text(6));
	
	s += QString("<li><cite>Destination IP</cite> %1</li>").arg(it->text(7));
	s += QString("<li><cite>Destination port</cite> %1</li>").arg(it->text(8));
	
	s += "</ul>";
	s += "</p>";
	s += "</body>";
	
	IQFInfoBrowser*ib = IQFInfoBrowser::infoBrowser();
	html = IQFMessageProxy::msgproxy()->insertInfoIntoHtmlHeader(s);
	ib->setHtml(html);
}
		
void IQFNotifiedPackets::setHelp(QTreeWidgetItem *it, int col)
{
	Q_UNUSED(col);
	Q_UNUSED(it);
	IQFHelpBrowser::helpBrowser()->setHtml(IQFMessageProxy::msgproxy()->getHelp("notified_packets"));
}

void IQFNotifiedPackets::setItemAcknowledged(QStringList& data)
{
	int i;
	QList<QTreeWidgetItem *> itemlist = this->findItems("*", Qt::MatchWildcard);
	for(i = 0; i < itemlist.size(); i++)
	{
		if(itemRepresentation(itemlist[i]) == data)
		{
			for(int j = 0; j < columnCount(); j++)
			{
				QFont f = itemlist[i]->font(j);
				f.setBold(false);
				itemlist[i]->setFont(j, f);
			}
		}
	}
}

void IQFNotifiedPackets::itemSelected(QTreeWidgetItem *it, int col)
{
	Q_UNUSED(col);
	for(int j = 0; j < columnCount(); j++)
	{
		QFont f = it->font(j);
		f.setBold(false);
		it->setFont(j, f);
	}
}


