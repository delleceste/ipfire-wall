#include <QTreeWidget>
#include <QtDebug>
#include "iqf_tree_widget.h"
#include "iqf_tree_item.h"
#include "iqf_item_delegate.h"
#include "iqflog.h"

IQFTreeWidget::IQFTreeWidget(QWidget *parent) : QTreeWidget(parent)
{
	/* do not createConnections(): let the super classes enable
	 * them when needed.
	 */
}

void IQFTreeWidget::treeItemClicked(QTreeWidgetItem *it, int col)
{
	Q_UNUSED(it);
	Q_UNUSED(col);
}

void IQFTreeWidget::treeItemEntered(QTreeWidgetItem * it, int col)
{
	Q_UNUSED(it);
	Q_UNUSED(col);
}

void IQFTreeWidget::treeItemDoubleClicked(QTreeWidgetItem *it, int col)
{
	Q_UNUSED(it);
	Q_UNUSED(col);
}

void IQFTreeWidget::treeItemPressed(QTreeWidgetItem *it, int col)
{
	Q_UNUSED(it);
	Q_UNUSED(col);
}


void IQFTreeWidget::isReallyItemColumnChanged(QTreeWidgetItem *it, int col)
{
	bool ok;
	/* if the tree is not visible, do not do anything. This happens when the tree
	 * is created or  a new item is added. In these circumstances, if the widget
	 * is not visible, there is no need to check the columns changed.
	 * Actually, it is supposed that a new item just created is correct in all
	 * its fields.
	 */
	if(!isVisible() || (columnCount() != it->columnCount()))
	{
		return;
	}
	
	IQFTreeWidgetItem * iqftwi = dynamic_cast<IQFTreeWidgetItem *>(it);
	if(iqftwi == NULL)
	{
		Log::log()->appendFailed("IQFTreeWidget::isReallyItemColumnChanged()\n"
			"Impossible to convert to IQFTreeWidgetItem* "
			"a QTreeWidgetItem* element! [%1]");
		return;
	}
// 	qDebug() << iqftwi->storedItems();
	/* ok is put to false if the col is out of range */
	if(it->text(col) != iqftwi->storedItem(col, &ok) && ok)
	{
		iqftwi->storeItemAt(col, it->text(col));
		itemColumnChanged(it, col);
	}
	else
	{
// 		printf("\e[1;32mcolonna non cambiata:\e[0m\n");
// 		qDebug() <<it->text(col) << "stored: " << iqftwi->storedItem(col, &ok) << "ok: " << ok;
	}
}

void IQFTreeWidget::deleteItem(QTreeWidgetItem *item)
{
	disconnect(this, SIGNAL(itemClicked(QTreeWidgetItem *, int)),0,0);
	disconnect(this, SIGNAL(itemDoubleClicked(QTreeWidgetItem *, int)),0,0);
	disconnect(this, SIGNAL(itemEntered(QTreeWidgetItem *, int)),0,0);
	disconnect(this, SIGNAL(itemChanged(QTreeWidgetItem *, int)),0,0);
	disconnect(this, SIGNAL(itemPressed(QTreeWidgetItem *, int)),0,0);
	delete item;
	createConnections();
}

void IQFTreeWidget::createConnections()
{
	connect(this, SIGNAL(itemClicked(QTreeWidgetItem *, int)), this,
		SLOT(treeItemClicked(QTreeWidgetItem *, int)));
	connect(this, SIGNAL(itemDoubleClicked(QTreeWidgetItem *, int)), this, SLOT(
		treeItemDoubleClicked(QTreeWidgetItem *, int)));
	connect(this, SIGNAL(itemEntered(QTreeWidgetItem *, int)), this, SLOT(
		treeItemEntered(QTreeWidgetItem *, int)));
	connect(this, SIGNAL(itemChanged(QTreeWidgetItem *, int)), this, SLOT(
		isReallyItemColumnChanged(QTreeWidgetItem *, int)));
	connect(this, SIGNAL(itemPressed(QTreeWidgetItem *, int)), this, SLOT(
		treeItemPressed(QTreeWidgetItem *, int)));
}

void IQFTreeWidget::disableConnections()
{
	disconnect();
}

