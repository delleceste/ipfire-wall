#include "iqf_tree_item.h"
#include <QtDebug>

IQFTreeWidgetItem::IQFTreeWidgetItem(QTreeWidgetItem *parent) : QTreeWidgetItem(parent),
	_ruleValid(true), _itemValid(true)
{
	_myBrush = foreground(0);
}

IQFTreeWidgetItem::IQFTreeWidgetItem(QTreeWidgetItem *parent, const QStringList & strings) :
		QTreeWidgetItem(parent, strings),
				_ruleValid(true) , _itemValid(true)
{
	_myBrush = foreground(0);
	setStoredItems(strings);
}

IQFTreeWidgetItem::IQFTreeWidgetItem(QTreeWidget *parent) : QTreeWidgetItem(parent),
				     _ruleValid(true), _itemValid(true)
{
	_myBrush = foreground(0);
}

IQFTreeWidgetItem::IQFTreeWidgetItem(QTreeWidget *parent,const QStringList & strings) 
	: QTreeWidgetItem(parent, strings), _ruleValid(true), _itemValid(true)
{
	_myBrush = foreground(0);
	setStoredItems(strings);
}

IQFTreeWidgetItem::IQFTreeWidgetItem(const QStringList & strings) 
	: QTreeWidgetItem(strings), _ruleValid(true), _itemValid(true)
{
	_myBrush = foreground(0);
	setStoredItems(strings);
}

QString IQFTreeWidgetItem::storedItem(int pos, bool *ok)
{
	*ok = true;
	if(pos < _storedItems.size())
		return _storedItems[pos];
	*ok = false;
	return QString();
}

void IQFTreeWidgetItem::setText(int col, const QString &text)
{
	QTreeWidgetItem::setText(col, text);
	/* also store the text internally, to use in isReallyItemColumnChanged */
	storeItemAt(col, text);
}

void IQFTreeWidgetItem::storeItemAt(int pos, QString s)
{
	if(pos < _storedItems.size())
		_storedItems[pos] = s;
	else
	{
		for(int i = _storedItems.size(); i < pos + 1; i++)
			_storedItems << "-";
		_storedItems[pos] = s;
	}
		
}

bool IQFTreeWidgetItem::reviseForErrors()
{
	int i;
	_columnsWithErrors.clear();
	bool ok;
	for(i = 0; i < columnCount(); i++)
	{
		ok = checkColumnChanged(i);
		if(!ok)
		{
			_columnsWithErrors << i;
			_ruleValid = false;
		}
	}
	if(_columnsWithErrors.size() > 0)
		return false;
	else
		return true;
}

void IQFTreeWidgetItem::colourItem(const QBrush& brush)
{
	for(int i = 0; i < columnCount(); i++)
		setForeground(i, brush);
		
}

void IQFTreeWidgetItem::setModified(bool modified)
{
	for(int i = 0; i < columnCount(); i++)
	{
		if(modified)
			setFont(i, QFont("", -1, QFont::Bold));
		else
			setFont(i, QFont("", -1, QFont::Normal));
	}
	
}


