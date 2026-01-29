#ifndef IQF_TREE_ITEM_H
#define IQF_TREE_ITEM_H

#include <QTreeWidgetItem>
#include <QTreeWidget>

class IQFTreeWidgetItem;

class IQFTreeWidgetItem : public QObject, public QTreeWidgetItem
{
	Q_OBJECT
	public:
		IQFTreeWidgetItem(QTreeWidgetItem *parent);
		IQFTreeWidgetItem(QTreeWidgetItem *parent, const QStringList & strings);
		IQFTreeWidgetItem(QTreeWidget *parent);
		IQFTreeWidgetItem(QTreeWidget *parent, const QStringList & strings);
		IQFTreeWidgetItem(const QStringList & strings);
		
		void setText(int col, const QString& txt);
		
		/* This avoids having to cast explicitly to QTreeWidgetItem* when calling
		 * parent() on a derived class.
		 */
		QTreeWidgetItem * parent() { return QTreeWidgetItem::parent(); }
		
		void setRuleValid() { _ruleValid = true; }
		void setRuleInvalid() { _ruleValid = false; }
		bool ruleValid() { return _ruleValid; }
		
		void setItemValid(bool valid) { _itemValid = valid; }
		bool itemValid() { return _itemValid; }
		QString invalidReason() { return _invalidReason; }
		
	
		/** checks if a determined column contains an error
		 *	This is a pure virtual function and so must be re implemented
		 * 	in a subclass.
		 */
		virtual bool checkColumnChanged(int col) = 0;
	
		/** checks all the item for errors. Use this before saving or
		 * sending the associated rule to the kernel.
		 * Practically, calls checkColumnChanged(col) over all the 
		 * item's columns. Will set _ruleValid to true if ok,
		 * otherwise will set it to false.
	 	 */
		bool reviseForErrors();
		QList<int> columnsWithErrors() {return  _columnsWithErrors; }
		
		/** @return the previously memorized item.
		 * pos contains the position itself or its negative value 
		 * in case of error.
		 */
		QString storedItem(int pos, bool *ok);
		QStringList storedItems() { return _storedItems; }
		void storeItemAt(int pos, QString s);
		void setStoredItems(const QStringList &newitems) { _storedItems = newitems; }
	
		QBrush myBrush() { return _myBrush; }
		void colourItem(const QBrush& brush);
		void setModified(bool mod);
		
	protected:
		QString _invalidReason;
		
	private:
		bool _ruleValid;
		int _editState;
		bool _itemValid;
		QBrush _myBrush;
		QList<int> _columnsWithErrors;
		QStringList _storedItems;
		

};

#endif

