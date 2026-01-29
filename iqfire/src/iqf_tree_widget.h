#ifndef IQF_TREE_WIDGET_H
#define IQF_TREE_WIDGET_H

#include <QWidget>
#include <QTreeWidget>
#include <QTreeWidgetItem>

class IQFTreeWidget : public QTreeWidget
{
	Q_OBJECT
	public:
		IQFTreeWidget(QWidget *parent);
		/** call this to delete an item in the tree widget.
		 * Before deleting the item,it disconnects all the 
		 * signals, and then reconnects them.
		 */
		void deleteItem(QTreeWidgetItem *item);
		
		void enableConnections() { createConnections(); }
		void disableConnections();
		
	protected slots:
		/** this really does nothing. Just is called as a slot
		 * when an item is clicked.
		 * Can be reimplemented in a subclass to make something
		 * when an item is clicked.
		 */
		virtual void treeItemClicked(QTreeWidgetItem *, int);
		
		/** this really does nothing. Just is called as a slot
		 * when an item is double clicked.
		 * Can be reimplemented in a subclass to make something
		 * when an item is double clicked.
		 */		
		virtual void treeItemDoubleClicked(QTreeWidgetItem *, int);
		
		/** this really does nothing. Just is called as a slot
		 * when an item is clicked.
		 * Can be reimplemented in a subclass to make something
		 * when an item is entered.
		 */	
		virtual void treeItemEntered(QTreeWidgetItem *, int);
		
		/** this really does nothing. Just is called as a slot
		 * when an item is clicked.
		 * Can be reimplemented in a subclass to make something
		 * when an item is pressed.
		 */
		virtual void treeItemPressed(QTreeWidgetItem *it, int col);
		
		/** The subclasses MUST implement this method, which is called if
		 * the text fields in the tree widget item it has changed in the 
		 * column col.
		 * This method is called by isReallyItemColumnChanged() if
		 * the text fields of it have changed.
		 * The isReallyItemColumnChanged() filters out the generic
		 * QTreeWidget itemChanged() signal and calls itmeColumnChanged()
		 * just when an item's text has really changed in the column col.
		 */
		virtual void itemColumnChanged(QTreeWidgetItem *it, int col) = 0;
		
		
	private:
		void createConnections();
		
	private slots:
		/* QTreeWidget signal itemChanged() is emitted whenever something changes
		 * in the tree item. Really, in this implementation we are only interested
		 * in changes to the text in the item, not if something else changes, such
		 * as toolTips or other.
		 * So, this method watches about real changes in one of the text columns in
		 * the tree item, and calls the method
		 * itemColumnChanged()
		 * if the change has really happened.
		 * All subclasses must implement the itemColumnChanged() pure virtual method
		 * which is called by the isReallyItemColumnChanged() below.
		 */
		void isReallyItemColumnChanged(QTreeWidgetItem *it, int col);
		
};










#endif





