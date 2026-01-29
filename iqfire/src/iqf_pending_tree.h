#ifndef IQF_PENDING_TREE_H
#define IQF_PENDING_TREE_H

#include <QWidget>
#include <QVector>
#include <QString>

#include <ipfire_structs.h>
#include "iqf_tree_item.h"
#include "iqf_tree_widget.h"
#include "iqf_pending_tree_item.h"
#include "ignored_packet.h"

/*  #define IPFI_DROP 		0     
 *  #define IPFI_ACCEPT		1
 *  #define IPFI_IMPLICIT	2
 */
 
#define IGNORE_PACKET 		10
#define IGNORE_PACKET_FOREVER 	11

class IQFRadioButton;
class IQFPendingItem;
class QLabel;
class QMouseEvent;

class IQFPendingTree : public IQFTreeWidget
{
	Q_OBJECT
	public:
		IQFPendingTree(QWidget *parent);
		~IQFPendingTree();
		
		int parseTreeForRules();
		/** Returns true if the new packet to be ignored is already
		 * present in the list.
		 */
		bool alreadyPresent(IgnoredPacket &newpacket);
		bool itemAlreadyPresent(const ipfire_info_t* info);
		IQFPendingTreeItem* addItem(ipfire_info_t *info, bool resolve);
		IQFPendingTreeItem* addItem(IgnoredPacket& ign, bool resolve);
		void deleteAllItems();
		
	public slots:
		/* needs be public because it is called by the popupWidget
		* when an item is selected.
		* It is also in the slot  treeItemEntered(QTreeWidgetItem *, int).
		*/
		void buildItemInfoAndEmit(QTreeWidgetItem *, int);
		
		void anItemWasResolved();		
		
	protected slots:
		void setAny();
		
		/** (Re) implemented from iqf_tree_widget.
		 * Just sets mouseTracking to false when an item is 
		 * clicked
		 */
		void treeItemClicked(QTreeWidgetItem *, int);
		
		/** (Re) implemented from iqf_tree_widget 
		 */
		void treeItemEntered(QTreeWidgetItem *, int);
				
		/** Implemented from IQFTreeWidget. This is a function invoked
		 *  from the private slot in IQFTreeWidget when one of the columns
		 *  really changed in an item. Read the 
		 *  isReallyItemColumnChanged(QTreeWidgetItem *it, int col) doc.
		 */
		void itemColumnChanged(QTreeWidgetItem *, int);
		
		/** Stores the column of the item that was pressed */
		void treeItemPressed(QTreeWidgetItem *it , int col);
		
	protected:
		void mouseReleaseEvent(QMouseEvent *e);
		void itemPressed(QTreeWidgetItem *, int);
		void showEvent(QShowEvent *e);
		
	private:
		int last_column_over;
};

#endif
