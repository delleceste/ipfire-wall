#ifndef IQF_PENDING_TREE_ITEM_H
#define IQF_PENDING_TREE_ITEM_H


#include <QWidget>
#include <ipfire_structs.h>
#include <QVector>
#include <QString>
#include <QSettings>
#include <QBrush>

#include "iqf_tree_item.h"
#include "iqf_tree_widget.h"

#include "ignored_packet.h"

/*  #define IPFI_DROP 		0     
 *  #define IPFI_ACCEPT		1
 *  #define IPFI_IMPLICIT	2
 */
 
#define IGNORE_PACKET 		10
#define IGNORE_PACKET_FOREVER 	11

class IQFRadioButton;
class IQFPendingTreeItem;
class QLabel;
class QMouseEvent;

class IQFPendingTreeItem :  public IQFTreeWidgetItem
{
	Q_OBJECT
	public:
		IQFPendingTreeItem(QTreeWidget *widget, ipfire_info_t* ipfi_info, bool resolve);
		IQFPendingTreeItem(QTreeWidget *widget, IgnoredPacket& ign, bool resolve);
		~IQFPendingTreeItem();
	
		QStringList infoToItemStringList(const ipfire_info_t *info);
		QStringList toStringList();
		
		void setIgnoredPacket(IgnoredPacket ignp) { myignored = ignp; has_ignored = true; }
		IgnoredPacket ignoredPacket() { return myignored; }
	
		ipfire_info_t info() { return myinfo; }
		
		ipfire_rule itemToRule();
	
		void setPolicy(int p);
		void applyPolicyColour(int policy);
		int policy()  {return _policy; }
		
		bool hasIgnoredPacket() { return has_ignored; }
		QList<unsigned int> socketPairFromInfo(const ipfire_info_t &info);
		
		void resolve();
		bool resolveEnabled() { return resolve_enabled; }
		bool checkColumnChanged(int);
		
	signals:
		void itemResolved();	
		void ruleBuildingFailed();
	
	protected slots:
		void resolved(const QString &, const QStringList&);
		
		
	private:
		ipfire_info_t myinfo;
		IgnoredPacket myignored;
		int _policy;
		bool has_ignored;
		bool resolve_enabled;
		QString quadKey; /* concatenates sip dip sport dport to create a hash (for resolution) */
		/* the source port is not shown in the item, because it is not so significant.
		 * For this reason, we store this information in this variable for practicity 
		 */
		unsigned short d_hiddenSourcePort;
};


#endif
