#ifndef IQF_POPUP_H
#define IQF_POPUP_H

#include <QWidget>
#include <ipfire_structs.h>
#include <QTreeWidget>
#include <QTreeWidgetItem>
#include <QVector>
#include <QString>
#include <QSettings>

#include "ignored_packet.h"
#include "iqf_pending_tree.h"

/*  #define IPFI_DROP 		0     
 *  #define IPFI_ACCEPT		1
 *  #define IPFI_IMPLICIT	2
 */
 
#define IGNORE_PACKET 		10
#define IGNORE_PACKET_FOREVER 	11

class IQFRadioButton;
class IQFPushButton;
class IQFPopupItem;
class QLabel;

class IQFPopup : public QWidget
{
	Q_OBJECT
	public:
	IQFPopup(QWidget *parent);
	~IQFPopup();
	
	void setUserResizableHeaders();
	bool isPopupEnabled() { return popup_enabled; }
	bool isPopupOnMatchEnabled() { return popup_on_match; }
	int bufferSize() { return buffer_size; }
	
	int itemCount() { return info_count; }
	int maxItemCount() { return buffer_size; }
	
	void setResolveEnabled(bool en) { resolve_enabled = en; }
	bool resolveEnabled() { return resolve_enabled; }
	
	void setNotifyListeningOnly(bool en);
	bool notifyListeningOnly() { return notify_listening_only; }
	
	IgnoredPacket last_ignored_packet;
	
	public slots:
		void addInfo(ipfire_info_t *info);
		void setPopupEnabled(bool enable);
		void setPopupOnMatchEnabled(bool enable) { popup_on_match = enable; }
		void disablePopups();
		void setPopupBuffer(int size);
		
		bool toBeIgnored(const ipfire_info_t *info);
		
	signals:
		void popupsDisabled();
		
	protected:
		void closeEvent( QCloseEvent * event );
		/* - enables mouse tracking for item representation in the
		 *   info browser;
		 * - disables the radio buttons until the user selects one or
		 *   more items.
		 */
		void showEvent(QShowEvent *e);
		
		void enterEvent(QEvent *e);
		
	protected slots:
		/* enables the radio buttons and disables the
		 * mouse tracking, to avoid that the info about the selected item
		 * changes on the info browser.
		*/
		void itemSelected(QTreeWidgetItem *, int);
		void aRadioClicked();
		void ok();
		void selectAll(bool select);
		
// 		void itemPressed(QTreeWidgetItem *, int);
		
		
	private:
		
		QVector<ipfire_rule> getRules();
		
		
		IQFPendingTree *tree;
		bool popup_enabled, popup_on_match;
		QWidget *radios; /* contains the radio buttons below */
		IQFRadioButton *radioAcc;
		IQFRadioButton *radioDen;
		IQFRadioButton *radioIgn;
		IQFRadioButton *radioIgnForever;
		IQFPushButton *bAccept;
		QLabel *label;
		int buffer_size, info_count;
		QVector<ipfire_rule> newrules;
	
		/* The services and IP resolution is initialized
		 * in the constructor reading the QSettings.
		*/
		bool resolve_enabled;
		/* this too is initialized reading QSettings in the constructor */
		bool notify_listening_only;
};


#endif



