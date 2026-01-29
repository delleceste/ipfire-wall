#ifndef IQF_PENDING_RULES_H
#define IQF_PENDING_RULES_H

#include <QWidget>
#include "ignored_packets_set.h"
#include "iqfwidgets.h"

class IQFPendingTree;

class WPendingRules : public QWidget
{
	Q_OBJECT
	public:
		WPendingRules(QWidget *parent);
		~WPendingRules();
		
		void setResolveEnabled(bool en) { resolve_enabled = en; }
		bool resolveEnabled() { return resolve_enabled; }
	
		
	public slots:
		void reloadTree();
		void addItem();
		
	protected:
		
	protected slots:
		void acceptRule();
		void blockRule();
		void removeItem();
		
	private:
		IQFPushButton *pbAccept, *pbBlock, *pbDelete;
		IQFPendingTree *ignTree;
		
		/* The services and IP resolution is initialized
		 * in the constructor reading the QSettings.
		*/
		bool resolve_enabled;
};

#endif

