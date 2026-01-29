#ifndef IQF_NOTIFIED_PACKETS_H
#define IQF_NOTIFIED_PACKETS_H

#include <QString>
#include <QTreeWidget>
#include <QTreeWidgetItem>
#include <QStringList>
#include <QMetaType>
#include "iqf_rulematch_set.h"


class IQFNotifiedPackets : public QTreeWidget
{
	Q_OBJECT
	public:
		IQFNotifiedPackets(QWidget *parent);
			
	public slots:
		void addItem(QTreeWidgetItem *);
		void setInfo(QTreeWidgetItem *it, int);
		void setHelp(QTreeWidgetItem *it, int);
		void setItemAcknowledged(QStringList& data);
		void itemSelected(QTreeWidgetItem *it, int col);
		void removeSelectedItems();
		
	protected:
		virtual void showEvent(QShowEvent* e);
		
	private:
		bool alreadyPresent(const QTreeWidgetItem *);
		QStringList itemRepresentation(const QTreeWidgetItem *it) const;
};



#endif


