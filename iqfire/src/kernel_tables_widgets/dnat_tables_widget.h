#ifndef DNAT_TABLES_WIDGET_H
#define DNAT_TABLES_WIDGET_H

#include "kernel_tables_widget.h"
#include "kernel_tables_abstract_thread.h"

class DnatTablesThread : public KernelTablesAbstractThread
{
  Q_OBJECT
  public:
    DnatTablesThread(QObject *parent) : KernelTablesAbstractThread(parent) {};
    
  protected:
    void run();
};

class DnatTablesWidget : public KernelTableWidget
{
  Q_OBJECT
  public:
    DnatTablesWidget(QWidget *parent);
    
  protected slots:
    void refresh();
    void treeItemInfoRequest(QTreeWidgetItem *, int);
};


#endif
