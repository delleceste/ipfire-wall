#ifndef SNAT_TABLES_WIDGET_H
#define SNAT_TABLES_WIDGET_H

#include "kernel_tables_widget.h"
#include "kernel_tables_abstract_thread.h"

class SnatTablesThread : public KernelTablesAbstractThread
{
  Q_OBJECT
  public:
    SnatTablesThread(QObject *parent) : KernelTablesAbstractThread(parent) {};
    
  protected:
    void run();
};

class SnatTablesWidget : public KernelTableWidget
{
  Q_OBJECT
  public:
    SnatTablesWidget(QWidget *parent);
    
  protected slots:
    void refresh();
    void treeItemInfoRequest(QTreeWidgetItem *, int);
   
};


#endif
