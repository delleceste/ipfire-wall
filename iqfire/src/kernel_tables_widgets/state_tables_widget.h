#ifndef STATE_TABLES_WIDGET_H
#define STATE_TABLES_WIDGET_H

#include "kernel_tables_widget.h"
#include "kernel_tables_abstract_thread.h"

class StateTablesThread : public KernelTablesAbstractThread
{
  Q_OBJECT
  public:
    StateTablesThread(QObject *parent) : KernelTablesAbstractThread(parent) {};
    
  protected:
    void run();
};

class StateTablesWidget : public KernelTableWidget
{
  Q_OBJECT
  public:
    StateTablesWidget(QWidget *parent);
    
  protected slots:
    void refresh();
    void treeItemInfoRequest(QTreeWidgetItem *, int);
};


#endif
