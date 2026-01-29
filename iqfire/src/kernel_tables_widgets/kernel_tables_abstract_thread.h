#ifndef KERNEL_TABLES_ABSTRACT_THREAD
#define KERNEL_TABLES_ABSTRACT_THREAD

#include <QThread>
#include <QStringList>


class KernelTablesAbstractThread : public QThread
{
    Q_OBJECT
  public:
    KernelTablesAbstractThread(QObject *parent) : QThread(parent) {};
    
    QList<QStringList> elements() { return d_elements; }
    
  protected:
    virtual void run() = 0;
    
    QList<QStringList> d_elements;
};

#endif
