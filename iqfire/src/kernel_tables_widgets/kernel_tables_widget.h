#ifndef KERNEL_TABLES_WIDGET
#define KERNEL_TABLES_WIDGET

#include <QTreeWidget>
#include <QString>
#include <QLabel>

class IQFPushButton;
class IQFComboBox;
class IQFLineEdit;
class QTimer;
class IQFRadioButton;
class IQFCheckBox;
class KernelTablesAbstractThread;

class KernelTableWidget : public QWidget
{
  Q_OBJECT
  
  public:
    
  KernelTableWidget(QWidget *parent);
  ~KernelTableWidget();
  
  void addTable(QStringList &t);
  void clearTables();
  void setTitle(const QString &s) { label->setText(s); }
  void setTableLabels(QStringList &labels);
  
  protected slots:
    virtual void refresh();
    void enableAutoRefresh(bool);
    void refreshIntervalChanged(int);
    void clearFilter();
    void filter();
    virtual void treeItemInfoRequest(QTreeWidgetItem *, int) = 0;
    void treeItemEntered(QTreeWidgetItem *, int);
    void threadFinished();
    
  protected:
    void showEvent(QShowEvent *e);
    void hideEvent(QHideEvent *e);
    
    KernelTablesAbstractThread *d_thread;
  
  private:
    QTreeWidget *tree;
    IQFComboBox *cbFind;
    IQFPushButton *pbFind, *pbClearFind;
    IQFLineEdit *le;
    QLabel *label, *threadLabel;
    QTimer *d_timer;
    unsigned short d_timerInterval;
    IQFRadioButton *rbPlainText, *rbRexp;
    IQFCheckBox* cbRefreshAuto;
    uint d_tableCnt;
};



#endif
