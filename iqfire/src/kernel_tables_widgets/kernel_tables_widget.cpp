#include "kernel_tables_widget.h"
#include "kernel_tables_abstract_thread.h"
#include <iqfwidgets.h>
#include <QGridLayout>
#include <QLabel>
#include <QTimer>
#include <colors.h>
#include <QColor>
#include <QHeaderView>
#include <QTime>
#include <macros.h>

KernelTableWidget::~KernelTableWidget()
{
  if(d_thread->isRunning())
  {
    pok("Thread \"%s\" is still running: waiting for it to exit", qstoc(d_thread->objectName()));
    d_thread->wait();
  }
}

KernelTableWidget::KernelTableWidget(QWidget *parent) : QWidget(parent)
{
  d_thread = NULL;
  d_tableCnt = 0;
  d_timerInterval = 10 * 1000;
  QLabel *label = new QLabel(this);
  label->setText("a kernel table");
  label->setSizePolicy(QSizePolicy(QSizePolicy::Preferred, QSizePolicy::Fixed));
  QLabel *labelFilter = new QLabel(this);
  labelFilter->setText("Filter view:");
  labelFilter->setSizePolicy(QSizePolicy(QSizePolicy::Preferred, QSizePolicy::Fixed));
  tree = new QTreeWidget(this);
  tree->setRootIsDecorated(false);
  tree->header()->setResizeMode(QHeaderView::ResizeToContents);
  tree->setMouseTracking(true);
  pbFind = new IQFPushButton(this);
  pbFind->setObjectName("pbFindTableItem");
  pbClearFind = new IQFPushButton(this);
  pbClearFind->setObjectName("pbClearFindTableItem");
  cbFind = new IQFComboBox(this);
  le = new IQFLineEdit(this);
  QGridLayout *lo = new QGridLayout(parent);
  IQFPushButton *pbRefresh = new IQFPushButton(this);
  pbRefresh->setObjectName("pbRefreshTablesList");
  cbRefreshAuto = new IQFCheckBox(this);
  IQFSpinBox *sbRefreshInterval = new IQFSpinBox(this);
  sbRefreshInterval->setObjectName("sbRefreshInterval");
  sbRefreshInterval->setMinimum(5);
  sbRefreshInterval->setValue(10);
  sbRefreshInterval->setMaximum(60);
  d_timer = new QTimer(this);
  d_timer->setInterval(d_timerInterval);
  d_timer->setSingleShot(false);
  
  QLabel *refIntLabel = new QLabel(this);
  refIntLabel->setText("Refresh Interval [sec.]:");
  refIntLabel->setSizePolicy(QSizePolicy(QSizePolicy::Preferred, QSizePolicy::Fixed));
  threadLabel = new QLabel(this);
  threadLabel->setText("Going to refresh...");
  pbFind->setText("Filter");
  pbRefresh->setText("Refresh");
  cbRefreshAuto->setText("Auto Refresh");
  
  pbClearFind->setText("Clear");
  
  rbRexp = new IQFRadioButton(this);
  rbRexp->setText("Reg Exp.");
  rbRexp->setChecked(false);
  
  rbPlainText = new IQFRadioButton(this);
  rbPlainText->setText("Plain Text");
  rbPlainText->setChecked(true);
  
  /* layout */
  /* label */
  lo->addWidget(label, 0, 0, 1, 12);
  /* find functions */
  lo->addWidget(labelFilter, 1, 0, 1, 1);
  lo->addWidget(cbFind, 1, 1, 1, 4);
  lo->addWidget(le, 1, 5, 1, 3);
  lo->addWidget(rbPlainText, 1, 8, 1, 1);
  lo->addWidget(rbRexp, 1, 9, 1, 1);
  lo->addWidget(pbFind, 1, 10, 1, 1);
  lo->addWidget(pbClearFind, 1, 11, 1,1);

  
  lo->addWidget(tree, 2, 0, 7, 12);
  lo->addWidget(pbRefresh, 9, 0, 1, 1);
  lo->addWidget(threadLabel, 9, 1, 1, 3);
  lo->addWidget(refIntLabel, 9, 8, 1, 2);
  lo->addWidget(sbRefreshInterval, 9, 10, 1, 1);
  lo->addWidget(cbRefreshAuto, 9, 11, 1, 1);
  
  
  connect(pbRefresh, SIGNAL(clicked()), this, SLOT(refresh()));
  connect(pbFind, SIGNAL(clicked()), this, SLOT(filter()));
  connect(cbRefreshAuto, SIGNAL(toggled(bool)), this, SLOT(enableAutoRefresh(bool)));
  connect(sbRefreshInterval, SIGNAL(valueChanged(int)), this, SLOT(refreshIntervalChanged(int)));
  connect(cbRefreshAuto, SIGNAL(toggled(bool)), sbRefreshInterval, SLOT(setEnabled(bool)));
  connect(d_timer, SIGNAL(timeout()), this, SLOT(refresh()));
  connect(pbClearFind, SIGNAL(clicked()), this, SLOT(clearFilter()));
  connect(tree, SIGNAL(itemClicked(QTreeWidgetItem *, int)), this, SLOT(treeItemInfoRequest(QTreeWidgetItem *, int)));
  connect(tree, SIGNAL(itemEntered(QTreeWidgetItem *, int)), this, SLOT(treeItemEntered(QTreeWidgetItem *, int)));
  
  cbRefreshAuto->setChecked(false);
  sbRefreshInterval->setDisabled(true);
}

void KernelTableWidget::refresh()
{
  threadLabel->setText("Request sent to kernel, please wait...");
}

void KernelTableWidget::threadFinished()
{
  clearTables();
  threadLabel->setText(QString("Tables updated at %1").arg(QTime::currentTime().toString()));
  QList<QStringList> items = d_thread->elements();
  foreach(QStringList sl, items)
    addTable(sl);
}

void KernelTableWidget::addTable(QStringList &t)
{
  QColor color;
  /* add itme count */
  d_tableCnt++;
  QString cnt = QString("%1").arg(d_tableCnt);
  t << cnt;
  
  QTreeWidgetItem *item = new QTreeWidgetItem(tree, t);
  item->setFlags(Qt::ItemIsSelectable|Qt::ItemIsEnabled);
//   if(item->text(1) == "TCP")
//     color = KDARKGREEN;
//   else if(item->text(1) == "UDP")
//     color = KDARKBLUE;
//   else if(item->text(1) == "ICMP")
//     color = KCAMEL;
//   else if(item->text(1) == "IGMP")
//     color = KYELLOW;
//   
//   if(item->text(0) == "IN")
//     color = color.lighter(106);
//   else if(item->text(0) == "FWD")
//     color = color.darker(106);
//   else if(item->text(0) == "PRE")
//     color = color.lighter(115);
//   else if(item->text(0) == "POST")
//     color = color.darker(120);
//   color.setAlpha(127);
//   for(int i = 0; i < item->columnCount(); i++)
//   {
//     color = color.darker(100 + i + 4);
//     item->setBackground(i, color);
//   }
}
  
void KernelTableWidget::clearTables()
{
  tree->clear();
  d_tableCnt = 0;
}

void KernelTableWidget::clearFilter()
{
  le->clear();
  refresh();
}

void KernelTableWidget::filter()
{
  int column = cbFind->currentIndex();
  if(column < tree->columnCount())
  {
    QList<QTreeWidgetItem *>items = tree->findItems("*", Qt::MatchWildcard, 0);
    foreach(QTreeWidgetItem *it, items)
      it->setHidden(true);
    if(rbPlainText->isChecked())
      items = tree->findItems(le->text(), Qt::MatchContains, column);
    else
      items = tree->findItems(le->text(), Qt::MatchRegExp, column);
     foreach(QTreeWidgetItem *it, items)
      it->setHidden(false);
  }
}

void KernelTableWidget::hideEvent(QHideEvent *e)
{
  if(d_timer->isActive())
    d_timer->stop();
  QWidget::hideEvent(e);
}

void KernelTableWidget::showEvent(QShowEvent *e)
{
  if(cbRefreshAuto->isChecked())
    enableAutoRefresh(cbRefreshAuto->isChecked());
  else /* just refresh once */
    QTimer::singleShot(300, this, SLOT(refresh()));
  QWidget::showEvent(e);
}

void KernelTableWidget::enableAutoRefresh(bool e )
{
  if(d_timer->isActive() && !e)
    d_timer->stop();
  if(!d_timer->isActive() && e)
  {
    d_timer->setInterval(d_timerInterval);
    d_timer->start();
  }

}

void KernelTableWidget::refreshIntervalChanged(int v)
{
  d_timerInterval = v * 1000;
  d_timer->setInterval(d_timerInterval);
}

void KernelTableWidget::setTableLabels(QStringList &labels)
{
  labels << "N.";
  tree->setColumnCount(labels.size());
  tree->setHeaderLabels(labels);
  cbFind->insertItems(0, labels);
}

void KernelTableWidget::treeItemEntered(QTreeWidgetItem *it, int c)
{
  QList<QTreeWidgetItem *>selItems = tree->selectedItems();
  if(selItems.size() == 0)
    treeItemInfoRequest(it, c);
}



