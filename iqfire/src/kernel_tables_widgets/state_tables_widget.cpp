#include "state_tables_widget.h"
#include "table_interpreter.h"
#include "html_rule_formatter.h"
#include <iqfnetlink.h>
#include <iqflog.h>
#include <iqfwidgets.h>
#include <iqfpolicy.h>
#include <QStringList>

void StateTablesThread::run()
{
  printf("refreshing state tables\n");
  d_elements.clear();
  IQFNetlinkControl* netc = IQFNetlinkControl::instance();
  int bytesRead = 0;
  struct state_info st;
  command table_req;
  memset(&table_req, 0, sizeof(table_req));
  table_req.cmd = PRINT_STATE_TABLE;
  memset(&st, 0, sizeof(st));
  if(netc->SendCommand(&table_req) > 0)
  {
    bytesRead = netc->ReadStateTable(&st);
    while((bytesRead > 0) && (st.direction != PRINT_FINISHED))
    {
      TableInterpreter ti(&st);
      QStringList list = ti.stateToList();
      d_elements << list;
      memset(&st, 0, sizeof(st));
      bytesRead = netc->ReadStateTable(&st);
    }
  }
}



StateTablesWidget::StateTablesWidget(QWidget *parent) : KernelTableWidget(parent)
{
  QStringList labels;
  labels  << "DIR." << "PROTO" << "SRC ADDR." << "S.PORT" << "DST ADDR" <<
    "D.PORT" << "IN IF" << "OUT IF" << "STATE" << "TIMEOUT" << "NAME" << "POS" << "OWNER";
  setTableLabels(labels);
  d_thread = new StateTablesThread(this);
  d_thread->setObjectName("State tables thread");
  connect(d_thread, SIGNAL(finished()), this, SLOT(threadFinished()));
}

void StateTablesWidget::refresh()
{
  KernelTableWidget::refresh(); /* update QLabel text */
  d_thread->start();
}

void StateTablesWidget::treeItemInfoRequest(QTreeWidgetItem *it, int col)
{
  Q_UNUSED(col);
  int rulePos;
  bool admin;
  QString html;
  ipfire_rule rule, nullrule;
  memset(&nullrule, 0, sizeof(nullrule));
  
  if(it->columnCount() > 12)
  {
    rulePos = it->text(11).toInt();
    admin = it->text(12) == "admin";
    rule = Policy::instance()->permissionRuleByPosition(rulePos, admin);
    
    if(memcmp(&rule, &nullrule, sizeof(rule))!= 0) /* a rule was found */
    {
      HtmlRuleFormatter rf(rule, it);
      html = rf.toHtml();
    }
    else
      html = QString("No rule for id/position %1").arg(rulePos);
    
    IQFInfoBrowser::infoBrowser()->setHtml(html);
  }
}










