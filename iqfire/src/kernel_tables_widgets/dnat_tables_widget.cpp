#include "dnat_tables_widget.h"
#include "table_interpreter.h"
#include "html_dnatItem_formatter.h"
#include <iqfnetlink.h>
#include <iqfwidgets.h>
#include <QStringList>

void DnatTablesThread::run()
{
  printf("refreshing dnat tables\n");
  d_elements.clear();
  IQFNetlinkControl* netc = IQFNetlinkControl::instance();
  int bytesRead = 0;
  struct dnat_info dnatinfo;
  command table_req;
  memset(&table_req, 0, sizeof(table_req));
  table_req.cmd = PRINT_DNAT_TABLE;
  memset(&dnatinfo, 0, sizeof(dnatinfo));
  
  if(netc->SendCommand(&table_req) > 0)
  {
    bytesRead = netc->ReadDnatTable(&dnatinfo);
    while((bytesRead > 0) && (dnatinfo.direction != PRINT_FINISHED))
    {
      TableInterpreter ti(&dnatinfo);
      QStringList list = ti.dnatToList();
      d_elements << list;
      memset(&dnatinfo, 0, sizeof(dnatinfo));
      bytesRead = netc->ReadDnatTable(&dnatinfo);
    }
  }
}

DnatTablesWidget::DnatTablesWidget(QWidget *parent) : KernelTableWidget(parent)
{
  QStringList labels;
  labels  << "DIR." << "PROTO" << "SRC ADDR." << "S.PORT" <<  "DST.ADDR" << "D.PORT" << "NEW D.ADDR" <<
    "NEW D.PORT" <<"IN IF" << "OUT IF" << "STATE" << "TIMEOUT" ;
  setTableLabels(labels);
  d_thread = new DnatTablesThread(this);
  d_thread->setObjectName("Dnat tables thread");
  connect(d_thread, SIGNAL(finished()), this, SLOT(threadFinished()));
}

void DnatTablesWidget::refresh()
{
  KernelTableWidget::refresh(); /* update QLabel text */
  d_thread->start();
}


void DnatTablesWidget::treeItemInfoRequest(QTreeWidgetItem *it, int col)
{
  Q_UNUSED(col);
  QString html;
  
  if(it->columnCount() > 12)
  {   
    HtmlDnatItemFormatter f(it);
    html = f.toHtml();
    IQFInfoBrowser::infoBrowser()->setHtml(html);
  }
}











