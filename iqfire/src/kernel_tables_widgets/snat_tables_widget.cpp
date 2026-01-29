#include "snat_tables_widget.h"
#include "table_interpreter.h"
#include "html_snatItem_formatter.h"
#include <iqfwidgets.h>
#include <iqfnetlink.h>
#include <QStringList>

void SnatTablesThread::run()
{
  printf("refreshing snat tables\n");
  d_elements.clear();
  IQFNetlinkControl* netc = IQFNetlinkControl::instance();
  int bytesRead = 0;
  struct snat_info snatinfo;
  command table_req;
  memset(&table_req, 0, sizeof(table_req));
  table_req.cmd = PRINT_SNAT_TABLE;
  memset(&snatinfo, 0, sizeof(snatinfo));
  
  if(netc->SendCommand(&table_req) > 0)
  {
    bytesRead = netc->ReadSnatTable(&snatinfo);
    while((bytesRead > 0) && (snatinfo.direction != PRINT_FINISHED))
    {
      TableInterpreter ti(&snatinfo);
      QStringList list = ti.snatToList();
      d_elements << list;
      memset(&snatinfo, 0, sizeof(snatinfo));
      bytesRead = netc->ReadSnatTable(&snatinfo);
    }
  }
}


SnatTablesWidget::SnatTablesWidget(QWidget *parent) : KernelTableWidget(parent)
{
  QStringList labels;
  labels  << "DIR." << "PROTO" << "SRC ADDR." << "S.PORT" << "NEW S.ADDR" <<
    "NEW S.PORT" << "DST.ADDR" << "D.PORT" << "OUT IF" << "STATE" << "TIMEOUT" ;
  setTableLabels(labels);
  d_thread = new SnatTablesThread(this);
  d_thread->setObjectName("Snat tables thread");
  connect(d_thread, SIGNAL(finished()), this, SLOT(threadFinished()));
}

void SnatTablesWidget::refresh()
{
  KernelTableWidget::refresh(); /* update QLabel text */
  d_thread->start();
}

void SnatTablesWidget::treeItemInfoRequest(QTreeWidgetItem *it, int col)
{
  Q_UNUSED(col);
  
  QString html;
  
  if(it->columnCount() > 12)
  {   
    HtmlSnatItemFormatter f(it);
    html = f.toHtml();
    IQFInfoBrowser::infoBrowser()->setHtml(html);
  }
}










