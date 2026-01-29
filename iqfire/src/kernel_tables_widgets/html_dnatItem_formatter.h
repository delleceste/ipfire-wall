#ifndef HTML_FORMATTER_FROM_DNAT
#define HTML_FORMATTER_FROM_DNAT

#include <QString>
#include <QTreeWidgetItem>

class HtmlDnatItemFormatter
{
  public:
  enum fields { DIR = 0, PROTO, SA, SP,  DA, DP, NEWDA, NEWDP, INIF, STATE, TIMEO };
    HtmlDnatItemFormatter(const QTreeWidgetItem*);
    QString toHtml() { return d_html; }
    
  private:
    QString d_html;
};


#endif