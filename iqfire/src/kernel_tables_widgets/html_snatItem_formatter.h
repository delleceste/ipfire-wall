#ifndef HTML_FORMATTER_FROM_SNAT
#define HTML_FORMATTER_FROM_SNAT

#include <QString>
#include <QTreeWidgetItem>

class HtmlSnatItemFormatter
{
  public: 
    enum fields { DIR = 0, PROTO, SA, SP, NEWSA, NEWSP, DA, DP, OUTIF, STATE, TIMEO };
    HtmlSnatItemFormatter(const QTreeWidgetItem*);
    QString toHtml() { return d_html; }
    
  private:
    QString d_html;
};


#endif