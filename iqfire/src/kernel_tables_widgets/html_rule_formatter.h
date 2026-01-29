#ifndef HTML_FORMATTER_FROM_RULE
#define HTML_FORMATTER_FROM_RULE

#include <QString>
#include <ipfire_structs.h>
#include <QTreeWidgetItem>

class HtmlRuleFormatter
{
  public:
    HtmlRuleFormatter(ipfire_rule& r, const QTreeWidgetItem*);
    QString toHtml() { return d_html; }
    
  private:
    QString d_html;
};


#endif

