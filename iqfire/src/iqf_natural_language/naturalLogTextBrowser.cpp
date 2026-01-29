#include "naturalLogTextBrowser.h"
#include <colors.h>
#include <macros.h>
#include <QScrollBar>

NaturalLogTextBrowser::NaturalLogTextBrowser(QWidget *parent) : IQFTextBrowser(parent)
{
  init();
}

void NaturalLogTextBrowser::init()
{
  d_html = "";
  setAcceptRichText(false);
  setAutoFormatting(false);
  d_header = "<html><head>";
  d_header += "<style type=\"text/css\" rel=\"stylesheet\">";
  d_header += "h3 { font-size:12pt; font-weight:bold; text-align:center; }";
  d_header += "ul, li { font-size:10pt; }";
  d_header += ".error { color:rgb(181, 0, 47); }";
  d_header += ".warning { color:rgb(186, 144, 192); }";
  d_header += ".ok { color:rgb(0, 151, 84); }";
  d_header += "a { color:rgb(0, 148, 213); }";
  d_header += "#legend { font-size:9pt;  } h4 {font-size:10pt; font-weight:bold; }";
  d_header += "</style>";
  d_header += "</head>\n<body>";
  d_header += "<div id=\"content\">\n";
  d_header += "<h3>Natural language processing messages</h3>\n<ul>";
  
  d_legend = "<div id=\"legend\">\n<h4>Legend:</h4>\n<ul>\n<li><span class=\"ok\">Green</span> elements: <strong>ok</strong> messages;</li>\n";
  d_legend += "<li><span class=\"warning\">dark violet</span> elements: <strong>warning</strong> messages: the corresponding rule was added,"
    " but you should check if it is correct in the <a href=\"action://showruletree\" title=\"check rule tree\">rule tree</a>;</li>\n";
  d_legend += "<li><span class=\"error\">red</span> elements: <strong>error</strong> messages: one or more natural rules might not have "
    "been added. Check in the <a href=\"action://showruletree\" title=\"check rule tree\">rule tree section</a> what rules are going "
    "to be added</li>\n</ul>\n</div><!-- id legend -->\n";
    
  d_closeList = "\n</ul>\n</div><!-- id content -->\n";
  d_closeHtml = "</body>\n</html><!-- end of document -->\n";
  
  d_html += d_header;
  d_html += d_closeList;
  d_html += d_legend;
  d_html += d_closeHtml;
  
  setHtml(d_html);
}

void NaturalLogTextBrowser::clear()
{
  QTextBrowser::clear();
  init();
}

void NaturalLogTextBrowser::update()
{
  d_html = d_header;
  foreach(QString s, d_messages)
    d_html += s;
  d_html += d_closeList;
  d_html += d_legend;
  d_html += d_closeHtml;
  setHtml(d_html);
  QScrollBar *sb = verticalScrollBar();
  sb->setValue(sb->maximum());
}

void NaturalLogTextBrowser::addOk(const QString &s)
{
  d_messages.push_back(QString("<li class=\"ok\">%1</li>").arg(s));
  update();
}

void NaturalLogTextBrowser::addWarning(const QString &w)
{
  d_messages.push_back(QString("<li class=\"warning\">%1</li>").arg(w));
  update();
}

void NaturalLogTextBrowser::addError(const QString &e)
{
  d_messages.push_back(QString("<li class=\"error\">%1</li>").arg(e));
  update();
}







