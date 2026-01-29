#include "html_snatItem_formatter.h"


HtmlSnatItemFormatter::HtmlSnatItemFormatter(const QTreeWidgetItem* it)
{
  d_html = "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.1//EN\" \"http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd\">"
  "<html xmlns=\"http://www.w3.org/1999/xhtml\">"
  "<link rel=\"stylesheet\" href=\"info.css\" type=\"text/css\" />" 
  "<head><title></title>"
  "<style type=\"text/css\">p,li {font-size:10pt; } body {background-color:rgb(158,183,201); }"
  " ul {background-color:rgb(148,199,235); } </style>"
  "</head>"
  "<body>";
  
  d_html += "<p>";
  
  d_html += QString("<h3>Source nat table summary</h3>");
  
  d_html += QString("<ul><li>Direction: <em>%1</em></li><li>protocol: <em>%2</em></li><li>source address: <a href="
    "\"action://resolvesip%3\" title=\"Resolve source ip\">%4</a></li>").arg(it->text(DIR)).arg(it->text(PROTO)).arg(it->text(SA)).
    arg(it->text(SA));
  
  if(it->text(SA) == it->text(NEWSA))
    d_html += "<li>source address is <em>not changed</em> by the rule</li>";
  else
    d_html += QString("<li><em>new</em> source address: <a href=\"action://resolvenewsip%1\" title=\"Resolve new source address\">%2</a></li>").
    arg(it->text(NEWSA)).arg(it->text(NEWSA));
    
  d_html += QString("<li>source port: <a href=\"action://resolvesport%1\" title=\"Click to obtain service name\">%2</a></li>").
    arg(it->text(SP)).arg(it->text(SP));
    
  if(it->text(SP) == it->text(NEWSP))
    d_html += "<li>source port <em>not changed</em> by the rule</li>";
  else
    d_html += QString("<li><em>new</em> source port: <a href=\"action://resolvesport%1\" title=\"Click to obtain service name\">%2</a></li>").
    arg(it->text(NEWSP)).arg(it->text(NEWSP));
    
  
  d_html += QString("<li>destination address: <a href=\"action://resolvedip%1\" title=\"Resolve destination address\">%2</a></li>").
    arg(it->text(DA)).arg(it->text(DA));
    
  d_html += QString("<li>destination port: <a href=\"action://resolvedport%1\" title=\"Click to obtain service name\">%2</a></li>").
    arg(it->text(DP)).arg(it->text(DP));
    
  d_html += QString("<li>input interface: <em>%1</em></li><li>output interface: <em>%2</em></li><li>state: <em>%3</em></li>").
    arg(it->text(OUTIF)).arg(it->text(OUTIF)).arg(it->text(STATE));
    
  d_html += QString("<li>timeout: <em>%1</em></li>").arg(it->text(TIMEO));
  
  d_html += "</ul>";
  
  
  d_html += "</p>";
  
  d_html += "</body>";
  
  
}



