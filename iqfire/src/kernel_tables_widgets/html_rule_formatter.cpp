#include "html_rule_formatter.h"
#include <rule_stringifier.h>

HtmlRuleFormatter::HtmlRuleFormatter(ipfire_rule& r, const QTreeWidgetItem* it)
{
  RuleStringifier rs(&r);
  QString sip, dip, dport, sport, inif, outif;
  d_html = "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.1//EN\" \"http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd\">"
  "<html xmlns=\"http://www.w3.org/1999/xhtml\">"
  "<link rel=\"stylesheet\" href=\"info.css\" type=\"text/css\" />" 
  "<head><title></title>"
  "<style type=\"text/css\">p,li {font-size:10pt; } body {background-color:rgb(250,250,255); }"
  " ul {background-color:rgb(148,199,235); } </style>"
  "</head>"
  "<body>";
  
  d_html += QString("<h3>Rule associated with table</h3>");
  
  d_html += QString("<h4 \"text-align:center\">Name: \"<strong>%1</strong>\"</h4>").arg(rs.Name());
  
  d_html += "<p>";
  
  d_html += "<ul>";
  
  d_html += QString("<li>Current state: <strong>%1</strong></li>").arg(it->text(8));
  
  d_html += QString("<li>protocol: <strong>%1</strong></li>").arg(rs.Proto());
  sip = rs.Sip();
  if(sip != "-")
    d_html += QString("<li>source IP address: <a href=\"action://resolvesip%1\">%2</a></li>").arg(sip).arg(sip);
  sport = rs.Sport();
  if(sport != "-")
    d_html += QString("<li>source port: <a href=\"action://resolvesport%1\">%2</a></li>").arg(sport).arg(sport);
  
  
  dip = rs.Dip();
  if(dip != "-")
    d_html += QString("<li>destination IP address: <a href=\"action://resolvedip%1\">%2</a></li>").arg(dip).arg(dip);
  dport = rs.Dport();
  if(dport != "-")
	d_html += QString("<li>destination port: <a href=\"action://resolvedport%1\">%2</a></li>").arg(dport).arg(dport);
  
  inif = rs.InDev();
  if(inif != "-")
    d_html += QString("<li>input device: <strong>%1</strong></li>").arg(inif);
  
  outif = rs.OutDev();
  if(outif != "-")
    d_html += QString("<li>output device: <strong>%1</strong></li>").arg(outif);
  
  d_html += "</ul>";
  
  d_html += "</p>";
  
  d_html += "<p>";
  
  d_html += QString("<h3>Item summary</h3>");
  
  d_html += QString("<ul><li>Direction: <em>%1</em></li><li>protocol: <em>%2</em></li><li>source address: <a href="
    "\"action://resolvesip%3\" title=\"Resolve source ip\">%4</a></li>").arg(it->text(0)).arg(it->text(1)).arg(it->text(2)).
    arg(it->text(2));
  
  d_html += QString("<li>source port: <a href=\"action://resolvesport%1\" title=\"Click to obtain service name\">%2</a></li>").
    arg(it->text(3)).arg(it->text(3));
 
  d_html += QString("<li>destination address: <a href=\"action://resolvedip%1\" title=\"Resolve destination address\">%2</a></li>").
    arg(it->text(4)).arg(it->text(4));
    
  d_html += QString("<li>destination port: <a href=\"action://resolvedport%1\" title=\"Click to obtain service name\">%2</a></li>").
    arg(it->text(5)).arg(it->text(5));
    
  d_html += QString("<li>input interface: <em>%1</em></li><li>output interface: <em>%2</em></li><li>state: <em>%3</em></li>").
    arg(it->text(6)).arg(it->text(7)).arg(it->text(8));
    
  d_html += QString("<li>timeout: <em>%1</em></li>").arg(it->text(9));
  
  d_html += "</ul>";
  
  
  d_html += "</p>";
  
  d_html += "</body>";
  
  
}



