#include "iqfruletree.h"
#include <QtDebug>

QString IQFRuleTree::buildInfoHtml(QTreeWidgetItem *it, int col)
{
	int direction;
	QString tmp;
	QString sip = "any", dip = "any", sport = "any", dport = "any",
 interface = "any";
 QTreeWidgetItem* itdir = NULL, *itpol = NULL, *itown = NULL;
 
 IQFRuleTreeItem *iqfit = dynamic_cast<IQFRuleTreeItem *>(it);
 
 if(iqfit == NULL)
 {
	 qDebug() << "! IQFRuleTree::buildInfoHtml(): "
			 "unable to dynamic_cast IQFRuleTreeItem * into "
			 "IQFRuleTreeItem *";
	 return "error";
 }
 
//  if(!iqfit->ruleValid() || !iqfit->itemValid())
//  {
//    printf("\e[1;31m* item or associated rule invalid!\e[0m\n");
//    return "error: item invalid or associated rule invalid";
//  }
	
	
 if(iqfit->hasRule() && (itdir = iqfit->parent()) == NULL)
	 return "direction information is not available (item NULL)";
 if(iqfit->hasRule() && (itpol = itdir->parent()) == NULL)
	 return "policy information is not available (item NULL)";
 if(iqfit->hasRule() && (itown = itpol->parent() ) == NULL)
	 return "owner information is not available (item NULL)";

 /* html header is inserted through message proxy. No need to create header tags here */

 tmp += "<div id=\"content\">";
	
 tmp += "<style type=\"text/css\" rel=\"stylesheet\">";
 tmp += "img { float:right; border:10px; margin:5px; padding:10px; margin-bottom:4px; margin-right:10px; border:thin black solid;}";
 tmp += "#image { float:left; margin:5px; padding:10px; margin-bottom:4px; margin-right:10px; border:thin black solid;}";
 tmp += "#text { text-align:justify; float:right; margin:5px; padding:10px; }";
 tmp += ".resolved { color:rgb(100, 100, 255); }";
	
 if(!iqfit->ruleValid())
 {
	 tmp += "#ruleTitle { text-decoration:line-through; }";
	 tmp += ".rule_representation { background-color:rgb(255, 120, 120); }";
	 tmp += ".rule_fields > li { background-color:rgb(255, 120, 120); }";
	 tmp += ".error { color:red; text-decoration:underline; }";
 }
  tmp += "p, li, ul, a { font-family:\"Tahoma sans-serif verdana sans\"; font-size:9.5pt; }";
 tmp += "</style>";
	
	
	
 tmp += "<div id=\"image\">";
 tmp += QString("<img src=\"%1\" />").arg(iqfit->iconPath());
 tmp += "</div>";
	
 tmp += "<div id=\"text\">";
	
 switch(iqfit->type())
 {
	 case IQFRuleTreeItem::OWNER:
		 if(col != 0)
			 break;
		 tmp += QString("<p>The user <strong>%1</strong>"
				 "is the owner of the rules under this tree.</p>").arg(iqfit->text(0));
		 if(iqfit->text(0).toUInt() == getuid())
			 tmp += "<p>You can modify them.</p>\n"
					 "<p class=\"hint\">Click to <strong>view</strong> or <strong>modify</strong>"
					 " the items inside this folder.</p>";
		 else
			 tmp += "<p>You cannot modify them.</p>\n"
					 "<p class=\"hint\">Click to <strong>view</strong> the items inside this folder.</p>";
				
		 break;
			
	 case IQFRuleTreeItem::DIRECTION:
		 if(col != 0)
			 break;
		
		 tmp += QString("<p>The rules under this tree affect the "
				 "<strong>%1</strong> direction.</p>").arg(iqfit->text(0));
		 if(iqfit->itemOwner() == getuid())
			 tmp += QString("<p>Click to <strong>view</strong> or <strong>modify</strong> "
					 "the %1 rules.</p>\n").arg(iqfit->text(0));
		 else
			 tmp += QString("<p class=\"hint\">Click to <strong>view</strong> "
					 "the %1 rules.</p>\n").arg(iqfit->text(0));
		 break;
				
	 case IQFRuleTreeItem::POLICY:
		 if(col != 0)
			 break;
		 tmp += QString("<p>The rules under this tree pertain to the <strong>%1</strong> rules.</p>").arg
				 (iqfit->text(0));
		 if(iqfit->itemOwner() == getuid())
			 tmp += QString("<p class=\"hint\">You can drag a rule from the permission tree and "
					 "drop it into the denial one to turn it into a denial rule and viceversa</p>");
		 break;
			
	 case IQFRuleTreeItem::NAT:
	 case IQFRuleTreeItem::SNAT:
	 case IQFRuleTreeItem::DNAT:	
	 case IQFRuleTreeItem::OUTDNAT:	
	 case IQFRuleTreeItem::MASQ:
			
		 if(iqfit->columnCount() == 1)
		 {
			 tmp += QString("<p>The rules under this tree"
					 " pertain to the <strong>%1</strong> rules.</p>").arg
					 (iqfit->text(0));
			 break;	
		 }
		 else if(iqfit->columnCount() != columnCount())
			 break;
	 default:
			
		 tmp += QString("<h4 id=\"ruleTitle\" align=\"center\"><bold>Rule"
				 "\"%1\"</bold></h4>\n").arg(iqfit->text(0));
		if(iqfit->isNatural())
		{
		  tmp += QString("<h4 id=\"ruleNatural\" align=\"center\">Rule"
				 "\"This is a Natural language rule\"</h4>\n");
		}
		 tmp += "<p class=\"rule_representation\">";
		 tmp += "<ul class=\"rule_fields\">";
	
		 tmp += QString("<li class=\"policy\"><strong>%1 rule</strong></li>\n").arg(itpol->text(0));
		 tmp += QString("<li class=\"owner\"><cite>Owner: "
				 "</cite><strong>%1</strong></li>\n").arg(itown->text(0));
		 tmp += QString("<li class=\"direction\"><cite>Direction: "
				 "</cite><strong>%1</strong></li>\n").arg(itdir->text(0));
			
		 tmp += QString("<li><cite>Protocol: </cite><strong>%1</strong></li>\n").arg(iqfit->text(1));
			
		 if(iqfit->hasRule() && iqfit->ItemRule().nflags.src_addr && iqfit->ItemRule().nflags.src_addr == ONEADDR)
		 {
			 sip = iqfit->text(2);
			 sip = sip.remove(QRegExp("\\s+"));
			 if(iqfit->ItemRule().parmean.samean == SINGLE)
			 {
				 tmp += QString("<li><cite>Source IP:</cite>" "<a href=\"action://resolvesip%1\" "
					 " title=\"click to resolve the address\n"
					"into its internet name\">%2</a></li>\n").arg(sip).arg(sip);
			 }
			else if(iqfit->ItemRule().parmean.samean == DIFFERENT_FROM)
			{
			  tmp += QString("<li><cite>Source IP: </cite><strong>not</strong><a href=\"action://resolvesip%1\" "
			     "title=\"click to resolve the address\ninto the internet name\">%2</a></li>\n").
			     arg(sip.remove("!")).arg(sip.remove("!"));
			}
			else if(iqfit->ItemRule().parmean.samean == MULTI && sip.contains(','))
			{
			  QStringList ips = sip.split(",", QString::SkipEmptyParts);
			  tmp += QString("<li><cite>Source IPs:</cite> ");
			  for(int i = 0; i < MAXMULTILEN && i < ips.size(); i++)
			    tmp += QString("<a href=\"action://resolvesip%1\" "
			      "title=\"click to resolve the address\ninto the internet name\">%2</a>, ").arg(ips[i]).arg(ips[i]);
			  tmp.remove(tmp.length() - 2, 2); /* remove last ", " */
			  tmp += "</li>\n"; 
			}
			else if(iqfit->ItemRule().parmean.samean == MULTI_DIFFERENT)
			{
			  sip.remove("!"); /* remove ! */
			  QStringList ips = sip.split(",", QString::SkipEmptyParts);
			  tmp += QString("<li><cite>Source IPs <strong>different from</strong>:</cite> ");
			  for(int i = 0; i < MAXMULTILEN && i < ips.size(); i++)
			    tmp += QString("<a href=\"action://resolvesip%1\" "
			      "title=\"click to resolve the address\ninto the internet name\">%2</a>, ").arg(ips[i]).arg(ips[i]);
			  tmp.remove(tmp.length() - 2, 2); /* remove last ", " */
			  tmp += "</li>\n"; 
			}	
			 else
				 tmp += QString("<li><cite>Source IP:"
						 " </cite><strong>%1</strong></li>\n").arg(sip);
		 }
			
		 if(iqfit->hasRule() && iqfit->ItemRule().nflags.src_port)
		 {
			 sport = iqfit->text(4);
			 sport.remove(QRegExp("\\s+"));
			 if(iqfit->ItemRule().parmean.spmean == SINGLE)
				 tmp += QString("<li><cite>Source port: </cite><a href=\"action://resolvesport%1\""
				" title=\"click to find out the\ncorresponding service name\">%2</a></li>\n")
				.arg(sport).arg(sport);
			else if(iqfit->ItemRule().parmean.spmean == DIFFERENT_FROM)
			{
			  sport = sport.remove("!");
			   tmp += QString("<li><cite>Source port<strong> different from</strong>: </cite><a href=\"action://resolvesport%1\""
				" title=\"click to find out the\ncorresponding service name\">%2</a></li>\n")
				.arg(sport).arg(sport);
			}
			else if(iqfit->ItemRule().parmean.spmean == MULTI && sport.contains(','))
			{
			  QStringList sps = sport.split(',', QString::SkipEmptyParts);
			  tmp += QString("<li><cite>Source ports</cite>: ");
			  for(int i = 0; i < MAXMULTILEN && i < sps.size(); i++)
			    tmp += QString("<a href=\"action://resolvesport%1\" "
			       "title=\"click to find out the\ncorresponding service name\">%2</a>, ").arg(sps[i]).arg(sps[i]);
			  tmp.remove(tmp.length() - 2, 2); /* remove last ", " */
			  tmp += "</li>\n";
			}
			else if(iqfit->ItemRule().parmean.spmean == MULTI_DIFFERENT && sport.contains(','))
			{
			  sport = sport.remove("!");
			  QStringList sps = sport.split(',', QString::SkipEmptyParts);
			  tmp += QString("<li><cite>Source ports</cite> <strong>different from</strong>: ");
			  for(int i = 0; i < MAXMULTILEN && i < sps.size(); i++)
			    tmp += QString("<a href=\"action://resolvesport%1\" "
			       "title=\"click to find out the\ncorresponding service name\">%2</a>, ").arg(sps[i]).arg(sps[i]);
			  tmp.remove(tmp.length() - 2, 2); /* remove last ", " */
			  tmp += "</li>\n";
			}
			 else
				 tmp += QString("<li><cite>Source PORT:"
						 "</cite><strong>%1</strong></li>\n").arg(sport);
		 }
			
		 if(iqfit->hasRule() && iqfit->ItemRule().nflags.dst_addr && iqfit->ItemRule().nflags.dst_addr == ONEADDR)
		 {
			 dip = iqfit->text(3);
			  dip = dip.remove(QRegExp("\\s+"));
			 if(iqfit->ItemRule().parmean.damean == SINGLE)
				 tmp += QString("<li><cite>Destination IP:</cite>"
						 "<a href=\"action://resolvedip%1\" "
						 " title=\"click to resolve the address\n"
						 "into the internet name\">%2</a></li>\n")
						 .arg(dip).arg(dip);
			else if(iqfit->ItemRule().parmean.damean == DIFFERENT_FROM)
			{
			  tmp += QString("<li><cite>Destination IP: </cite><strong>not</strong><a href=\"action://resolvedip%1\" "
			     "title=\"click to resolve the address\ninto the internet name\">%2</a></li>\n").
			     arg(dip.remove("!")).arg(dip.remove("!"));
			}
			else if(iqfit->ItemRule().parmean.damean == MULTI && dip.contains(','))
			{
			  QStringList ipd = dip.split(",", QString::SkipEmptyParts);
			  tmp += QString("<li><cite>Destination IPs:</cite> ");
			  for(int i = 0; i < MAXMULTILEN && i < ipd.size(); i++)
			    tmp += QString("<a href=\"action://resolvedip%1\" "
			      "title=\"click to resolve the address\ninto the internet name\">%2</a>, ").arg(ipd[i]).arg(ipd[i]);
			  tmp.remove(tmp.length() - 2, 2); /* remove last ", " */
			  tmp += "</li>\n"; 
			}
			else if(iqfit->ItemRule().parmean.damean == MULTI_DIFFERENT && dip.contains(','))
			{
			  dip.remove("!"); /* remove ! */
			  QStringList ipd = dip.split(",", QString::SkipEmptyParts);
			  tmp += QString("<li><cite>Destination IPs <strong>different from</strong>:</cite> ");
			  for(int i = 0; i < MAXMULTILEN && i < ipd.size(); i++)
			    tmp += QString("<a href=\"action://resolvesip%1\" "
			      "title=\"click to resolve the address\ninto the internet name\">%2</a>, ").arg(ipd[i]).arg(ipd[i]);
			  tmp.remove(tmp.length() - 2, 2); /* remove last ", " */
			  tmp += "</li>\n"; 
			}
			 else
				 tmp += QString("<li><cite>Destination IP:"
						 " </cite><strong>%1</strong></li>\n").arg(dip);
		 }
			
		 if(iqfit->hasRule() && iqfit->ItemRule().nflags.dst_port)
		 {
			 dport = iqfit->text(5);
			 dport= dport.remove(QRegExp("\\s+"));
			 if(iqfit->ItemRule().parmean.dpmean == SINGLE)
			 {
				 tmp += QString("<li><cite>Destination PORT: </cite>"
						 "<a href=\"action://resolvedport%1\""
						 " title=\"click to find out the\n"
						 "corresponding service name\">%2</a></li>\n")
						 .arg(dport).arg(dport);
			 }
			else if(iqfit->ItemRule().parmean.dpmean == DIFFERENT_FROM)
			{
			  dport = dport.remove("!");
			   tmp += QString("<li><cite>Destination port<strong> different from</strong>: </cite><a href=\"action://resolvedport%1\""
				" title=\"click to find out the\ncorresponding service name\">%2</a></li>\n")
				.arg(sport).arg(sport);
			}
			else if(iqfit->ItemRule().parmean.dpmean == MULTI && dport.contains(','))
			{
			  QStringList dps = dport.split(',', QString::SkipEmptyParts);
			  tmp += QString("<li><cite>Destination ports</cite>: ");
			  for(int i = 0; i < MAXMULTILEN && i < dps.size(); i++)
			    tmp += QString("<a href=\"action://resolvedport%1\" "
			       "title=\"click to find out the\ncorresponding service name\">%2</a>, ").arg(dps[i]).arg(dps[i]);
			  tmp.remove(tmp.length() - 2, 2); /* remove last ", " */
			  tmp += "</li>\n";
			}
			else if(iqfit->ItemRule().parmean.dpmean == MULTI_DIFFERENT && dport.contains(','))
			{
			  dport = dport.remove("!");
			  QStringList dps = dport.split(',', QString::SkipEmptyParts);
			  tmp += QString("<li><cite>Destination ports</cite> <strong>different from</strong>: ");
			  for(int i = 0; i < MAXMULTILEN && i < dps.size(); i++)
			    tmp += QString("<a href=\"action://resolvedport%1\" "
			       "title=\"click to find out the\ncorresponding service name\">%2</a>, ").arg(dps[i]).arg(dps[i]);
			  tmp.remove(tmp.length() - 2, 2); /* remove last ", " */
			  tmp += "</li>\n";
			}			 
			else
				 tmp += QString("<li><cite>Destination port:"
						 "</cite><strong>%1</strong></li>\n").arg(dport);
		 }
			
		 /* interface */
		 if(iqfit->hasRule())
		 {
			 direction = iqfit->ItemRule().direction;
			 if(direction == IPFI_INPUT || direction == IPFI_INPUT_PRE ||
						 direction == IPFI_FWD)
			 {
				 if(iqfit->ItemRule().nflags.indev) 
					 tmp += QString("<li><cite>Input INTERFACE: "
							 "</cite><strong>%1</strong></li>\n").arg(iqfit->text(6));
				 else
					 tmp += QString("<li><cite>Input INTERFACE: "
							 "</cite><strong>any</strong></li>\n");
			 }
			 if(direction == IPFI_OUTPUT || direction == IPFI_OUTPUT_POST ||
						 direction == IPFI_FWD)
			 {
				 if(iqfit->ItemRule().nflags.outdev) 
					 tmp += QString("<li><cite>Output INTERFACE: "
							 "</cite><strong>%1</strong></li>\n").arg(iqfit->text(7));
				 else
					 tmp += QString("<li><cite>Output INTERFACE: "
							 "</cite><strong>any</strong></li>\n");
			 }
		 }
			
		 /* stateful */
		 if(iqfit->hasRule() && iqfit->ItemRule().state)
		 {
			 tmp += "<li>This rule <strong>keeps</strong> the "
					 "<a href=\"browserHelp://stateful_rules\" "
					 "alt=\"Help about stateful rules\">state</a></li>\n";
			 tmp += "<li>Click <a href=\"manual://stateful.html\">here</a> to learn "
					 "more about stateful rules.</li>";
		 }
		 
		 if(iqfit->hasRule() && iqfit->type() < IQFRuleTreeItem::NAT
				  && iqfit->ItemRule().notify)
			 tmp += "<li>A popup will <strong>notify</strong>"
					 " the rule when applied</li>\n";
			
		 if(iqfit->type() == IQFRuleTreeItem::DNAT)
		 {
			 if(iqfit->text(8) != "-")
				 tmp += QString("<li>New destination IP address:"
						 "<strong>%1</strong></li>\n").arg
						 (iqfit->text(8));
			 else
				 tmp += QString("<li>The ip address "
						 " will <strong>not</strong> be changed</li>\n");
			 if(iqfit->text(9) != "-")
				 tmp += QString("<li>New destination port:"
						 "<strong>%1</strong></li>\n").arg
						 (iqfit->text(9));
			 else
				 tmp += QString("<li>The destination port "
						 " will <strong>not</strong> be changed</li>\n");
		 }
		 else if(iqfit->type() == IQFRuleTreeItem::MASQ)
		 {
			 tmp += QString("<li>The network interface "
					 "<strong>%1</strong> will be masqueraded</li>\n").arg
					 (iqfit->text(7));
		 }
		 
		 tmp += "</ul>";
		 tmp += "</p>";

		 if(iqfit->hasRule() && iqfit->ItemRule().ip.protocol == 6 && iqfit->ItemRule().pkmangle.mss.enabled)
		 {
		   tmp += "<p><ul>";
		   tmp += "<strong>Note</strong>: ";
		   tmp += "<li>The rule will modify the <em>Maximum Segment Size</em> (MSS) of the "
		      "TCP packets during the <cite>three-way handshake</cite>.";
		   if(iqfit->ItemRule().pkmangle.mss.option == MSS_VALUE)
		     tmp += QString(" The MSS value will be set to <strong>%1</strong> bytes.").arg(iqfit->ItemRule().pkmangle.mss.mss);
		   else if(iqfit->ItemRule().pkmangle.mss.option == ADJUST_MSS_TO_PMTU)
		     tmp += " The MSS value will be adjusted to the <em>path MTU</em>.";
		   tmp += "</li></ul>";
		    tmp += "</p>";  
		 }
		 
		 if(iqfit->isNatural())
		 {
		   tmp += QString("<p>This rule derives from the <strong>natural language</strong> sentence "
		    "\"<em>%1</em>\".</p><p>You can see and modify the natural text rules <a href=\"action://shownaturallanguage\" "
		    "title=\"Go to the natural language editor\">clicking here</a></p>").arg(iqfit->associatedNaturalSentence());
		    tmp += "<p>To learn more about <strong>natural language</strong> read this "
					 "<a href=\"manual://natural_language\" "
					 "alt=\"Natural language manual page\">manual page</a>.</p>\n";
		 }
			
		 
		 break;
 }
	
 if(!iqfit->ruleValid())
 {
	 tmp += "<h4>Note</h4>";
	 tmp += "<p class=\"error\">The rule contains errors.</p>";
	 tmp += "<p>Look in the tree for items red-coloured and correct them!</p>";
	 tmp += QString("<p><ul><li>%1</li></ul></p>").arg(iqfit->invalidReason());
 }
 tmp += "</div>"; /* text */
 tmp += "</div>"; /* content */

 return tmp;
}
