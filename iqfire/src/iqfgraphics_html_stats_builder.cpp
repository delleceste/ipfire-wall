#include <QString>
#include "iqfstats_proxy.h"
#include "iqfwidgets.h"
#include "iqf_message_proxy.h"
#include <ipfire_structs.h>
#include "iqfgraphics_scene.h"

QString RuleScene::buildHtmlStats(int direction)
{
	IQFStatsProxy *sp = IQFStatsProxy::statsProxy(this);
	QString s;
	QString h = "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n"
			"<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.1//EN\""
			"\"http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd\">\n";
	
	h += "<html xmlns=\"http://www.w3.org/1999/xhtml\">"
			"<link rel=\"stylesheet\" href=\"ruleview.css\" type=\"text/css\" />\n";
	
	h += "<body>";
	
	h += "<p>";
	
	h += "<style type=\"text/css\">";
			
	h += "ul"
			"{"
				"display:block;"
				"margin:2px;"
				"padding:1px;"
				"border-width:2px;"
			"}";
	
	h += "li"
			"{"
			"font-size:12px;"
			"}\n";
	h += "strong"
			"{"
			"font-size:12px;"
			"font-weight:bold;"
			"}\n";
	h += "p"
			"{"
			"border-width:1px;"
			"border-color:black;"
			"background-color:rgb(255, 240, 255);"
			"}\n";
		
	h += ".accepted"
			"{"
			"color:green;"
			"}";
	
	h += ".blocked"
			"{"
			"color:red;"
			"}";
	
	h += "</style>";
	
	switch(direction)
	{
		case IPFI_INPUT_PRE:
			
			
			s += "<ul class=\"rview_ul\">";
			
			s += QString("<li>Received: <strong>%1</strong></li>").arg(sp->pre());
			
			if(sp->badSumIn() != 0)
				s += QString("<li>Bad checksum:\n<strong>%1</strong> packets</li>").arg(sp->badSumIn());
			
			s += "</ul>";
			
			break;
		case IPFI_OUTPUT_POST:
			s += "<ul class=\"rview_ul\">";
			
			s += QString("<li><strong>%1</strong> left<br/>the machine</li>").arg(sp->post());
			
			
			s += "</ul>";
			break;
			
		case IPFI_FWD:
			
			s += "<ul class=\"rview_ul\">";
			
			if(sp->fwd() != 0)
			{
				s += QString("<li class=\"accepted\"><strong>%1</strong>"
						" accepted</li>").arg(sp->fwdAcc());
				s += QString("<li class=\"blocked\"><strong>%1</strong>"
						" blocked</li>").arg(sp->fwdDrop());
				if(sp->fwdAccImpl() != 0)
					s += QString("<li class=\"impl_accepted\"><strong>%1</strong>"
							" impl. accepted</li>").arg(sp->fwdAccImpl());
				if(sp->fwdDropImpl() != 0)
					s += QString("<li class=\"impl_blocked\"><strong>%1</strong>"
							" impl. blocked</li>").arg(sp->fwdDropImpl());
				
			}
			else
			{
				s += QString("<li><strong>%1</strong> packets processed</li>").arg(sp->fwd());
			}
					
			
			s += "</ul>";
			
			break;
			
		case IPFI_INPUT:
			s += "<ul class=\"rview_ul\">";
			
			if(sp->in() != 0)
			{
				s += QString("<li class=\"accepted\"><strong>%1</strong>"
						" accepted</li>").arg(sp->inAcc());
				s += QString("<li class=\"blocked\"><strong>%1</strong>"
						" blocked</li>").arg(sp->inDrop());
				if(sp->inAccImpl() != 0)
					s += QString("<li class=\"impl_accepted\"><strong>%1</strong>"
							" impl. accepted</li>").arg(sp->inAccImpl());
				if(sp->inDropImpl() != 0)
					s += QString("<li class=\"impl_blocked\"><strong>%1</strong>"
							" impl. blocked</li>").arg(sp->inDropImpl());
			}
			else
			{
				s += QString("<li><strong>%1</strong> packets processed</li>").arg(sp->in());
			}	
			s += "</ul>";
			
			break;
		case IPFI_OUTPUT:
			
			s += "<ul class=\"rview_ul\">";
			
			if(sp->in() != 0)
			{
				s += QString("<li class=\"accepted\"><strong>%1</strong>"
						" accepted</li>").arg(sp->outAcc());
				s += QString("<li class=\"blocked\"><strong>%1</strong>"
						" blocked</li>").arg(sp->outDrop());
				if(sp->outAccImpl() != 0)
					s += QString("<li class=\"impl_accepted\"><strong>%1</strong>"
							" impl. accepted</li>").arg(sp->outAccImpl());
				if(sp->outDropImpl() != 0)
					s += QString("<li class=\"impl_blocked\"><strong>%1</strong>"
							" impl. blocked</li>").arg(sp->outDropImpl());
			}
			else
			{
				s += QString("<li><strong>%1</strong> packets processed</li>").arg(sp->out());
			}		
			s += "</ul>";
			
			break;
	}
	
	h += s;
	
	h += "</p>";
	
	h += "</body>";
	h += "\n</html>";
	return h;
}

void RuleScene::itemHovered(const QString &url)
{
	if(url.contains("rulescene://") && url.contains("_out"))
	{
		IQFInfoBrowser::infoBrowser()->setHtml((IQFMessageProxy::msgproxy()->getInfo("rulesceneStatsOut")));
		IQFHelpBrowser::helpBrowser()->setHtml((IQFMessageProxy::msgproxy()->getHelp("rulesceneStatsOut")));
	}
	else if(url.contains("rulescene://") && url.contains("_in"))
	{
		IQFInfoBrowser::infoBrowser()->setHtml((IQFMessageProxy::msgproxy()->getInfo("rulesceneStatsIn")));
		IQFHelpBrowser::helpBrowser()->setHtml((IQFMessageProxy::msgproxy()->getHelp("rulesceneStatsIn")));
	}
	else if(url.contains("rulescene://") && url.contains("_fwd"))
	{
		IQFInfoBrowser::infoBrowser()->setHtml((IQFMessageProxy::msgproxy()->getInfo("rulesceneStatsFwd")));
		IQFHelpBrowser::helpBrowser()->setHtml((IQFMessageProxy::msgproxy()->getHelp("rulesceneStatsFwd")));
	}
}

void RuleScene::itemClicked(const QString &url)
{
	if(url.contains("rulescene://") && url.contains("_out"))
		emit showStatsOut();
	else if(url.contains("rulescene://") && url.contains("_in"))
		emit showStatsIn();
	else if(url.contains("rulescene://") && url.contains("_fwd"))
		emit showStatsFwd();
}


