#include "iqf_notifier_widget.h"
#include "iqf_utils.h"
#include <QLabel>
#include <QPushButton>
#include <QVBoxLayout>
#include <QSettings>
#include <QTimer>
#include <QTextBrowser>
#include <QPoint>
#include <QtDebug>
#include <QPalette>
#include "resolver_proxy.h"
#include "colors.h"
#include <arpa/inet.h> /* for IPPROTO_TCP & co */

IQFNotifierWidget::IQFNotifierWidget(QWidget *parent) : QWidget(parent)
{
	QSettings s;
	setMouseTracking(true);
	timerInterval = s.value("NOTIFY_WIDGET_TIMEOUT", 5).toInt() * 1000;
	resolve_enable = s.value("MATCH_RESOLVE_ENABLE", true).toBool();
// 	setWindowFlags(Qt::FramelessWindowHint);
	setWindowFlags(Qt::ToolTip);
	setAttribute(Qt::WA_QuitOnClose, false);
	text = new NotifierTextBrowser(this);
	QVBoxLayout *lo = new QVBoxLayout(this);
	lo->addWidget(text);
	lo->setMargin(3);
	text->setFrameShape(QFrame::NoFrame);
	connect(text, SIGNAL(anchorClicked(const QUrl&)), this, SLOT(acknowledged(const QUrl&)));
	timer = new QTimer(this);
	timer->setSingleShot(true);
	timer->setInterval(timerInterval);
	connect(timer, SIGNAL(timeout()), this, SLOT(hide()));
	
	locked = false;
}

void IQFNotifierWidget::changeTimeout(int secs)
{
	QSettings s;
	s.setValue("NOTIFY_WIDGET_TIMEOUT", secs);
	timerInterval = secs * 1000;
	timer->setInterval(timerInterval);
	qDebug() << "timer for the popup on match changed to: " << timerInterval/1000;
}

void IQFNotifierWidget::updateContents(QStringList &data)
{
	Q_UNUSED(data);
}
		

void IQFNotifierWidget::setResolveEnabled(bool en)
{
	QSettings s;
	resolve_enable = en;
	s.setValue("MATCH_RESOLVE_ENABLE", en);
}

void IQFNotifierWidget::closeEvent(QCloseEvent *e)
{
	qDebug() << "Close event";
	acknowledged(QUrl("close"));
	QWidget::closeEvent(e);
}		
		
/* if no data is passed, then the html is built from the internal 
* _data
*/		
QString IQFNotifierWidget::buildHtmlMessage(const QStringList &update)
{
	QString s, sip, dip, sport, dport;
	QString src_resolve_error, dst_resolve_error;
	
		
	/* format of data from iqf_rulematch_set.cpp, stringRepresentation(): 
	 * name, direction, proto, iface, saddr, sport, daddr, dport, response
	 */
	if(_data.size() < 9)
	{
		qDebug() << "! IQFNotifierWidget::buildHtmlMessage(): data size < 9!";
		s = "<h3>Error: data size too small!</h3>" + QString().number(_data.size());
		qDebug() << _data;
		return s;
	}
	else if(_data.size() >= 10)
	{
		if(_data.at(9).contains("ACCEPT"))
			setPalette(QPalette(KGREEN));
		else if(_data.at(9).contains("DROP"))
			setPalette(QPalette(KRED));
	}
	
	QString h = "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n"
			"<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.1//EN\""
			"\"http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd\">\n";
	
	h += "<html xmlns=\"http://www.w3.org/1999/xhtml\">";
	
	h += "<style type=\"text/css\">";

	h += "p { font-family:\"Tahoma sans-serif sans\"; font-size:8pt; margin:2px; padding:2px; }";
	h += "li { font-size:8pt; margin:2px; padding:2px; }";
	h += ".list_title { font-size:8pt; margin:2px; padding:2px; font-weight:bold; }";
	h += "a { font-size:8pt; text-align:right; margin:3px; padding:2px; }";
	h += "</style>";
	
	s = "<body><p align=\"center\">";
	
	s += QString("Rule \"%1\" applied [<a align=\"right\" href=\"close\">close</a>"
			" <a align=\"right\" href=\"lock\">lock</a>]").arg(_data[0]);
	
	if(update.isEmpty())
	{
		sip = _data[4];
		dip = _data[7];
		sport = _data[5];
		dport = _data[8];
	}
	else /* update with resolved if resolved info is different from the unresolved */
	{
		sip = update[0];
		if(sip != _data[4])
			sip += QString(" [%1]").arg(_data[4]);
		dip = update[1];
		if(dip != _data[7])
			dip += QString(" [%1]").arg(_data[7]);
		sport = update[2];
		if(sport != _data[5])
			sport += QString(" [%1]").arg(_data[5]);
		dport = update[3];
		if(dport != _data[8])
			dport += QString(" [%1]").arg(_data[8]);
	}
	
	s += "<ul align=\"left\">";
	if(_data.at(1).contains("IN"))
	{
		
		s += QString("<li class=\"list_title\">Packet arrived from %1 via %2</li>").arg(sip).arg(_data[3]);
		s += QString("<li>directed to port %1 on %2</li>").arg(dport).arg(dip);
		s += QString("<li>protocol %1</li>").arg(_data[2]);
		s += QString("<li>source port %1</li>").arg(sport);
	}
	else if(_data.at(1).contains("OUT"))
	{
		s += QString("<li class=\"list_title\" title=\"titolo prova\" alt=\"Prova alt\">Packet leaving for %1: %2</li>").arg(dip).arg(dport);
		s += QString("<li>from %1 via %2</li>").arg(sip).arg(_data[6]);
		s += QString("<li>protocol %1</li>").arg(_data[2]);
		s += QString("<li>source port %1</li>").arg(sport);
	}
	
	else if(_data.at(1).contains("FWD"))
	{
		s += QString("<li class=\"list_title\">Forwarding packet from %1 to %2</li>").arg(sip).arg(dip);
		s += QString("<li>interfaces: [%1]->[%2]</li>").arg(_data[3]).arg(_data[6]);
		s += QString("<li>protocol %1</li>").arg(_data[2]);
		s += QString("<li>destination port %1</li>").arg(dport);
		s += QString("<li>source port %1</li>").arg(sport);
	}
	
	s += "</ul>";
	s += "</p>";
	
// 	if(data.size() > 10 && (data.at(10).contains("error:")))
// 	{
// 		s += "<p id=\"resolve_information\">";
// 		s += "<ul class=\"resolve_information\">";
// 		s += "<li class=\"list_title\">Numeric ip:port info:</li>";
// 		QString resolveError;
// 		for(int i = 9; i < data.size(); i++)
// 		{
// 			if(data.at(i).contains("error:"))
// 			{
// 				if(resolveError != data.at(i))
// 				{
// 					resolveError = data.at(1);
// 					s += QString("<li title=\"There was an error resolving"
// 						" the IP address or port\">Name resolution error: %1</li>")
// 						.arg(data[i].remove("error:"));
// 				}
// 			}
// 			else if(data.at(i).contains("sip:")) /* if there is sip: there also is sport */
// 			{
// 				s += QString("<li title=\"The numeric source IP\">Source %1").
// 					arg(data[i]).remove("sip:");
// 			}
// 			else if(data.at(i).contains("sport:")) /* if there is sip: there also is sport */
// 			{
// 				s += QString(" :%1)</li>").
// 					arg(data[i].remove("sport:"));
// 			}
// 			else if(data.at(i).contains("dip:"))/* if there is dip: there also is dport */ 
// 			{
// 				s += QString("<li title=\"The numeric destination IP\">Destination %1").
// 					arg(data[i]).remove("dip:");
// 			}
// 			else if(data.at(i).contains("dport:"))
// 			{
// 				s += QString(" :%1)</li>").
// 					arg(data[i].remove("dport:"));
// 			}
// 			
// 		}
// 		s += "</ul>";
// 		s += "</p>";
// 	} /* if data.size() > 10 */
	
	
	
	
	
// 	s += "<a align=\"right\" href=\"close\">Ok</a>";
	
	s += "</body>";
	
	h += s;
	
	h += "\n</html>";
	
	return h;
}	
		
void IQFNotifierWidget::updateMessageWithResolved(const QString &key, const QStringList& resolved)
{	
	if(locked)
		return;
	if(key != d_currentResolveKey)
		return;
	QStringList resolvedData = resolved;
	QString html;
	html = buildHtmlMessage(resolvedData);
	text->setHtml(html);
	
	/* if updateMessageWithResolved() is called, it means that the 
	 * resolver is enabled and that the popup is shown and waiting 
	 * for the timeout.
	 */
	if(isVisible())
	{
		timer->stop();
		timer->start();
	}
	else
	{
		move(popupPosition());
		timer->start();
		show();
		locked = false;
	}
}
		
void IQFNotifierWidget::showMessage(QStringList &data, QPoint &pos,
	const ipfire_info_t *info)
{
	if(locked)
	{
		qDebug() << "showMessage(): locked";
		return;
	}
	QString html, s;
	unsigned short sport = 0, dport = 0;
	
	data.removeFirst(); /* the date */
	/* Store the current message in _data. */
	_data = data;
	
	/* build and set html without resolving first */
	html = buildHtmlMessage();
	text->setHtml(html);
	
	if(resolve_enable) /* no popup shown now. It will be shown when resolved */
	{
		switch(info->protocol)
		{
			case IPPROTO_TCP:
				sport = info->transport_header.tcphead.source;
				dport = info->transport_header.tcphead.dest;
			break;
			case IPPROTO_UDP:
				sport = info->transport_header.udphead.source;
				dport = info->transport_header.udphead.dest;
				break;
			default:
				break; /* leave ports 0 */
		}
		/* do not start the timer to hide before we have resolved */
		IQFResolverProxy *resolver = IQFResolverProxy::resolver();
		d_currentResolveKey = QString("%1%2%3%4").arg(info->iphead.saddr).arg(info->iphead.daddr).
				arg(sport).arg(dport);
		connect(resolver, SIGNAL(resolved(const QString &, const QStringList&)), this,
			SLOT(updateMessageWithResolved(const QString &, const QStringList&)), Qt::DirectConnection);
		resolver->resolve(info->iphead.saddr, info->iphead.daddr, sport, dport);
		
		setPopupPosition(pos); /* remember the popup position! */
	}
	else /* show the popup with the information we have */
	{
		if(isVisible())
		{
			timer->stop();
			timer->start();
		}
		else
		{
			move(pos);
			timer->start();
			show();
			locked = false;
		}
	}
	
}

void IQFNotifierWidget::acknowledged(const QUrl& url)
{
	if(url.toString() == "close")
	{
		emit itemAck(_data);
		locked = false;
		hide();
	}
	else if(url.toString() == "lock")
	{
		locked = true;
		QString html = text->toHtml();
		html.replace("lock", "");
		/* remove the white space between close and ']' ;) */
		html.replace("</a> <a>", "</a><a>");
		text->setHtml(html);
	}
}

void IQFNotifierWidget::enterEvent(QEvent *e)
{
	Q_UNUSED(e);
	/* if the user goes with the mouse over the widget, do not close it! */
	timer->stop();
}











