#include "iqfstats_textbrowser.h"
#include <QString>
#include <QTimer>
#include <QSettings>
#include <QtDebug>
#include <QVBoxLayout>
#include <QDateTime>
#include <QScrollBar>


StatsText::StatsText(QWidget *parent) : QTextBrowser(parent)
{
	QSettings s;
// 	QLayout* lo = parent->layout();
// 	if(lo != NULL)
// 		lo->addWidget(this);
	QVBoxLayout *lo = new QVBoxLayout(parent);
	timer = new QTimer(this);
	timer->setSingleShot(false);
	interval = s.value("TEXTSTATS_REFRESH_INTERVAL", 5).toInt() * 1000;
	timer->setInterval(interval);
	connect(timer, SIGNAL(timeout()), this, SLOT(updateStats()));
	lo->addWidget(this);
}

void StatsText::updateStats()
{
	IQFStatsProxy* sp = IQFStatsProxy::statsProxy();
	struct kernel_stats ks = sp->getStats();
	QString s;
	int scrollVal;
	/* save and then restore the scrollbar value */
	QScrollBar* scrollb = verticalScrollBar();
	scrollVal = scrollb->value();
	
	float lost_percent = 0;
	float perc_in_drop = 0;
	float perc_in_drop_impl = 0;
	float perc_out_drop = 0;
	float perc_out_drop_impl = 0;
	float perc_fwd_drop = 0;
	float perc_fwd_drop_impl = 0;
	float perc_in_acc_impl = 0;
	float perc_out_acc_impl = 0;
	float perc_fwd_acc_impl = 0;

	/* hours, minutes, seconds and days */
	double hours, mins, days;
	time_t current_time;
	double secs_difftime;

	unsigned long long total = 0;

	total = ks.in_rcv + ks.out_rcv + ks.fwd_rcv +
			ks.pre_rcv + ks.post_rcv;

	/* update percentage */
	if( total != 0)
		lost_percent = (float)
				( ( ( (float) ks.total_lost / (float) total) ) * 100);
	else
		lost_percent = 0;

	QString h = "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n"
			"<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.1//EN\""
			"\"http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd\">\n";
	
	s += "<style type=\"text/css\">\n";
	s += "h3 { font-size:24px; font-weight:bold; text-decoration:underline; color:rgb(10,10,18);}\n";
	s += "h4 { font-size:18px; color:rgb(10,10,18); }\n";
	s += "ul, li { font-size:12pt; }\n";
	s += "h3 { font-size:24px; }";
	s += "</style>\n\n";
	
	s += "<div id=\"statsDiv\">";
	
	s += "<h3>Kernel statistics</h3>";
	
	s += "<div id=\"datetime\">";
	s += QString("<ul><li>Kernel module loaded on %1</li>").arg(QDateTime::
			fromTime_t(ks.kmod_load_time).toString());
	if(ks.policy == 0)
		s += QString("<li>The packets not matching any rule will be dropped.</li>");
	else
		s += QString("<li>The packets not matching any rule will be accepted.</li>");
	s += "</ul>";
	s += "</div>"; /* datetime div  */
	
	/* Calculate current time and the number of seconds elapsed between kernel module
	* loading time and now. Then calculate corresponding hours, minutes and seconds.
	*/
	time(&current_time);
	secs_difftime = difftime(current_time, ks.kmod_load_time);

	hours = secs_difftime/(3600);
	mins = secs_difftime/60;
	days = secs_difftime/(3600 * 24);
	
	s += "<div class=\"statistics\">";
	
	s += "<h4>Packets processed:</h4>\n";
	s += "<ul id=\"statsList\">\n";
	if(ks.in_rcv)
	{
		s += QString("<li> Input:\t<strong>%1</strong>\t[%2/day %3/h %4/min %5/s]</li>").
				arg(ks.in_rcv).arg((float)ks.in_rcv/days, 0 , 'f', 1).arg((float)ks.in_rcv/hours, 0 , 'f', 1).arg((float)ks.in_rcv/mins, 0 , 'f', 1).
				arg((float)ks.in_rcv/secs_difftime, 0 , 'f', 1);			
		s += "<ul id=\"statsDetails\">";
		perc_in_drop = (float) ks.in_drop / (float) ks.in_rcv * 100;
		perc_in_drop_impl = (float) ks.in_drop_impl / (float) ks.in_rcv * 100;
		perc_in_acc_impl = (float) ks.in_acc_impl / (float) ks.in_rcv * 100;
		s += QString("<li> Blocked: %1 [%2%]</li>").arg(ks.in_drop).arg((float)perc_in_drop, 0 , 'f', 1);
		
		if(ks.in_drop_impl > 0)
			s += QString("<ul id=\"statsImplicit\"><li>implicitly: %1 [%2%]</li></ul>")
					.arg(ks.in_drop_impl).arg((float)perc_in_drop_impl);
		s += QString("<li> Accepted: %1 [%2%]</li>").arg(ks.in_rcv - ks.in_drop).arg(
			     (float) 100 - perc_in_drop, 0 , 'f', 1);
		if(ks.in_acc_impl > 0)
			s += QString("<ul id=\"statsImplicit\"><li>implicitly: %1 [%2%]</li></ul>")
					.arg(ks.in_acc_impl).arg((float)perc_in_acc_impl, 0 , 'f', 3);
		s += "</ul>"; /* id="statsDetails" */
	}
	else
		s += QString("<li> Input:\t<strong>no</strong>\t packets received</li>");

	
	if(ks.out_rcv)
	{
		s += QString("<li> Output:\t<strong>%1</strong>\t[%2/day %3/h %4/min %5/s]</li>").
				arg(ks.out_rcv).arg((float)ks.out_rcv/days, 0 , 'f', 1).arg((float)ks.out_rcv/hours, 0 , 'f', 1).arg((float)ks.out_rcv/mins, 0 , 'f', 1).
				arg((float)ks.out_rcv/secs_difftime, 0 , 'f', 1);
		s += "<ul id=\"statsDetails\">";
		perc_out_drop = (float) ks.out_drop / (float) ks.out_rcv * 100;
		perc_out_drop_impl = (float) ks.out_drop_impl / (float) ks.out_rcv * 100;
		perc_out_acc_impl = (float) ks.out_acc_impl / (float) ks.out_rcv * 100;
		s += QString("<li> Blocked: %1 [%2%]</li>").arg(ks.out_drop).arg((float)perc_out_drop, 0 , 'f', 3);
		
		if(ks.out_drop_impl > 0)
			s += QString("<ul id=\"statsImplicit\"><li>implicitly: %1 [%2%]</li></ul>")
					.arg(ks.out_drop_impl).arg(perc_out_drop_impl);
		s += QString("<li> Accepted: %1 [%2%]</li>").arg(ks.out_rcv - ks.out_drop).arg(
			     (float) 100 - perc_out_drop, 0 , 'f', 1);
		if(ks.out_acc_impl > 0)
			s += QString("<ul id=\"statsImplicit\"><li>implicitly: %1 [%2%]</li></ul>")
					.arg(ks.out_acc_impl).arg((float)perc_out_acc_impl, 0 , 'f', 3);
		s += "</ul>"; /* id="statsDetails" */
	}
	else
		s += QString("<li> Output:\t<strong>no</strong>\t packets received</li>");
				
	if(ks.fwd_rcv)
	{
		
		s += QString("<li> Forward:\t<strong>%1</strong>\t[%2/day %3/h %4/min %5/s]</li>").
				arg(ks.fwd_rcv).arg((float)ks.fwd_rcv/days, 0 , 'f', 1).arg((float)ks.fwd_rcv/hours, 0 , 'f', 1).arg((float)ks.fwd_rcv/mins, 0 , 'f', 1).
				arg((float)ks.fwd_rcv/secs_difftime, 0 , 'f', 1);
		s += "<ul id=\"statsDetails\">";
		perc_fwd_drop = (float) ks.out_drop / (float) ks.out_rcv * 100;
		perc_fwd_drop_impl = (float) ks.out_drop_impl / (float) ks.out_rcv * 100;
		perc_fwd_acc_impl = (float) ks.out_acc_impl / (float) ks.out_rcv * 100;
		s += QString("<li> Blocked: %1% [%2%]</li>").arg(ks.out_drop).arg(perc_fwd_drop, 0 , 'f', 1);
		
		if(ks.fwd_drop_impl > 0)
			s += QString("<ul id=\"statsImplicit\"><li>implicitly: %1 [%2%]</li></ul>")
					.arg(ks.fwd_drop_impl).arg((float)perc_fwd_drop_impl, 0 , 'f', 1);
		s += QString("<li> Accepted: %1% [%2%]</li>").arg(ks.fwd_rcv - ks.fwd_drop).arg(
			     (float) 100 - perc_fwd_drop, 0 , 'f', 1);
		if(ks.fwd_acc_impl > 0)
			s += QString("<ul id=\"statsImplicit\"><li>implicitly: %1 [%2%]</li></ul>")
					.arg(ks.fwd_acc_impl).arg((float)perc_fwd_acc_impl, 0 , 'f', 1);
	}
	else
		s += QString("<li> Forward:\t<strong>no</strong>\t packets received</li>");

	s += "</ul>";
	s += "<ul>";
	
	if(ks.pre_rcv)
		s += QString("<li> Pre routing:\t<strong>%1</strong>\t[%2/day %3/h %4/min %5/s]</li>").
				arg(ks.pre_rcv).arg(ks.pre_rcv/days).arg(ks.pre_rcv/hours, 0 , 'f', 1).arg(ks.pre_rcv/mins, 0 , 'f', 1).
				arg(ks.pre_rcv/secs_difftime, 0 , 'f', 1);
	else
		s += QString("<li> Pre routing:\t<strong>no</strong>\t packets received</li>");
	
	if(ks.post_rcv)
		s += QString("<li> Post routing:\t<strong>%1</strong>\t[%2/day %3/h %4/min %5/s]</li>").
				arg(ks.post_rcv).arg((float)ks.post_rcv/days, 0 , 'f', 1).arg(ks.post_rcv/hours, 0 , 'f', 1).arg(ks.post_rcv/mins, 0 , 'f', 1).
				arg(ks.post_rcv/secs_difftime, 0 , 'f', 1);
	else
		s += QString("<li> Post routing:\t<strong>no</strong>\t packets received</li>");
	
	s += "</ul>";
	s += "<ul>";

	s += QString("<li id=\"total\"> <strong>Total<strong>:\t<strong>%1</strong>\t[%2/day %3/h %4/min %5/s]</li>").
			arg(ks.post_rcv).arg(ks.post_rcv/days, 0 , 'f', 1).
			arg(ks.post_rcv/hours, 0 , 'f', 1).arg(ks.post_rcv/mins, 0 , 'f', 1).
			arg(ks.post_rcv/secs_difftime, 0 , 'f', 1);
	
	s += "</ul>"; /* statsList */
	
	s += "<ul id=\"userspaceStats\">";
	s += QString("<li>Packets <strong>sent</strong> to the userspace firewall: %1</li>").arg(ks.sent_tou);
	s += QString("<li>Packets <strong>not sent</strong> to the userspace firewall: %1</li>").arg(total - ks.sent_tou);
	s += QString("<li>Packets <strong> not sent</strong> to the userspace firewall"
		" due to the <cite>kernel/user</cite><strong> log level</strong>: %1</li>").arg(ks.not_sent);
	s += "</ul>"; /* userspaceStats */
	
	if(ks.pre_rcv != 0 && ks.bad_checksum_in > 0)
	{
		s += QString("<ul class=\"preRoutingChecks\">");
		s += "<p>Pre routing checks found:</p>";
		s += QString("<li>%1 packets with checksum errors over %2 arrived [%2%]</li>").arg(
			     ks.pre_rcv).arg((float) ks.bad_checksum_in / (float) ks.pre_rcv * (float) 100, 0 , 'f', 1);
		s += "</ul>";
	}
	
	s += "</div>"; /* id=\"statistics\" */
	
	s += "</div>"; /* statsDiv */
	
	h += s;
	
	h += "\n</html>";
	
	setHtml(h);
	
	/* restore the scrollbar value */
	scrollb->setValue(scrollVal);
}

/* Activate the statistics read only when shown */
void StatsText::showEvent(QShowEvent *e)
{
	updateStats();
	timer->start(interval);
	QWidget::showEvent(e);
}

void StatsText::hideEvent(QHideEvent *e)
{
	timer->stop();
	QWidget::hideEvent(e);
}




