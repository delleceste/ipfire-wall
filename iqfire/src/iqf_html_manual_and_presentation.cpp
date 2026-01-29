#include "iqf_html_manual_and_presentation.h"
#include "iqf_message_proxy.h"
#include "iqf_navigation_history.h"
#include "iqfstats_proxy.h"
#include "iqfpolicy.h"
#include "iqfire.h"
#include <ipfire_structs.h>

#include <QStringList>
#include <QShowEvent>
#include <QTimer>
#include <QSettings>
#include <QFile>
#include <QLayout>
#include <QScrollBar>
#include <QtDebug>

IQFPresenter::IQFPresenter(QWidget *parent) : IQFTextBrowser(parent)
{
	
	QSettings s;
	QStringList paths = s.value("BROWSER_PATHS", BROWSER_DEFAULT_PATHS).
		toStringList();
	QLayout *lo = parent->layout();
	if(lo != NULL)
		lo->addWidget(this);
	setSearchPaths(paths);
	atHome = false;
	timer = new QTimer(this);
	timerInterval = s.value("SUMMARY_REFRESHER_TIMEOUT", 10).toInt() * 1000;
	timer->setSingleShot(false);
	connect(timer, SIGNAL(timeout()), this, SLOT(refreshHome()));
	setMouseTracking(false);
	startupPage = s.value("STARTUP_PAGE", 8).toInt();
	setObjectName("iqfire-wall Presenter and Manual Browser");
}

void IQFPresenter::loadHome(bool get_rules_nums)
{
	QString manHtml;
	QSettings s;
	char username[PWD_FIELDS_LEN];
	struct kstats_light statsl;
	
	if(isVisible() && atHome)
	{
		struct passwd* pwd;
		pwd = getpwuid(getuid() );
		if(pwd != NULL)
			strncpy(username, pwd->pw_name, PWD_FIELDS_LEN);
		else
			strncpy(username, "Error getting user name", PWD_FIELDS_LEN);
			
		manHtml  = IQFMessageProxy::msgproxy()->getMan("welcome");
		IQFStatsProxy::statsProxy()->getStatsLight(&statsl);
		
		manHtml.replace("$username$", QString(username));
		manHtml.replace("$allowed$", QString("%1").arg(statsl.allowed));
		manHtml.replace("$blocked$", QString("%1").arg(statsl.blocked));
		
		if(get_rules_nums)
		{
			QList<unsigned int> rn = Policy::instance()->rulesNumbers();
			/* rn contains: 1 number of denial rules, perm and translation */
			if(rn.size() >= 3)
			{
				denRNum = rn.at(0);
				accRNum = rn.at(1);
				trRNum = rn.at(2);
			}
		}
// 		else
// 			qDebug() << "not refreshing rules num";
		
		manHtml.replace("$denRulesNum$", QString("%1").arg(denRNum));
		manHtml.replace("$accRulesNum$", QString("%1").arg(accRNum));
		manHtml.replace("$trRulesNum$", QString("%1").arg(trRNum));
		
		QString startupMsg;
		if(startupPage == IQFIREmainwin::DOCBROWSER)
			startupMsg = "Next time <a href=\"action://startConsole\">" 
				" start directly with the console page </a>";
		else 
			startupMsg = "Next time <a href=\"action://startManual\">" 
					" start with this presentation page</a>";
			
		manHtml.replace("$startup_page$", startupMsg);
				
		
		setHtml(manHtml);
	}
}

void IQFPresenter::showEvent(QShowEvent *e)
{
	atHome = true;
	timer->start(timerInterval);
	loadHome(true);
// 	setSource(QUrl("action://home"));
	QWidget::showEvent(e);
}

void IQFPresenter::hideEvent(QHideEvent *e)
{
	atHome = false;
// 	qDebug() << "hide event: stopping timer";
	timer->stop();
	QWidget::hideEvent(e);
}

void IQFPresenter::refreshHome()
{
	if(atHome && isVisible())
	{
		int value = verticalScrollBar()->value();
		loadHome(false);
		verticalScrollBar()->setValue(value);
	}
// 	else
// 		qDebug() << "timeout: NOT reloadin home (home:" << atHome << 
// 				"visible: " << isVisible() << ")";
}

void IQFPresenter::setSource(const QUrl &name)
{
	QString url = name.toString();
	if(url.contains("action://") && url.contains("home", Qt::CaseInsensitive))
	{
		setOpenExternalLinks(false);
		atHome = true;
		loadHome(true);
		timer->start(timerInterval);
	}
	else if(!url.contains("action://"))
	{
		QString filteredUrl = name.toString();
		atHome = false;
		timer->stop();
		
		if(filteredUrl.contains("http://"))
		{
			/* do not do anything: links dispatcher
			 * will call the web browser with the help
			 * of QDesktopServices.
			 * We leave the page unchanged.
			 */
		}
		else
		{
			if(filteredUrl.contains("file://"))
				filteredUrl = filteredUrl.remove("file://");
			if(filteredUrl.contains("manual://"))
				filteredUrl = filteredUrl.remove("manual://");
			if(filteredUrl.contains("welcome"))
			{
			  atHome = true;
			  loadHome(true);
			}
			else
			  setHtml(IQFMessageProxy::msgproxy()->getMan(filteredUrl.remove(".html")));
		}
	}
}

void IQFPresenter::substitute(const QString &orig, const QString &subst)
{
  QString doc = toHtml();
  doc.replace(orig, subst);
  setHtml(doc);
}

	
