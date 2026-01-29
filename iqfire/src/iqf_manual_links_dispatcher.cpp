#include "iqfire.h"
#include <QString>
#include <QSettings>
#include <QDesktopServices>
#include "iqfwidgets.h"
#include "iqf_navigation_history.h"
#include "iqf_html_manual_and_presentation.h"
#include "iqfgraphics_scene.h"

void IQFIREmainwin::loadPresentationOnManualBrowser()
{
	
}

void IQFIREmainwin::performAction(const QUrl &url)
{
	QSettings s;
	QString act = url.toString().toLower();
	if(act.startsWith("action://"))
	{
		act.remove("action://");
		
		if(act == "showconsole")
			showPageConsole();
		else if(act == "showstats")
			showStats();
		else if(act == "showlogs")
			showLogsConsole();
		else if(act == "showconsolefilter")
			showConsoleSettings();
		else if(act == "showruleview")
			showRuleView();
		else if(act == "showruletree")
			showRuleTree();
		else if(act == "shownaturallanguage")
			showNaturalLanguage();
		else if(act == "showStats")
			showStats();
		else if(act == "showpendingrules")
			showPendingRules();
		else if(act == "shownotifiedpackets")
			showNotifiedPackets();
		else if(act == "silentmodality")
			enableSilentModality(true);
		else if(act == "verbosemodality")
			enableSilentModality(false);
		else if(act == "showhelppanel")
			showHelpPanel(true);
		else if(act == "hidehelppanel")
			showHelpPanel(false);
		else if(act == "showinfopanel")
			showInfoPanel(true);
		else if(act == "hideinfopanel")
			showInfoPanel(false);
		else if(act == "showconfigurationwidget")
			showConfigurationWidget();
		else if(act == "showstatetables")
			showKernelStateTables();
		else if(act == "showsnattables")
			showKernelSnatTables();
		else if(act == "showdnattables")
			showKernelDnatTables();
		else if(act == "showkernelstats")
			showKernelTableStats();
		else if(act == "home")
			showManual();
		/* rules from the links of the rulescene htmls */
		else if(act == "addpermissionin")
			rulescene->addPermissionIn();
		else if(act == "addpermissionout")
			rulescene->addPermissionOut();
		else if(act == "addpermissionfwd")
			rulescene->addPermissionFwd();
		
		else if(act == "adddenialin")
			rulescene->addDenialIn();
		else if(act == "adddenialout")
			rulescene->addDenialOut();
		else if(act == "adddenialfwd")
			rulescene->addDenialFwd();
		
		else if(act == "addmasquerade")
			rulescene->addMasquerade();
		else if(act == "adddnat")
			rulescene->addDNAT();
		else if(act == "addsnat")
			rulescene->addSNAT();
		else if(act == "addoutdnat")
			rulescene->addOutDNAT();
		
		else if(act == "startmanual")
		{
			s.setValue("STARTUP_PAGE", DOCBROWSER);
			presenter->setStartupPage(DOCBROWSER);
		}
		else if(act == "startconsole")
		{
			s.setValue("STARTUP_PAGE", CONSOLE);
			presenter->setStartupPage(CONSOLE);
		}
		else
			qDebug() << "The action " << act << " is not recognized.";
	}
	else if(act.startsWith("manual://"))
		openManualAtPage(url);
	else if(act.startsWith("http://"))
		QDesktopServices::openUrl(url);
	else if(sender() == presenter)
	{
		History::history()->add(url.toString());
		checkHistoryActionsStatus();
	}
}


void IQFIREmainwin::openManualAtPage(const QUrl &url)
{
	QString surl = url.toString();
	if(surl.startsWith("manual://"))
	{
		_history->add(surl);
		surl.remove("manual://");
		storeNavigationToolbarButtonsState();
		if(ui.stackedWidgetHelpOrStats->currentIndex() != 0)
			ui.stackedWidgetHelpOrStats->setCurrentIndex(0);
		ui.stackedWidgetMain->setCurrentIndex(DOCBROWSER);
		modifySidePanel(DOCBROWSER);
		/* history emits a signal when it changes. */;
		presenter->setSource(QUrl(surl));
	}
}

void IQFIREmainwin::actionFromManual(const QUrl &url)
{
	QString act = url.toString().toLower();

	if(act.startsWith("action://"))
	{
		performAction(url);
	}
	else
	{
		History::history()->add(url.toString());
		checkHistoryActionsStatus();
	}
	
}






