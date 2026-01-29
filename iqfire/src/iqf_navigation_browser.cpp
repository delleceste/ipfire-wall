#include "iqfire.h"
#include "iqf_message_proxy.h"
#include "iqfstats.h"
#include "iqf_html_manual_and_presentation.h"
#include <QSettings>

void IQFIREmainwin::loadNavigationPanel()
{
	QSettings s;
	
	QStringList paths = s.value("BROWSER_PATHS", BROWSER_DEFAULT_PATHS).
			toStringList();
	qDebug() << "Search paths: " << paths;
	ui.textBrowserNavigation->setSearchPaths(paths);
	
	if(s.value("NAVIGATION_BROWSER_HTML_STATIC", false).toBool())
	{	
		QString info_path = IQFMessageProxy::msgproxy()->infoPath();
		QString filename = s.value("NAVIGATION_PANEL_HTML", 
		   QString("%1navigation_panel.html").arg(info_path)).toString();
	
		ui.textBrowserNavigation->setSource(QUrl(filename));
		qDebug() << "setting source for the navigation panel to :" << filename;
	}
	else
	{
		QString html = buildDynamicNavigationHtml();
		ui.textBrowserNavigation->setHtml(html);
	}
	
}

void IQFIREmainwin::reloadHtmlInNavigationPanel(int index)
{
	Q_UNUSED(index);
	QString html = buildDynamicNavigationHtml();
	ui.textBrowserNavigation->setHtml(html);
}

void IQFIREmainwin::reloadHtmlInNavigationPanel()
{
	reloadHtmlInNavigationPanel(-1);
}

QString IQFIREmainwin::buildDynamicNavigationHtml()
{
	QString s;
	int index;
	
	QString h = "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n"
			"<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.1//EN\""
			"\"http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd\">\n";
	
	h += "<html xmlns=\"http://www.w3.org/1999/xhtml\">"
			"<link rel=\"stylesheet\" href=\"navpanel.css\" type=\"text/css\" />\n";
	
	h += "<body>";
	
	/* build the html body */
	QString verbosity, nav;
	
	if(silentact->isChecked())
		verbosity = "verbose";
	else
		verbosity = "silent";
	
	s += "<p id=\"title\">iqfire-wall</p>\n";
	
	s += "<div class=\"section\">";
// 	s += "<h4 class=\"section\">Windows</h4>";
	
	s += "<p class=\"componentTitle\">\n";
	s += "Components </p>";
	
	s += "<p class=\"description\">";
	
	s += "Navigate through the firewall components choosing the "
		"desired element from the list below.";
	
	s += "</p>";
	s += "<ul class=\"list\">";
	
	index = ui.stackedWidgetMain->currentIndex();
	
	/* Console */
	if(index != 0)
		s += "<li ><a href=\"console\">Console</a></li>";
	else
		s += "<li class=\"currentItem\" title=\"The console is the window currently displayed.\">Console</li>";
	
// 	s += "<ul class=\"sublist\">";
	s += QString("<li class=\"sublist\" ><a href=\"%1\">%2</a> modality</li>").
		arg(verbosity).arg(verbosity);
	
	if(index != 2) /* console configuration */
	{
		s += "<li class=\"sublist\" title=\"Configure the console view: setup filters on the output\n"
		"or enable/disable service name resolution (for ports)\"><a href=\"consoleConfig\">"
		"Configure the console</a></li>";
	}
	else
	{
		s += "<li  class=\"sublist\" class=\"currentItem\" title=\"The current displayed page\">Filter view</li>";
		s += "<li  class=\"sublist\" class=\"currentItem\" title=\"The current displayed page\">Configure console</li>";
	}
	s += "</ul>";
	
	
	s += "<p>";
	
	
	s += "<ul>";
	
	/* statistics */
	if(index != 4)
		s += "<li><a href=\"stats\" title=\"A plot will show the statistics of the firewall\">Statistics</a></li>";
	else
		s += "<li class=\"currentItem\" title=\"The current displayed page.\n"
		"The plot shows the statistics of the firewall packet filtering.\">Statistics</li>";
	
	if(index != 3)
		s += "<li><a href=\"tree\" title=\"Here you will be able to navigate"
		"the ruleset through a tree\nview and to modify existing rules or to add new ones\">Setup Rules</a></li>";
	else
		s += "<li class=\"currentItem\" title=\"The current displayed page.\n"
		"Here you will be able to navigate the ruleset through a tree"
		"\nview and to modify existing rules or to add new ones\">Setup Rules</li>";
	
	if(index != 6)
		s += "<li><a href=\"view\" title=\"View a Linux Routing scheme and configure\n"
		"the firewall through it!\">A Rule View</a>...</li>";
	else
		s += "<li class=\"currentItem\" title=\"The current displayed page\">A Rule View...</li>";
	
	if(index != 5)
		s += "<li><a href=\"pendingRules\" title=\"The packets not yet authorized/blocked explicitly are memorized\n"
				"in a list that can be viewed and or edited here.\n"
		"New rules can be added starting from the elements of this list!\">Waiting for authorization</a></li>";
	else
		s += "<li class=\"currentItem\" title=\"The current displayed page\">Waiting for authorization</li>";
	
	if(index != 1)
		s += "<li><a href=\"notifiedPackets\" title=\"The packets notified by the firewall are memorized\n"
		"in a list that can be viewed here.\">Notified packets</a></li>";
	else
		s += "<li class=\"currentItem\" title=\"The current displayed page\">Notified packets</li>";
	
	
	s += "</ul>"; /* main list */
	
	
	
	s += "</p>";
	
	s += "</div>";
	
	s += "<div class=\"section\">";
	
	
	s += "<p class=\"componentTitle\">\n";
	s += "Documentation </p>";
	
	s += "<p class=\"description\">";
	
	s += "A set of documentation tools are available<br/>"
			"In particular, <em>info</em> and <em>help</em> panels "
			"provide <cite>online</cite> help for each element of the "
			"user interface";
	
	s += "</p>";		
	
	s += "<ul class=\"info\">";
	
	if(index != 8)
		s += "<li><a href=\"manual\">iqFirewall manual</a></li>";
	else
		s += "<li class=\"currentItem\" title=\"The current displayed page\">iqFirewall manual</li>";
	
	s += "<li><a href=\"showHelp\" title=\"Opens a help panel in place of the current navigation one.\n"
		"The help panel provides useful hints when you move the mouse\nover any "
		"item of the iqfire-wall's graphical user interface.\n"
		"Try it in conjunction with the info panel...\">Show iQfire help</a></li>\n";
	s += "<li><a href=\"showInfo\" title=\"Opens an informational panel in place of the current navigation one.\n"
			"The info panel provides useful information when you move the mouse\nover any "
			"item of the iqfire-wall's graphical user interface.\">Show info panel</a></li>";
	s += "</ul>";
	
	
	s += "</div>";
	
	h += s;
	
	h += "</body>";
	
	h += "</html>";
	
	return h;
}



