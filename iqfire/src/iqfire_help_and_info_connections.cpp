
#include "iqfire.h"
#include "iqfruletree.h"
#include "iqfwidgets.h"

void IQFIREmainwin::createHelpAndInfoConnections()
{
	/* the info text browser can have links that can display help messages in the help
	* text browser.
	* The URL must begin with "browserHelp://"
	*/
	connect(IQFInfoBrowser::infoBrowser(), SIGNAL(anchorClicked(const QUrl&)), IQFHelpBrowser::helpBrowser(),
		SLOT(clickFromInfoLink(const QUrl&)));
	connect(IQFHelpBrowser::helpBrowser(), SIGNAL(anchorClicked(const QUrl&)), IQFHelpBrowser::helpBrowser(),
		SLOT(clickFromInfoLink(const QUrl&)));	
	
	/* must start with "manual://" to be accepted by openManualAtPage() */
// 	connect(IQFInfoBrowser::infoBrowser(), SIGNAL(anchorClicked(const QUrl&)),
// 		this, SLOT(openManualAtPage(const QUrl&)));
// 	connect(IQFHelpBrowser::helpBrowser(), SIGNAL(anchorClicked(const QUrl&)),
// 		this, SLOT(openManualAtPage(const QUrl&)));
	
	/* The info and help text browser can have associated:
	 * a) a generic action to perform on the user interface (change page in the 
	 *    stacked widget or open the manual widget at a certain page), or 
	 *    open an external link thanks to the QDesktopServices;
	 * b) open a file on the file system (file://) or resolve an IP or port
	 *    with IQFLittleResolverThread.
	 * * The following four connections realize the whole
	 */
	
	/* the following two perform actions as opening a manual page from the 
	 * help/info browser or changing a page on the main stacked widget..
	 * or anything else in void IQFIREmainwin::performAction(const QUrl &url)
	 */
	connect(IQFInfoBrowser::infoBrowser(), SIGNAL(anchorClicked(const QUrl&)),
		this, SLOT(performAction(const QUrl&)));
	connect(IQFHelpBrowser::helpBrowser(), SIGNAL(anchorClicked(const QUrl&)),
		this, SLOT(performAction(const QUrl&)));
	
	/* This calls setSource() on IQFTextBrowser, to load a file:// or 
	 * to resolve a service name or address (see IQFTextBrowser::setSource()
	 */
// 	connect(IQFInfoBrowser::infoBrowser(), SIGNAL(anchorClicked(const QUrl&)),
// 		this, SLOT(setSource(const QUrl&)));
// 	connect(IQFHelpBrowser::helpBrowser(), SIGNAL(anchorClicked(const QUrl&)),
// 		this, SLOT(setSource(const QUrl&)));
	
	connect(ruletree_filter, SIGNAL(infoChanged(QString)), IQFInfoBrowser::infoBrowser(),
		SLOT(setHtml(QString)));
	connect(ruletree_nat, SIGNAL(infoChanged(QString)), IQFInfoBrowser::infoBrowser(),
		SLOT(setHtml(QString)));
	connect(ruletree_filter, SIGNAL(helpChanged(QString)), IQFHelpBrowser::helpBrowser(),
		SLOT(setHtml(QString)));
	connect(ruletree_nat, SIGNAL(helpChanged(QString)), IQFHelpBrowser::helpBrowser(),
		SLOT(setHtml(QString)));
	
	
}
