#ifndef IQFIRE_H
#define IQFIRE_H

#include <QApplication>
#include <KApplication>
#include <KMainWindow>
#include <KXmlGuiWindow>

#include <kparts/mainwindow.h>
#include <QWidget>
#include <ui_iqfire.h>

#include <QSystemTrayIcon>
#include <QSettings>

#include <ipfire_structs.h>  

#include "widget_konsole.h"
#include "iqflog.h"
#include "iqfiredata.h"
#include "iqfpolicy.h"
#include "iqfnetlink.h"
#include "iqfinit.h"
#include "colors.h"
#include <macros.h>

#define DEFAULT_ICON_PATH QString("/usr/share/iqfire/icons/")
#define ICON_PATH  s.value("ICON_PATH", DEFAULT_ICON_PATH).toString()

		


extern "C"
{
	/* Returns the translated string langline, 
 * declared global so not destroyed at the
 * end of the function execution.
 */
char* translation(const char* eng);

#define TR(eng) (translation(eng) )

}


class QSystemTrayIcon;
class RuleScene;
class IQFRuleTree;
class IQFSysTray;
class WPendingRules;
class History;
class IQFStats;
class IQFConfig;
class IQFPresenter;
class IQFTrafficProxy;
class IQFUpdates;
class NaturalWidget;
class NaturalUpdatesManager;

class IQFIREmainwin : public KMainWindow
{
	Q_OBJECT

	public:

	enum pages { CONSOLE, NOTIFIED_PACKETS, CONF_CONSOLE, TREEVIEW, STATS, NATURAL_LANGUAGE,
		PENDING_RULES, GRAPHICSVIEW, SETTINGS, DOCBROWSER, STATE_TABLES, SNAT_TABLES, DNAT_TABLES,
		KMEMORY, LOGS };
		
	static IQFIREmainwin * instance(QWidget* p = NULL, int argc = 0, char **argv = NULL);
	
	~IQFIREmainwin();
	
	QString toFilterString();
	
	IQFSysTray *systemTrayIcon() { return trayIcon; }

	public slots:
		void setCurrentPage(int n);
		void setCurrentPage(QWidget *widget);
		void showPageConsole();
		void showLogsConsole();
		void showConsoleSettings();
		void showRuleView();
		void showRuleTree();
		void showStats();
		void showNaturalLanguage();
		void showPendingRules();
		void showNotifiedPackets();
		void showKernelStateTables();
		void showKernelSnatTables();
		void showKernelDnatTables();
		void showKernelTableStats();
		void enableSilentModality(bool en);
		void showHelpPanel(bool);
		void showInfoPanel(bool);
		void showConfigurationWidget();
		void reloadSettings();
		/** tells the configuration widget to reload the settings 
		 * from the QSettings 
		*/
		void triggerReloadSettings(bool dummy);
		
		/* the following three are in iqf_manual_links_dispatcher.cpp */
		void performAction(const QUrl &url);
		/* particular case of performAction, when the slot is called
		 * by the manual.
		 */
		void actionFromManual(const QUrl &url);
		void loadPresentationOnManualBrowser();
		
		/* */
		
		void openManualAtPage(const QUrl &url);
		
		/* checks if the history has previous or next elements 
		* and disables/enables the corresponding icons on the 
		* toolBar.
		*/
		void checkHistoryActionsStatus();
		
		void disablePopupMatch(bool dis);
		void disablePopupUnknownConnections(bool dis);
		

	signals:
		void filterChanged(const QString &filter);
		
	protected:
		void resizeEvent(QResizeEvent * event);
		void hideEvent(QHideEvent *e);
		void changeEvent(QEvent *e);
		
	protected slots:
		void iconActivated(QSystemTrayIcon::ActivationReason reason);
		void QuitApplication();
		void closeEvent(QCloseEvent *);
		void logwidgetClosed();
		/* Connected to the toolBar action */
		void enableSilentFromToolBar(bool en);
		void showNATPart(bool show);
		void showLittleStats();
		void hideLittleStats();
		void showStatsSummary(bool);
		void showManual();
		
		/* For filter view */
		void viewProtocolChanged(int);
		void viewMoreClicked();
		void applyFilter(bool enable);
		void updateFilter();
		void viewDirectionChanged(int);
		void viewIPGBoxChanged(const QString &s);
		void viewPortsGBoxChanged(const QString &s);
		void viewIFGBoxChanged(const QString &s); 
		void reloadFilterInfo();/* end filter view */
		void reloadFilterInfo(const QString &);
		
		void navigationBrowserLinkClicked(const QString &link);
 		void showNavigationPanel(bool);
		void modifySidePanel(int page_index);
		void reloadHtmlInNavigationPanel(int page_index);
		void showFilterAction(int page);
		void reloadHtmlInNavigationPanel();
		
		void anotherInstanceDetected();
		
		/* history slots */
		void home();
		void back();
		void forward();
		
		void storeSplitterState(int page = 0);
		void searchInTree();
		void hideSearchWidgets();
		void showSearchWidgets();
		void activateSearchAction(int page);
		
		/** When the user changes page in the main window,
		 * we must show inside the help and info browser the
		 * correct updated pages.
		*/
		void infoAndHelpForPage(int page);
		
		void lookForUpdates();
		/* traffic watcher */
		void newTrafficIface(const QString&);
		
	private:
	    
		IQFIREmainwin(QWidget *parent, int argc, char **argv);
	  
		Ui::IQFIREmainwin ui;
		void CreateSystemTray();
		QByteArray splitterDefaultSize;
		IQFSysTray *trayIcon;
		Log* loginstance;
		IQFStats *iqfstats;
		IQFNetlinkControl *control; /* control handle to send commands */
		IQFireData* iqfdata_instance;
		Policy * iqfpolicy_instance;
		IQFInitializer *initializer_instance;
		void createConnections();
		void createSystrayConnections();
		void createHelpAndInfoConnections();
		void createToolBarActions();
		void loadNavigationPanel();
		QString buildDynamicNavigationHtml();
		void initSettingsForSidePanel();
		void storeNavigationToolbarButtonsState();
		void setupFilterInteraction();
		void changePageByHistory(int page);
		void setupIconsForActions();
		void setupButtonIcons();
		void saveToolbarStatus();
		
		
		/* Actions which must be visible to all the class methods */
		QAction *configureact, *silentact, *navigationPanelAct,
  			*infoPanelAct, *helpPanelAct, *backAct, *forwardAct, *filterAction;

		/* Rule scene */
		RuleScene *rulescene;
		IQFWidgetKonsole  *console;
		IQFRuleTree* ruletree_filter, *ruletree_nat;
		NaturalWidget *naturalWidget;
		WPendingRules* pending_rules_widget;
		IQFPresenter* presenter;
		
		History *_history;
		/* when we show the statistics plot into the help/stats stacked 
		 * widget, in the rule view, we memorize if the help was shown
		 * before viewing the stats.
		 */
		bool help_was_shown;
		/* the first time the user minimizes or closes the main window,
		 * we tell him that the window has been iconified in the system tray.
		 */
		bool neverMinimized, neverClosed;
		
		IQFConfig *iqfconf;
		IQFTrafficProxy * traffic;
		IQFUpdates *updates;
		NaturalUpdatesManager *naturalUpdManager;
		
		bool d_shuttingDown;
		
		static IQFIREmainwin *_instance;
		
	private slots:
		
		/* when outside a block, restore info and help */
		void infoAndHelpForRuleScene();	
		void blockInterfaceWhileAddingRule(bool block);
		void about();
		void enableUpdateFilterButton();
		void updateWindowTitle(int page);
};

#endif
