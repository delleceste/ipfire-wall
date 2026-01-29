#include "iqfire.h"
#include "iqfinit.h"
#include "iqfgraphics_scene.h"
#include "iqfruletree.h"
#include "iqfstats_proxy.h"
#include "iqfstats.h"
#include "iqfsystray.h"
#include "iqf_utils.h"
#include "iqf_pending_rules.h"
#include "iqf_message_proxy.h"
#include "iqf_navigation_history.h"
#include "iqf_notifier_widget.h"
#include "iqf_splash.h"
#include "iqfstats_textbrowser.h"
#include "iqfconfig.h"
#include "iqf_html_manual_and_presentation.h"
#include "iqf_updates.h"
#include "iqfire_confdir.h"
#include "iqf_traffic_proxy.h"
#include "iqf_traffic_widget.h"
#include "resolver_proxy.h"
#include "stats/kernel_tables_stats.h"
#include <naturalWidget.h>
#include <naturalRuleHash.h>
#include <naturalLogTextBrowser.h>
#include <naturalUpdatesManager.h>
#include <state_tables_widget.h>
#include <snat_tables_widget.h>
#include <dnat_tables_widget.h>

#include <QMessageBox>
#include <QtDebug>
#include <QCloseEvent>
#include <QSettings>
#include <QVariant>
#include <QTimer>
#include <QDate>

IQFIREmainwin* IQFIREmainwin::_instance = NULL;

IQFIREmainwin * IQFIREmainwin::instance(QWidget* p, int argc, char **argv)
{
  if(_instance == NULL)
  {
    _instance = new IQFIREmainwin(p, argc, argv);
  }
  return _instance;
}

IQFIREmainwin::IQFIREmainwin(QWidget* p, int argc, char **argv)
{
  
  Q_UNUSED(p);
  QSettings s;
  QString initMsg, qtstyle;
  int steps = 0;
  d_shuttingDown = false;
  
  /* initialize the configuration widget to null.
  * This will be created the first time it is requested when
  * changing the page of the main window.
  */
  iqfconf = NULL;
  /* the same for the presenter */
  presenter = NULL;
  
  /* splash screen */
  IQFSplash *splash = IQFSplash::splashScreen(0);
  splash->setSteps(16);
  setObjectName("MainWindow");
  
   /* Setup the interface */
  splash->newStep("Setting up the iQfirewall graphical user interface...", ++steps);
  ui.setupUi(this);
  
  splash->newStep("Setting the stylesheet...", ++steps);
  if(s.value("QT_DEFAULT_STYLE", true).toBool())
  {
    qtstyle = s.value("QT_STYLE", "oxygen").toString();
    qApp->setStyle(qtstyle);
  }	
  else
  {
    QString savedStyleSheet =
    IQFUtils::utils(this)->styleSheet(s.value("STYLESHEET_FILENAME", "").toString());
    qApp->setStyleSheet(savedStyleSheet);
  }
  
  /* Create a 'log' widget in the stackedWidget */
  splash->newStep("Creating log widget...", ++steps);
  loginstance = NULL;
  loginstance = Log::log(ui.pageLog);
  
  _history = History::history(this, 30);
  
  /* Initialize IPFIREwall: send hello and take care of the command line
  * arguments that affect the way to startup the firewall
  * (i.e. background, rc mode, justload... 
  */
  initializer_instance = NULL;
  splash->newStep("Initializing the user/kernel communication...", ++steps);
  initializer_instance = IQFInitializer::instance(argc, argv);
  
  IQFireConfdir confChecker;
  
  if(confChecker.check() < 0)
    exit(EXIT_FAILURE);
  /* loads module if needed. Checks for module load failures looking at /tmp failure log */
  if(initializer_instance->init(initMsg) != HELLO_OK)
  {
    QMessageBox::critical(0, "iqFirewall: initialization error", initMsg);
    _exit(EXIT_FAILURE);
  }
  /* Read and load the rulesets */
  splash->newStep("Reading and loading the rules...", ++steps);

  iqfpolicy_instance = Policy::instance();
  if(iqfpolicy_instance->AllocOk() )
    iqfpolicy_instance->SendAllRulesToKernel();

  splash->newStep("Creating info and help browsers...", ++steps);
  /* Setup globally visible through iqfwidgets IQFHelpBrowser and IQFInfoBrowser */
  IQFHelpBrowser *help_browser = IQFHelpBrowser::helpBrowser();
  IQFInfoBrowser *info_browser = IQFInfoBrowser::infoBrowser();

  /* Remember to reparent the help and info browser once setup the UI! */
  help_browser->reparent(ui.stackedWidgetHelpOrStats->widget(0)); /* reparent help */
  info_browser->reparent(ui.widgetInfoBrowser); /* reparent info */
  QHBoxLayout *infoLo = new QHBoxLayout(ui.widgetInfoBrowser);
  infoLo->addWidget(info_browser);
  QHBoxLayout *helpLo = new QHBoxLayout(ui.stackedWidgetHelpOrStats->widget(0));
  helpLo->addWidget(help_browser);

  splash->newStep("Creating the presentation widget...", ++steps);
  presenter = new IQFPresenter(ui.pageHtmlManual);
  
  splash->newStep("Creating the system tray...", ++steps);
  CreateSystemTray();
  ui.stackedWidgetMain->addWidget(loginstance);
  
  /* Instantiate the singleton class which will store the configuration of
  * the firewall throug all the execution time:
  */
  iqfdata_instance = NULL;
  
  /* Read configuration files and command line to discover the options 
  * and save them globally.
  */
  iqfdata_instance = IQFireData::instance(argc, argv);
  
  control = IQFNetlinkControl::instance();
  
  splash->newStep("Creating the console", ++steps);
  console = new IQFWidgetKonsole(ui.pageConsole, this);

  splash->newStep("Setting up the \"filter view\" widget...", ++steps);
  setupFilterInteraction();
  ui.checkBoxSilent->setChecked(control->isSilentEnabled());
  ui.checkBoxLogState->setDisabled(true);
  
  /* Create the rule scene */
  splash->newStep("Creating the \"rule scene\"...", ++steps);
  rulescene = new RuleScene(ui.widgetRuleView);

  splash->newStep("Creating the \"natural language widgets\"...", ++steps);
  naturalWidget = new NaturalWidget(ui.widgetNaturalLanguage);
  
  splash->newStep("Creating the kernel tables widgets...", ++steps);
  StateTablesWidget *stateTW = new StateTablesWidget(ui.pageStateT);
  SnatTablesWidget *snatTW = new SnatTablesWidget(ui.pageSnatT);
  DnatTablesWidget *dnatTW = new DnatTablesWidget(ui.pageDnatT);
  KernelTablesStats *ktablesStats = new KernelTablesStats(ui.pageKMem);
  
  /* The rule tree widget */
  splash->newStep("Creating the \"rule tree\" interface...", ++steps);
  /* We can pass DENIAL or ACCEPT to build the filter widget */
  ruletree_filter = new IQFRuleTree(ui.widgetFilter, DENIAL);
  /* we pass TRANSLATION to build the translation widget  */
  ruletree_nat = new IQFRuleTree(ui.widgetNat, TRANSLATION);
  
  /* Show only the filter rules at startup */
  ui.widgetNat->setHidden(true);
  ui.labelNAT->setHidden(true);
  ui.splitterNAT->setSizes(QList<int>() << 10 << 0);
  /* hide or show the save rules button below the rule tree */
  ui.pushButtonSaveRulesToFile->setHidden(s.value("AUTOSAVE_RULES_ON_CHANGE", true).toBool());
  
  splitterDefaultSize.append(5);
  splitterDefaultSize.append(1);
  ui.splitterMain->restoreState(s.value("SPLITTERMAIN_SIZES", splitterDefaultSize).toByteArray());
  
  splash->newStep("Setting up the statistic proxy...", ++steps);
  /* Stats proxy */
  IQFStatsProxy *stats_proxy = IQFStatsProxy::statsProxy(this);
  /* Statistics widget */
  splash->newStep("Setting up the statistic widgets...", ++steps);
  iqfstats = new IQFStats(ui.frameStats, ui.widgetStatsLegend);
  ui.stackedWidgetStats->setCurrentIndex(0);
  /* Passing null prevents IQFStats from creating the legend */
  IQFStats *stats_little = new IQFStats(ui.stackedWidgetHelpOrStats->widget(1), NULL);
  
  StatsText *statst = new StatsText(ui.widgetStatsSummary);
  Q_UNUSED(statst);
  // 	QGridLayout *statstlo = new QGridLayout(ui.widgetStatsSummary);
  // 	statstlo->addWidget(statst, 0, 0, 5, 5);
  
  connect(rulescene, SIGNAL(showStatsIn()), stats_little, SLOT(showStatsIn()));
  connect(rulescene, SIGNAL(showStatsOut()), stats_little, SLOT(showStatsOut()));
  connect(rulescene, SIGNAL(showStatsFwd()), stats_little, SLOT(showStatsFwd()));
  connect(rulescene, SIGNAL(showStatsIn()), this, SLOT(showLittleStats()));
  connect(rulescene, SIGNAL(showStatsOut()), this, SLOT(showLittleStats()));
  connect(rulescene, SIGNAL(showStatsFwd()), this, SLOT(showLittleStats()));
  
  connect(stats_proxy, SIGNAL(statsUpdated()), iqfstats, SLOT(updateStats()));
  connect(stats_proxy, SIGNAL(statsUpdated()), stats_little, SLOT(updateStats()));
  
  /* Pending rules widget */
  QGridLayout *pending_rules_lo = new QGridLayout(ui.widgetPendingRules);
  pending_rules_lo->setMargin(1);
  pending_rules_lo->setSpacing(1);
  pending_rules_widget = new WPendingRules(ui.widgetPendingRules);
  pending_rules_lo->addWidget(pending_rules_widget);
  
  splash->newStep("Populating the tool bar...", ++steps);
  createToolBarActions();
  setupIconsForActions();
  ui.stackedWidgetBrowser->setHidden(true);
  hideSearchWidgets();
  
  /* initialize the QSettings for the side panel, if uninitialized */
  splash->newStep("Setting up the side panel...", ++steps);
  initSettingsForSidePanel();
  /* This needs the actions in the ToolBar to be alive */
  modifySidePanel(ui.stackedWidgetMain->currentIndex());
  
  /* configuration widget */
  splash->newStep("Creating the configuration widget...", ++steps);
  QVBoxLayout *lo = new QVBoxLayout(ui.widgetConfiguration);
  iqfconf = new IQFConfig(ui.widgetConfiguration);
  lo->addWidget(iqfconf);
  lo->setSpacing(0);
  
  /* load html navigation panel */
  loadNavigationPanel();
  /* Connect signals and slots */
  splash->newStep("The interface should be ready in an instant...", ++steps);
  createSystrayConnections();
  createConnections();
  createHelpAndInfoConnections();
  
  
  help_was_shown = helpPanelAct->isChecked();
  
  /* minimum height and width */
  setMinimumHeight(350);
  setMinimumWidth(400);
  setWindowIcon(QIcon(ICON_PATH + "ipfire.png"));
  infoAndHelpForPage(s.value("STARTUP_PAGE", 8).toInt());
  if(s.value("STARTUP_HIDDEN", false).toBool())
  {
    trayIcon->showMessage("(iq)Firewall loaded", 
    "The firewall is loaded.\n"
    "Click on this icon to show its window.", QSystemTrayIcon::Information,
    3500);
  }
  /* reset the window size we had the last time */
  resize(QSize(s.value("WINWIDTH", 850).toInt(), s.value("WINHEIGHT", 580).toInt()));
  
  checkHistoryActionsStatus();
  /* setCurrentPage calls _history->add with the correct value.
  * _history->add() needs to be called to add the first page to
  * the history stack
  */
  setCurrentPage(s.value("STARTUP_PAGE", 9).toInt());
  neverMinimized = s.value("NEVER_MINIMIZED", true).toBool();
  neverClosed = s.value("NEVER_CLOSED", true).toBool();
  
  /* look for updates */
  updates = new IQFUpdates(this);
  updates->setObjectName("iqfire global updater");
  connect(updates, SIGNAL(updateFinished()), iqfconf, SLOT(refreshUpdateInfoLabel()));
  /* 1. now */
  QTimer::singleShot(180000, this, SLOT(lookForUpdates()));
  /* once per day, if the firewall stays up for a long time */
  QTimer *updTimer = new QTimer(this);
  updTimer->setSingleShot(false);
  /* check once per day, which is the minimun interval allowed by the configuration */
  updTimer->setInterval(1000 * 3600 * 24);
  updTimer->start();
  connect(updTimer, SIGNAL(timeout()), this, SLOT(lookForUpdates()));
  
  /* natural updates manager */
  naturalUpdManager = new NaturalUpdatesManager(this);
  /* when the button `Check Now' is clicked on the configuration, we trigger an immediate update of
   * the natural language files.
   */
  connect(iqfconf, SIGNAL(updateNaturalLanguage()), naturalUpdManager, SLOT(update())); 
  connect(naturalUpdManager, SIGNAL(updatedToVersion(int)), iqfconf, SLOT(naturalDictUpdated(int)));
  
  setupButtonIcons();
  
  ui.pushButtonSaveRulesToFile->setHidden(s.value("AUTOSAVE_RULES_ON_CHANGE").toBool());
  
  /* traffic information */
  traffic = IQFTrafficProxy::trafproxy();
  connect(traffic, SIGNAL(configured(const QString&)), this, SLOT(newTrafficIface(const QString&)));
  traffic->setup();
  
}

IQFIREmainwin::~IQFIREmainwin()
{
  IQFInitializer* init_instance = IQFInitializer::instance();
  if(init_instance->SendGoodbye() < 0)
    QMessageBox::critical(this, "Error", "There was an error sending goodbye");
  delete IQFNetlinkControl::instance();
  IgnoredPacketsSet::instance()->saveIgnoredPackets();
  NaturalRuleHash::naturalRuleHashMap()->save();
  /* natural text is saved by the user when clicking on the apply and save button.
   * Natural text must not be saved in the destructor.
   */
}

void IQFIREmainwin::saveToolbarStatus()
{
  QSettings s;
  s.setValue("TB_NAV_VISIBLE", ui.toolBarNavigation->isVisible());
  s.setValue("TB_PANELS_VISIBLE", ui.toolBarPanels->isVisible());
  s.setValue("TB_PAGES_VISIBLE", ui.toolBarPages->isVisible());
  s.setValue("TB_GENERIC_VISIBLE", ui.toolBar->isVisible());
  QList<IQFTrafficToolBar *>dynamicTbars = findChildren<IQFTrafficToolBar *>();
  for(int i = 0; i < dynamicTbars.size(); i++)
    s.setValue(QString("TB_%1_VISIBLE").arg(dynamicTbars[i]->name()), dynamicTbars[i]->isVisible());
}

void IQFIREmainwin::resizeEvent(QResizeEvent *e)
{
  QSettings s;
  /* save the window size for next startup */
  s.setValue("WINHEIGHT", e->size().height());
  s.setValue("WINWIDTH", e->size().width());
  QMainWindow::resizeEvent(e);
}

void IQFIREmainwin::hideEvent(QHideEvent *e)
{
  
  /* store toolbar status.
  * We cannot save this status in the destructor because
  * the user could exit iqFirewall by the systray icon.
  */
  saveToolbarStatus();
  QMainWindow::hideEvent(e);
}

void IQFIREmainwin::changeEvent(QEvent *e)
{
  
  if(e->type() == QEvent::WindowStateChange &&
    windowState() & Qt::WindowMinimized)
  {
    hide();
    if(neverMinimized)
    {
      trayIcon->showMessage("(iq)Firewall minimized", 
      "The firewall window has been minimized here.\n"
      "Click on this icon to show it again.\n"
      "(This message won't be shown again.)", QSystemTrayIcon::Information,
      30000);
      QSettings s;
      s.setValue("NEVER_MINIMIZED", false);
      neverMinimized = false;
    }
    
  }
}

void IQFIREmainwin::createConnections()
{
	connect(ui.action_Quit, SIGNAL(triggered() ), this, SLOT(QuitApplication() ) );
	connect(ui.actionConsole, SIGNAL(triggered() ), this, SLOT(showPageConsole() ) );
	connect(ui.actionIQfire_Logs, SIGNAL(triggered() ), this, SLOT(showLogsConsole() ) );
	connect(ui.actionConfigure_Console_settings, SIGNAL(triggered()), this, SLOT(showConsoleSettings() ) );
	connect(ui.actionRule_View, SIGNAL(triggered()), this, SLOT(showRuleView()));
	connect(ui.actionRule_Tree, SIGNAL(triggered()), this, SLOT(showRuleTree()));
	connect(ui.actionStatistics, SIGNAL(triggered()), this, SLOT(showStats()));
	connect(ui.actionPending_rules, SIGNAL(triggered()), this, SLOT(showPendingRules()));
	connect(ui.actionNatural_Language, SIGNAL(triggered()), this, SLOT(showNaturalLanguage()));
	connect(ui.actionNotified_packets, SIGNAL(triggered()), this, SLOT(showNotifiedPackets()));
	connect(ui.actionKernel_State_Tables, SIGNAL(triggered()), this, SLOT(showKernelStateTables()));
	connect(ui.actionKernel_Snat_Tables, SIGNAL(triggered()), this, SLOT(showKernelSnatTables()));
	connect(ui.actionKernel_Dnat_Tables, SIGNAL(triggered()), this, SLOT(showKernelDnatTables()));
	connect(ui.actionKernel_Tables_Memory_Usage, SIGNAL(triggered()), this, SLOT(showKernelTableStats()));
	connect(ui.actionConfigure_firewall, SIGNAL(triggered()), this, SLOT(showConfigurationWidget()));
	connect(ui.actionHandbook, SIGNAL(triggered()), this, SLOT(showManual()));
	connect(ui.actionSearch, SIGNAL(triggered()), this, SLOT(showSearchWidgets()));
	connect(ui.actionSetup_console_options_and_filters, SIGNAL(triggered()), this, 
	SLOT(showConsoleSettings()));
	connect(ui.actionAbout_Qt, SIGNAL(triggered()), qApp, SLOT(aboutQt()));
	connect(ui.actionAbout, SIGNAL(triggered()), this, SLOT(about()));
	connect(ui.actionPrevious_Window, SIGNAL(triggered()),  this, SLOT(back()));
	connect(ui.actionNext_Window, SIGNAL(triggered()),  this, SLOT(forward()));
	connect(ui.actionHome_Window, SIGNAL(triggered()),  this, SLOT(home()));
	// 	connect(ui.actionHistory, SIGNAL(toggled(bool)), ui.toolBarNavigation, SLOT(setVisible(bool)));
	// 	connect(ui.actionNavigation, SIGNAL(toggled(bool)), ui.toolBarPages, SLOT(setVisible(bool)));
	// 	connect(ui.actionSidebar_contents, SIGNAL(toggled(bool)), ui.toolBarPanels, SLOT(setVisible(bool)));
	// 	connect(ui.actionGeneric, SIGNAL(toggled(bool)), ui.toolBar, SLOT(setVisible(bool)));

	connect(loginstance, SIGNAL(somethingHasFailed() ), this, SLOT(showLogsConsole() ) );
	connect(loginstance, SIGNAL(widgetClosed()), this, SLOT(logwidgetClosed()) );
	connect(ui.checkBoxSilent, SIGNAL(toggled(bool)), control, SLOT(enableSilent(bool))); 
	connect(ui.checkBoxSilent, SIGNAL(toggled(bool)), silentact, SLOT(setChecked(bool))); 
	connect(ui.checkBoxServices, SIGNAL(toggled(bool)), console,  SLOT(enableResolvPorts(bool)));
	connect(rulescene, SIGNAL(mouseOverItem(QString)), IQFInfoBrowser::infoBrowser(), SLOT(setHtml(QString)));
	connect(rulescene, SIGNAL(mouseOverItemHelp(QString)), IQFHelpBrowser::helpBrowser(), SLOT(setHtml(QString)));
	connect(rulescene, SIGNAL(mouseOutsideItem()), this, SLOT(infoAndHelpForRuleScene()));

	connect(ui.checkBoxShowNat, SIGNAL(toggled(bool)), this, SLOT(showNATPart(bool)));
	connect(ui.pushButtonApply, SIGNAL(clicked() ), ruletree_filter, SLOT(applyRules()));
	connect(ui.pushButtonApply, SIGNAL(clicked() ), ruletree_nat, SLOT(applyRules()));
	connect(ui.pushButtonSaveRulesToFile, SIGNAL(clicked()), iqfpolicy_instance, SLOT(saveRules()));
	connect(ui.pushButtonUndoRuleTreeChanges, SIGNAL(clicked()), ruletree_filter, SLOT(undoChanges()));
	connect(ui.pushButtonUndoRuleTreeChanges, SIGNAL(clicked()), ruletree_nat, SLOT(undoChanges()));

	connect(iqfpolicy_instance, SIGNAL(rulesChanged()), ruletree_filter, SLOT(populateTree()));
	connect(iqfpolicy_instance, SIGNAL(rulesChanged()), ruletree_nat,  SLOT(populateTree()));
	connect(iqfpolicy_instance, SIGNAL(saveProgressMaximum(int)), ui.progressBarRuleTree,  SLOT(setMaximum(int)));
	connect(iqfpolicy_instance, SIGNAL(saveProgressChanged(int)), ui.progressBarRuleTree,  SLOT(setProgress(int)));
			      
			      
	/* when the set of ignored packets (filled by the popup system changes, it
	* emits a signal to notify the interested objects, i.e. the pending rules 
	* widget.
	*/
	connect(IgnoredPacketsSet::instance(), SIGNAL(setChanged()), pending_rules_widget, SLOT(reloadTree()));
	connect(IgnoredPacketsSet::instance(), SIGNAL(ignoredAdded()), pending_rules_widget, SLOT(addItem()));
						
	/* When we toggle the Apply Filter checkBox, a signal is emitted to activate the filter 
	* on the console widget. filterChanged() passes a string representing a filter (to enable
	* it on the console), or a string telling the console to disable the filter, if active.
	*/
	connect(this, SIGNAL(filterChanged(const QString &)), console, SLOT(filterChanged(const QString &)));

	/* When the main stacked widget page changes, we change the side panel according
	* to the last choice of the user.
	*/
	connect(ui.stackedWidgetMain, SIGNAL(currentChanged(int)), this, SLOT(reloadHtmlInNavigationPanel(int)));
	connect(ui.stackedWidgetMain, SIGNAL(currentChanged(int)), this, SLOT(activateSearchAction(int)));
	connect(ui.stackedWidgetMain, SIGNAL(currentChanged(int)), this, SLOT(storeSplitterState(int)));
	connect(ui.stackedWidgetMain, SIGNAL(currentChanged(int)), this, SLOT(infoAndHelpForPage(int)));
	connect(ui.stackedWidgetMain, SIGNAL(currentChanged(int)), this, SLOT(updateWindowTitle(int)));
	connect(ui.stackedWidgetMain, SIGNAL(currentChanged(int)), this, SLOT(showFilterAction(int)));
	connect(ui.textBrowserNavigation, SIGNAL(changePage(int)), this, SLOT(setCurrentPage(int)));
	connect(ui.textBrowserNavigation, SIGNAL(silentModality(bool)), silentact, SLOT(setChecked(bool)));
	connect(ui.textBrowserNavigation, SIGNAL(silentModality(bool)), this, SLOT(reloadHtmlInNavigationPanel()));
	connect(ui.textBrowserNavigation, SIGNAL(showHelp(bool)), helpPanelAct, SLOT(setChecked(bool)));
	connect(ui.textBrowserNavigation, SIGNAL(showInfo(bool)), infoPanelAct, SLOT(setChecked(bool)));

	/* Unique application notification */
	connect(qApp, SIGNAL(Rise() ), this, SLOT(anotherInstanceDetected() ) );

	/* Clears the items in the notify tree widget */
	connect(ui.pushButtonRemoveSelected, SIGNAL(clicked()), ui.treeWidgetMatchedPackets,
	SLOT(removeSelectedItems()));
	connect(ui.pushButtonClearNotified, SIGNAL(clicked()), ui.treeWidgetMatchedPackets,
		  SLOT(clear()));
	/* configuration buttons */
	connect(ui.pbConfApply, SIGNAL(clicked()), this, SLOT(reloadSettings()));
	connect(ui.pbConfApply, SIGNAL(clicked()), iqfconf, SLOT(refreshUpdateInfoLabel()));
	connect(ui.pbConfCancel, SIGNAL(clicked()), iqfconf, SLOT(undoChanges()));

	/* statistics stackedWidget choice */
	connect(ui.radioButtonStatsSummary, SIGNAL(toggled(bool)), this, SLOT(showStatsSummary(bool)));
	/* search/find */
	connect(ui.pushButtonFind, SIGNAL(clicked()), this, SLOT(searchInTree()));
	connect(ui.pushButtonCloseFind, SIGNAL(clicked()), this, SLOT(hideSearchWidgets()));
	connect(presenter, SIGNAL(anchorClicked(const QUrl&)), this, SLOT(performAction(const QUrl &)));
	/* block what cannot be done during the adding/removing of a rule
	*/
	connect(ruletree_filter, SIGNAL(blockInterface(bool)), this,  SLOT(blockInterfaceWhileAddingRule(bool)));
	connect(ruletree_nat, SIGNAL(blockInterface(bool)), this,  SLOT(blockInterfaceWhileAddingRule(bool)));
	/* block what cannot be done during the adding/removing of a rule */
	connect(rulescene, SIGNAL(blockInterface(bool)), this,  SLOT(blockInterfaceWhileAddingRule(bool)));
	connect(ruletree_filter, SIGNAL(showNaturalLanguage()), this, SLOT(showNaturalLanguage()));

	connect(_history, SIGNAL(historyModified()), this, SLOT(checkHistoryActionsStatus()));
	connect(ui.pushButtonCloseConsoleSettings, SIGNAL(clicked()), this, SLOT(back()));
	connect(ui.pbConfCancel, SIGNAL(clicked()), this, SLOT(back()));

	/* On the fly settings for the system tray animation */
	connect(iqfconf->ui.dSBMeanAdjustFactor, SIGNAL(valueChanged(double)), trayIcon, SLOT(setMeanAdjustFactor(double)));
	connect(iqfconf->ui.dSBAllowNeedle, SIGNAL(valueChanged(double)), trayIcon, SLOT(changeAllowNeedleLen(double)));
	connect(iqfconf->ui.dSBBlockNeedle, SIGNAL(valueChanged(double)), trayIcon, SLOT(changeBlockNeedleLen(double)));
	connect(iqfconf->ui.cBNeedleArrows, SIGNAL(toggled(bool)), trayIcon, SLOT(setArrowsEnabled(bool)));
	connect(iqfconf->ui.sBAnimationSpeed, SIGNAL(valueChanged(int)), trayIcon, SLOT(changeAnimationSpeed(int)));
	connect(iqfconf->ui.rBCircularGauge, SIGNAL(toggled(bool)), trayIcon, SLOT(setCircularDashboard(bool)));
	connect(iqfconf->ui.spinBoxAlpha, SIGNAL(valueChanged(int)), trayIcon, SLOT(setAlpha(int)));

	
	/* connect the resolver resolved() signals to the info_browser */
	IQFResolverProxy *resolver = IQFResolverProxy::resolver();
	connect(resolver, SIGNAL(resolved(const QString&, const QString &, const QString&)), IQFInfoBrowser::infoBrowser(), SLOT(resolutionUpdate(const QString &,const QString &,  const QString&)));

	/* connect natural widget new natural item signal to rule tree to add the item to the tree */
	connect(naturalWidget, SIGNAL(newNaturalItem(const uid_t, const int, const int, const QStringList&, const QString&)),  ruletree_filter, 
		 SLOT(addNaturalItem(const uid_t, const int, const int, const QStringList&, const QString&)));
	/* before signaling new natural items, make tree widget clear existing natural items */
	connect(naturalWidget, SIGNAL(clearNaturalItems()), ruletree_filter, SLOT(removeNaturalItems()));
	connect(naturalWidget, SIGNAL(showRuleTree()), this, SLOT(showRuleTree()));
	connect(naturalWidget->logTextBrowser(), SIGNAL(anchorClicked(const QUrl&)), this, SLOT(performAction(const QUrl&)));
	connect(IQFHelpBrowser::helpBrowser(), SIGNAL(appendNaturalTextFromClick(const QString&)), naturalWidget, SLOT(appendNaturalText(const QString&)));
	connect(naturalWidget, SIGNAL(applyNaturalRules() ), ruletree_filter, SLOT(applyRules()));
}

void IQFIREmainwin::createSystrayConnections()
{
  connect(trayIcon, SIGNAL(activated(QSystemTrayIcon::ActivationReason)),
	   this, SLOT(iconActivated(QSystemTrayIcon::ActivationReason)));
	   connect(trayIcon, SIGNAL(newNotifyItem(QTreeWidgetItem*)), ui.treeWidgetMatchedPackets,
		    SLOT(addItem(QTreeWidgetItem*)));
		    connect(trayIcon->notifierWidget(), SIGNAL(itemAck(QStringList &)), ui.treeWidgetMatchedPackets,
			     SLOT(setItemAcknowledged(QStringList&)));
}

void IQFIREmainwin::createToolBarActions()
{
      QSettings s;
      QAction *quit = ui.toolBar->addAction(QIcon(ICON_PATH + "exit.png"), "Quit", this, SLOT(QuitApplication()) );
      quit->setStatusTip("Close the iQfirewall application.");
      silentact = ui.toolBar->addAction(QIcon(ICON_PATH + "silent.png"), "Silent");
      silentact->setStatusTip("Switch between silent and verbose modalities.");
      silentact->setCheckable(true);
      if(control->isSilentEnabled())
	silentact->setChecked(true);
      connect(silentact, SIGNAL(toggled(bool)), ui.checkBoxSilent, SLOT(setChecked(bool)));

      /* The following slots are in iqf_side_panel.cpp */
      navigationPanelAct = new QAction(QIcon(ICON_PATH + "navigation_panel.png"), "Show/hide navigation panel", this);
      ui.toolBarPanels->addAction(navigationPanelAct);
      navigationPanelAct->setCheckable(true);
      connect(navigationPanelAct, SIGNAL(toggled(bool)), this, SLOT(showNavigationPanel(bool)));

      infoPanelAct = new QAction(QIcon(ICON_PATH + "info.png"), "Show/hide info panel", this);
      infoPanelAct->setCheckable(true);
      ui.toolBarPanels->addAction(infoPanelAct);
      connect(infoPanelAct, SIGNAL(toggled(bool)), this, SLOT(showInfoPanel(bool)));

      helpPanelAct = new QAction(QIcon(ICON_PATH + "tip.png"), "Show/hide help panel", this);
      helpPanelAct->setCheckable(true);
      ui.toolBarPanels->addAction(helpPanelAct);
      connect(helpPanelAct, SIGNAL(toggled(bool)), this, SLOT(showHelpPanel(bool)));

      connect(helpPanelAct, SIGNAL(triggered()), this, SLOT(reloadHtmlInNavigationPanel()));
      connect(infoPanelAct, SIGNAL(triggered()), this, SLOT(reloadHtmlInNavigationPanel()));
      connect(silentact, SIGNAL(triggered()), this, SLOT(reloadHtmlInNavigationPanel()));
      connect(navigationPanelAct, SIGNAL(triggered()), this, SLOT(reloadHtmlInNavigationPanel()));

      /* Navigation toolBar actions */
      QAction *homeAct = new QAction(QIcon(ICON_PATH + "gohome.png"), "Home",
      ui.toolBarNavigation);
      ui.toolBarNavigation->addAction(homeAct);
      connect(homeAct, SIGNAL(triggered()), this, SLOT(home()));

      backAct = new QAction(QIcon(ICON_PATH + "back.png"), "Back",
      ui.toolBarNavigation);
      ui.toolBarNavigation->addAction(backAct);
      connect(backAct, SIGNAL(triggered()), this, SLOT(back()));

      forwardAct = new QAction(QIcon(ICON_PATH + "forward.png"), "Forward",
      ui.toolBarNavigation);
      ui.toolBarNavigation->addAction(forwardAct);
      connect(forwardAct, SIGNAL(triggered()), this, SLOT(forward()));

      QAction *consoleAct = new QAction(QIcon(ICON_PATH + "console.png"), "Console", ui.toolBarPages);
      QAction *rViewAct = new QAction(QIcon(ICON_PATH + "ruleview.png"), "Rule view",  ui.toolBarPages);
      QAction *rTreeAct = new QAction(QIcon(ICON_PATH + "ruletree.png"),"Rule tree",  ui.toolBarPages);
      QAction *naturalLanguageAct = new QAction(QIcon(ICON_PATH + "natural_language.png"), "Natural language", ui.toolBarPages);
      QAction *statsAct = new QAction(QIcon(ICON_PATH + "stats.png"), "Statistics",  ui.toolBarPages);
      QAction *pendingRulesAct = new QAction(QIcon(ICON_PATH + "pending_rules.png"), "Connections waiting for authorization",  ui.toolBarPages);
      QAction *notifiedPacketsAct = new QAction(QIcon(ICON_PATH + "notified.png"),  "Packets notified by the firewall",  ui.toolBarPages);
      filterAction = new QAction(QIcon(ICON_PATH + "filter.png"), "Filter console output", ui.toolBarPages);
      QAction *stateTablesAct = new QAction(QIcon(ICON_PATH + "statet.png"), "Kernel state tables", ui.toolBarPages);
      QAction *snatTablesAct = new QAction(QIcon(ICON_PATH + "snatt.png"), "Kernel source nat tables", ui.toolBarPages);
      QAction *dnatTablesAct = new QAction(QIcon(ICON_PATH + "dnatt.png"), "Kernel destination nat tables", ui.toolBarPages);
      QAction *kTablesMem = new QAction(QIcon(ICON_PATH + "ktablesmem.png"), "Kernel tables memory usage", ui.toolBarPages);
      

      connect(consoleAct,  SIGNAL(triggered()), this, SLOT(showPageConsole()));
      connect(rViewAct,  SIGNAL(triggered()), this, SLOT(showRuleView()));
      connect(rTreeAct, SIGNAL(triggered()), this, SLOT(showRuleTree()));
      connect(naturalLanguageAct, SIGNAL(triggered()), this, SLOT(showNaturalLanguage()));
      connect(statsAct, SIGNAL(triggered()), this, SLOT(showStats()));
      connect(pendingRulesAct, SIGNAL(triggered()), this, SLOT(showPendingRules()));
      connect(notifiedPacketsAct, SIGNAL(triggered()), this, SLOT(showNotifiedPackets()));
      connect(filterAction, SIGNAL(triggered()), this, SLOT(showConsoleSettings()));
      connect(stateTablesAct, SIGNAL(triggered()), this, SLOT(showKernelStateTables()));
      connect(snatTablesAct, SIGNAL(triggered()), this, SLOT(showKernelSnatTables()));
      connect(dnatTablesAct, SIGNAL(triggered()), this, SLOT(showKernelDnatTables()));
      connect(kTablesMem, SIGNAL(triggered()), this, SLOT(showKernelTableStats()));

      ui.toolBarPages->addAction(consoleAct);
      ui.toolBarPages->addAction(filterAction);
      ui.toolBarPages->addAction(rViewAct);
      ui.toolBarPages->addAction(rTreeAct);
      ui.toolBarPages->addAction(naturalLanguageAct);
      ui.toolBarPages->addAction(statsAct);
      ui.toolBarPages->addAction(pendingRulesAct);
      ui.toolBarPages->addAction(notifiedPacketsAct);
      ui.toolBarPages->addSeparator();
      ui.toolBarPages->addAction(stateTablesAct);
      ui.toolBarPages->addAction(snatTablesAct);
      ui.toolBarPages->addAction(dnatTablesAct);
      ui.toolBarPages->addAction(kTablesMem);

      /* Actions to show/hide the toolbars */
      ui.toolBarPanels->setWindowTitle("Sidebar contents");
      ui.toolBarNavigation->setWindowTitle("Navigation history");
      ui.toolBarPages->setWindowTitle("Navigation");
      ui.toolBar->setWindowTitle("Generic");

      ui.menuTool_bars->addAction(ui.toolBarNavigation->toggleViewAction());
      ui.menuTool_bars->addAction(ui.toolBarPanels->toggleViewAction());
      ui.menuTool_bars->addAction(ui.toolBarPages->toggleViewAction());
      ui.menuTool_bars->addAction(ui.toolBar->toggleViewAction());

      ui.toolBarNavigation->setVisible(s.value("TB_NAV_VISIBLE",true).toBool());
      ui.toolBarPanels->setVisible(s.value("TB_PANELS_VISIBLE",true).toBool());
      ui.toolBarPages->setVisible(s.value("TB_PAGES_VISIBLE",true).toBool());
      ui.toolBar->setVisible(s.value("TB_GENERIC_VISIBLE",true).toBool());
}

void IQFIREmainwin::setupIconsForActions()
{
  QSettings s;
  ui.action_Quit->setIcon(QIcon(ICON_PATH + "exit.png"));
  ui.actionConfigure_Console_settings->setIcon(QIcon(ICON_PATH + "filter.png"));
  ui.actionIQfire_Logs->setIcon(QIcon(ICON_PATH + "logs.png"));
  ui.actionSearch->setIcon(QIcon(ICON_PATH + "search.png"));
  ui.actionConsole->setIcon(QIcon(ICON_PATH + "console.png"));
  ui.actionRule_Tree->setIcon(QIcon(ICON_PATH + "ruletree.png"));
  ui.actionStatistics->setIcon(QIcon(ICON_PATH + "stats.png"));
  ui.actionRule_view->setIcon(QIcon(ICON_PATH + "ruleview.png"));
  ui.actionPending_rules->setIcon(QIcon(ICON_PATH + "pending_rules.png"));
  ui.actionNotified_packets->setIcon(QIcon(ICON_PATH + "notified.png"));
  ui.actionConfigure_firewall->setIcon(QIcon(ICON_PATH + "configure.png"));
  ui.actionSetup_console_options_and_filters->setIcon(QIcon(ICON_PATH + "filter.png"));
  ui.actionHandbook->setIcon(QIcon(ICON_PATH + "manual.png"));
  ui.actionPrevious_Window->setIcon(QIcon(ICON_PATH + "back.png"));
  ui.actionNext_Window->setIcon(QIcon(ICON_PATH + "forward.png"));
  ui.actionHome_Window->setIcon(QIcon(ICON_PATH + "gohome.png"));
  ui.actionKernel_State_Tables->setIcon(QIcon(ICON_PATH + "statet.png"));
  ui.actionKernel_Snat_Tables->setIcon(QIcon(ICON_PATH + "snatt.png"));
  ui.actionKernel_Dnat_Tables->setIcon(QIcon(ICON_PATH + "dnatt.png"));
  ui.actionKernel_Tables_Memory_Usage->setIcon(QIcon(ICON_PATH + "ktablesmem.png"));
}

void IQFIREmainwin::showLittleStats()
{
  QSettings s;
  int page_index = ui.stackedWidgetMain->currentIndex();
  /* when the user clicks on a block of the rule view, we have to show
  the stats.
  We show them always, if the navigation panel is currently shown,
  otherwise we switch between stats and help */
  
  ui.stackedWidgetHelpOrStats->setCurrentIndex(1);
  ui.labelHelpOrStats->setText("Blocked packets/time:");
  if(navigationPanelAct->isChecked()) /* if we have the navigation enabled */
  {
    navigationPanelAct->setChecked(false); /* disable it */
    /* but  save its value */
    s.value(QString("NAVIGATION_BROWSER_%1").arg(page_index), true);
  }
  if(!helpPanelAct->isChecked()) /* same as above */
  {
    helpPanelAct->setChecked(true);
    s.value(QString("HELP_BROWSER_%1").arg(page_index), false);
  }
  
  
}

void IQFIREmainwin::hideLittleStats()
{
  ui.stackedWidgetHelpOrStats->setCurrentIndex(0);
  ui.labelHelpOrStats->setText("Help:");
}

void IQFIREmainwin::showStatsSummary(bool show)
{
  if(show)
    ui.stackedWidgetStats->setCurrentIndex(1);
  else
    ui.stackedWidgetStats->setCurrentIndex(0);
}

void IQFIREmainwin::showFilterAction(int page)
{
  if(page != 0 && page != 2)
  {
    filterAction->setEnabled(false);
    filterAction->setToolTip("Action available only when console window is active");
  }
  else
    filterAction->setEnabled(true);
}

void IQFIREmainwin::setCurrentPage(int n)
{
  QSettings s;
  storeNavigationToolbarButtonsState();
  if(ui.stackedWidgetHelpOrStats->currentIndex() != 0)
    ui.stackedWidgetHelpOrStats->setCurrentIndex(0);
  if(!ui.splitterMain->beenMoved() && n == 5 /*rule view */)
    ui.splitterMain->restoreState(s.value("SPLITTERMAIN_SIZES", splitterDefaultSize).toByteArray());
  ui.stackedWidgetMain->setCurrentIndex(n);
  if(n != DOCBROWSER)
    _history->add(ui.stackedWidgetMain->currentIndex());
  else
    _history->add("action://home");
  /* history emits a signal when it changes. */;
  modifySidePanel(n);	
}

void IQFIREmainwin::setCurrentPage(QWidget *widget)
{
  storeNavigationToolbarButtonsState();
  if(ui.stackedWidgetHelpOrStats->currentIndex() != 0)
    ui.stackedWidgetHelpOrStats->setCurrentIndex(0);
  ui.stackedWidgetMain->setCurrentWidget(widget);
  modifySidePanel(ui.stackedWidgetMain->currentIndex());
  if(ui.stackedWidgetMain->currentIndex() != DOCBROWSER)
    _history->add(ui.stackedWidgetMain->currentIndex());
  else
    _history->add("action://home");
  /* history emits a signal when it changes. */
}

void IQFIREmainwin::storeSplitterState(int page)
{
  Q_UNUSED(page);
  QSettings s;
  QList<int> sizes;
  sizes = ui.splitterMain->sizes();
  /* save the splitter sizes just if the panel is shown (i.e. both
  * parts of the splitter are visible.
  */
  if(sizes.size() == 2 && sizes[0] != 0 && sizes[1] != 0)
  {
    QByteArray savedState =  ui.splitterMain->saveState();
    /* The main splitter: save its position in QSettings at exit */
    s.setValue("SPLITTERMAIN_SIZES", savedState);
  }
}

void IQFIREmainwin::showPageConsole()
{
  setCurrentPage(ui.pageConsole);
}

void IQFIREmainwin::showPendingRules()
{
  setCurrentPage(ui.pagePendingRules);
}

void IQFIREmainwin::showRuleView()
{
  QSettings s;
  if(!ui.splitterMain->beenMoved())
    ui.splitterMain->restoreState(s.value("SPLITTERMAIN_SIZES", splitterDefaultSize).toByteArray());
  setCurrentPage(ui.pageRules);
}

void IQFIREmainwin::showRuleTree()
{
  setCurrentPage(ui.pageRuleTree);
}

void IQFIREmainwin::showNaturalLanguage()
{
  IQFHelpBrowser::helpBrowser()->setHtml(IQFMessageProxy::msgproxy()->getHelp(QString("natural_language_%1").arg(Dictionary::instance()->language())));
  setCurrentPage(ui.pageNaturalLanguage);
}


void IQFIREmainwin::showKernelStateTables()
{
    setCurrentPage(ui.pageStateT);
}

void IQFIREmainwin::showKernelSnatTables()
{
  setCurrentPage(ui.pageSnatT);
}

void IQFIREmainwin::showKernelDnatTables()
{
  setCurrentPage(ui.pageDnatT);
}

void IQFIREmainwin::showKernelTableStats()
{
  setCurrentPage(ui.pageKMem);
}

void IQFIREmainwin::showStats()
{	
  setCurrentPage(ui.pageStats);
}

void IQFIREmainwin::showNotifiedPackets()
{
  setCurrentPage(ui.pageNotifiedPackets);
}

void IQFIREmainwin::showManual()
{
  /* see iqf_manual_links_dispatcher for openManualAtPage() */
  openManualAtPage(QUrl("manual://welcome"));
  /* see iqf_html_manual_and_presentation setSource() for "manual://welcome" treatment */
}

void IQFIREmainwin::showNATPart(bool show)
{
  ui.widgetNat->setHidden(!show);
  ui.labelNAT->setHidden(!show);
  
  if(!show)
    ui.splitterNAT->setSizes(QList<int>() << 10 << 0);
  else
    ui.splitterNAT->setSizes(QList<int>() << 5 << 5);
}

void IQFIREmainwin::enableSilentFromToolBar(bool en)
{
  ui.checkBoxSilent->setChecked(en);
  reloadHtmlInNavigationPanel(); /* to show "enable verbose"/ "enable silent */
}

void IQFIREmainwin::showLogsConsole()
{
  setCurrentPage(LOGS);
}

void IQFIREmainwin::showConsoleSettings()
{
  QSettings s;
  setCurrentPage(ui.pageConsoleSettings);
  ui.checkBoxServices->setChecked(s.value("RESOLVE_SERVICES", true).toBool());
}

void IQFIREmainwin::logwidgetClosed()
{
  back();
}

void IQFIREmainwin::enableSilentModality(bool en)
{
  silentact->setChecked(en);
}

void IQFIREmainwin::CreateSystemTray()
{
  QSettings s;
  trayIcon = new IQFSysTray(this);
  trayIcon->show();
}

void IQFIREmainwin::triggerReloadSettings(bool dummy)
{
  Q_UNUSED(dummy);
  if(iqfconf != NULL)
    iqfconf->reloadSettings();
}

void IQFIREmainwin::closeEvent(QCloseEvent *event)
{
  if(d_shuttingDown)
  {
    IQFResolverProxy::resolver()->waitForRunningThreads();
    storeSplitterState();
    storeNavigationToolbarButtonsState();
    if(isVisible())
      saveToolbarStatus();
    event->accept();
  }
  else
  {
    /* Hide the window and do not exit */
    hide();
    storeNavigationToolbarButtonsState();
    event->ignore();
    if(neverClosed)
    {
      trayIcon->showMessage("(iq)Firewall minimized", 
      "The firewall window has been minimized here.\n"
      "Click on this icon to show it again.\n"
      "To close the program, right click on this tray icon\n"
      "and choose \"Quit\", or \"File->Quit\" from the main\n"
      "window.\n"
      "(This message won't be shown again.)", QSystemTrayIcon::Information, 30000);
      QSettings s;
      s.setValue("NEVER_CLOSED", false);
      neverClosed = false;
    }
  }	
}

void IQFIREmainwin::iconActivated(QSystemTrayIcon::ActivationReason reason)
{
  switch (reason) {
    case QSystemTrayIcon::Trigger:
    case QSystemTrayIcon::DoubleClick:
      if(isVisible())
	hide();
      else
      {
	/* show is not enough when the window was iconified */
	showNormal();
      }
      break;
    case QSystemTrayIcon::MiddleClick:
      trayIcon->showMessage("Reloading system tray icon", "Reloading system tray icon in an instant...", 
      QSystemTrayIcon::Information, 1000);
      trayIcon->hide();
      
      QTimer::singleShot(1000, trayIcon, SLOT(show()));
      break;
    default:
      break;
  }
}

void IQFIREmainwin::anotherInstanceDetected()
{
  if(!infoPanelAct->isChecked())
    infoPanelAct->setChecked(true);
  if(!helpPanelAct->isChecked())
    helpPanelAct->setChecked(true);
  
  IQFHelpBrowser::helpBrowser()->setHtml(IQFMessageProxy::msgproxy()->getHelp("helpUnique"));
  IQFInfoBrowser::infoBrowser()->setHtml(IQFMessageProxy::msgproxy()->getInfo("infoUnique"));
  
  if(isHidden())
    show();
  else
    raise();
}

void IQFIREmainwin::QuitApplication()
{
  d_shuttingDown = true;
  close();
  //qApp->quit();
}

void IQFIREmainwin::home()
{
  QSettings s;
  unsigned page = s.value("HOME_PAGE", 0).toUInt();
  if(page != (unsigned) (ui.stackedWidgetMain->currentIndex()))
    setCurrentPage(page);
}

void IQFIREmainwin::back()
{
  
  QVariant page = _history->previous();
  /* history emits a signal when it changes. */;
  if(page.type() == QVariant::Int || page.type() == QVariant::UInt)
  {
    
    if(page != (unsigned) (ui.stackedWidgetMain->currentIndex()))
      changePageByHistory(page.toUInt());
  }
  else if(page.type() == QVariant::String) /* an html file for the manual */
  {
    storeNavigationToolbarButtonsState();
    if(ui.stackedWidgetMain->currentIndex() != 9)
      ui.stackedWidgetMain->setCurrentIndex(9);
    presenter->setSource(QUrl(page.toString()));
    modifySidePanel(9);
  }
  
}

void IQFIREmainwin::forward()
{
  QVariant page = _history->next();
  /* history emits a signal when it changes. */;
  if(page.type() == QVariant::Int || page.type() == QVariant::UInt)
  {
    
    if(page != (unsigned) (ui.stackedWidgetMain->currentIndex()))
      changePageByHistory(page.toUInt());
  }
  else if(page.type() == QVariant::String) /* an html file for the manual */
  {
    storeNavigationToolbarButtonsState();
    if(ui.stackedWidgetMain->currentIndex() != DOCBROWSER)
      ui.stackedWidgetMain->setCurrentIndex(DOCBROWSER);
    presenter->setSource(QUrl(page.toString()));
    modifySidePanel(DOCBROWSER);
  }
}

void IQFIREmainwin::changePageByHistory(int page)
{
  storeNavigationToolbarButtonsState();
  if(ui.stackedWidgetHelpOrStats->currentIndex() != 0)
    ui.stackedWidgetHelpOrStats->setCurrentIndex(0);
  ui.stackedWidgetMain->setCurrentIndex(page);
  /* page 5 needs help browser update */
  if(page == 5)
    IQFHelpBrowser::helpBrowser()->setHtml(IQFMessageProxy::msgproxy()->getHelp(QString("natural_language_%1").arg(Dictionary::instance()->language())));
  modifySidePanel(page);
}

void IQFIREmainwin::checkHistoryActionsStatus()
{
  if(!_history->hasNext())
  {
    forwardAct->setEnabled(false);
    ui.actionNext_Window->setEnabled(false);
  }
  else
  {
    forwardAct->setEnabled(true);
    ui.actionNext_Window->setEnabled(true);
  }
  
  if(!_history->hasPrevious())
  {
    backAct->setEnabled(false);
    ui.actionPrevious_Window->setEnabled(false);
  }
  else
  {
    backAct->setEnabled(true);
    ui.actionPrevious_Window->setEnabled(true);
  }
}

void IQFIREmainwin::showConfigurationWidget()
{
  setCurrentPage(ui.pageConfig);
}

void IQFIREmainwin::disablePopupMatch(bool dis)
{
  Q_UNUSED(dis);
}

void IQFIREmainwin::disablePopupUnknownConnections(bool dis)
{
  Q_UNUSED(dis);
}

void IQFIREmainwin::reloadSettings()
{
  QSettings s;
  QDate nextScheduledUpdate;
  
  if(iqfconf != NULL)
  {
    /* General */
    s.setValue("STARTUP_HIDDEN", iqfconf->startupIconified());
    s.setValue("AUTOSTART", iqfconf->autostart());
    IQFUtils::utils()->enableAutostart(iqfconf->autostart());
    
    if(traffic->interval() != iqfconf->trafficRefreshInterval())
      traffic->changeInterval(iqfconf->trafficRefreshInterval());
    
    /* System Tray */
    trayIcon->enablePopupNotifier(iqfconf->popupAuthorizationEnabled());
    s.setValue("POPUP_ENABLE", iqfconf->popupAuthorizationEnabled());
    trayIcon->enablePopupOnMatchNotifier(iqfconf->popupMatchingPacketsEnabled());
    s.setValue("POPUP_ON_MATCH", iqfconf->popupMatchingPacketsEnabled());
    trayIcon->setPopupMaxItems(iqfconf->maxPopupAuthorizationItems());
    s.setValue("POPUP_BUFFER_SIZE", iqfconf->maxPopupAuthorizationItems());
    trayIcon->setPopupOnMatchTimeout(iqfconf->popupMatchingPacketsTimeout());
    s.setValue("POPUP_PACKET_MATCH_TIMEOUT", iqfconf->popupMatchingPacketsTwoNotificationsInterval());
    trayIcon->setPopupOnMatchResolveEnabled(iqfconf->popupMatchingPacketsResolveServices());
    s.setValue("MATCH_RESOLVE_ENABLE", iqfconf->popupMatchingPacketsResolveServices());
    
    /* Pending packets resolver: on the popup notifier (1) and on the pending rules widget (2) */
    /* (1) trayIcon will set on pending tree which will call addInfo with the flag on or off :^D */
    trayIcon->setPopupNotifierResolveEnabled(iqfconf->popupNotifierResolveServices());
    /* (2) pending rules widget will call addInfo with the flag on or off, as for the notifier */
    pending_rules_widget->setResolveEnabled(iqfconf->popupNotifierResolveServices());
    s.setValue("NOTIFIER_RESOLVE_ENABLE", iqfconf->popupNotifierResolveServices());
    
    s.setValue("POPUP_NOTIFY_LISTEN_ONLY", iqfconf->popupNotifyActiveServicesOnly());
    trayIcon->setNotifyActiveServicesOnly(iqfconf->popupNotifyActiveServicesOnly());
    
    s.setValue("ANIMATE_SYSTRAY", iqfconf->systrayAnimationEnabled());
    trayIcon->enableAnimation(iqfconf->systrayAnimationEnabled());
    trayIcon->changeTimerTimeout(iqfconf->systrayAnimationRefreshInterval());
    
    /* paths: the first three require restart */
    s.setValue("PERMISSION_FILENAME", iqfconf->allowedFilename());
    s.setValue("BLACKLIST_FILENAME", iqfconf->denialFilename() );
    s.setValue("TRANSLATION_FILENAME",  iqfconf->natFilename());
    s.setValue("BROWSER_PATHS", QStringList() << iqfconf->htmlDocPaths() <<
    iqfconf->htmlHelpPaths() << iqfconf->htmlManualPaths());
    /* load new text browser paths */
    IQFMessageProxy::msgproxy()->setInfoPath(iqfconf->htmlDocPaths());
    IQFMessageProxy::msgproxy()->setHelpPath(iqfconf->htmlHelpPaths());
    IQFMessageProxy::msgproxy()->setManPath(iqfconf->htmlManualPaths());
    presenter->setSearchPaths(s.value("BROWSER_PATHS").toStringList());
    IQFInfoBrowser::infoBrowser()->setSearchPaths
    (s.value("BROWSER_PATHS").toStringList());
    IQFHelpBrowser::helpBrowser()->setSearchPaths(
    s.value("BROWSER_PATHS").toStringList());
    QString icpath = iqfconf->iconPath();
    
    if(!icpath.endsWith('/'))
      icpath.append('/');
    s.setValue("ICON_PATH", icpath);
    
    /* style sheet */
    s.setValue("QT_DEFAULT_STYLE", iqfconf->defaultStyle());
    s.setValue("QT_STYLE", iqfconf->selectedQTStyle());
    qApp->setStyleSheet(iqfconf->styleSheet());
    s.setValue("STYLESHEET_FILENAME", iqfconf->currentStyleFilename());
    
    /* automatically write on file when rules change */
    ui.pushButtonSaveRulesToFile->setHidden(iqfconf->ui.cBSaveOnFileDirectly->isChecked());
    s.setValue("AUTOSAVE_RULES_ON_CHANGE", iqfconf->ui.cBSaveOnFileDirectly->isChecked());
    
    
    /* timeout for the update of the info/help at enter event of iqfwidgets */
    s.setValue("INTERACTIVE_HINTS_TIMEOUT", iqfconf->helpInfoDelay());
    
    /* natural language */
    if(iqfconf->dictionaryPath() != s.value("DICT_PATH").toString() || 
      iqfconf->selectedLanguage() != s.value("NATURAL_LANGUAGE").toString())
    {
      s.setValue("DICT_PATH", iqfconf->dictionaryPath());
      s.setValue("NATURAL_LANGUAGE", iqfconf->selectedLanguage());
      pok("Reloading dictionaries and grammar from directory \"%s\", language \"%s\"", qstoc(iqfconf->dictionaryPath()),
	   qstoc(iqfconf->selectedLanguage()));
      naturalWidget->reloadDictAndGrammar();
    }
    s.setValue("NATURAL_LANGUAGE_STRICT_SYNTAX_CHECK", iqfconf->strictSyntaxCheck());
    s.setValue("NATURAL_UPDATES_INTERVAL", iqfconf->dictUpdatesInterval());
    s.setValue("NATURAL_UPDATES_ENABLE", iqfconf->dictUpdatesEnabled());
    
    
    if(getuid() == 0)
    {
      /* write the file updated */
      Log::log()->appendMsg("Reloading administrator's settings:");
      Log::log()->appendMsg("Saving the modifications on the option file...");
      iqfconf->saveAdminConfig();
      Log::log()->Ok();
      command com;
      IQFireData::instance()->initCommand(&com);
      Log::log()->appendMsg("Reading the new file...");
      /* NULL if for struct userspace_opts, not needed */
      IQFireData::instance()->GetIQFConfigFromFile(&com, NULL);
      Log::log()->Ok();
      Log::log()->appendMsg("Sending new options to the kernel...");
      IQFireData::instance()->sendOptionsToKernel(&com);
      Log::log()->appendMsg("Reloading options completed");
      
      /* proc entries */
      if(iqfconf->rmemDefault() != IQFInitializer::instance()->procSysNetCoreMemDefault())
	IQFInitializer::instance()->setProcSysNetCoreMemDefault(
	iqfconf->rmemDefault());
      if(iqfconf->rmemMax() != IQFInitializer::instance()->procSysNetCoreMemMax())
	IQFInitializer::instance()->setProcSysNetCoreMemMax(
	iqfconf->rmemMax());
      if(iqfconf->procPolicy() != IQFInitializer::instance()->procPolicy())
	IQFInitializer::instance()->setProcPolicy(iqfconf->procPolicy());
    }
    
    /* software updates */
    s.setValue("PROXY_HOST", iqfconf->proxyHost());
    s.setValue("PROXY_PORT", iqfconf->proxyPort());
    s.setValue("PROXY_USER", iqfconf->proxyUser());
    s.setValue("PROXY_PASSWORD", iqfconf->proxyPassword());
    s.setValue("PROXY_ENABLED", iqfconf->proxyEnabled());
    s.setValue("UPDATES_ENABLED", iqfconf->updatesEnabled());
    s.setValue("UPDATES_INTERVAL", iqfconf->updatesInterval());
    s.setValue("NEXT_UPDATE", s.value("LAST_UPDATE", QDate::currentDate()).toDate().addDays(
    iqfconf->updatesInterval()));  
    
    trayIcon->initCheckableMenuActions();
  }
}

void IQFIREmainwin::hideSearchWidgets()
{
  ui.pushButtonCloseFind->setHidden(true);
  ui.labelSearch->setText("Filter rules: ");
  ui.lineEditFind->setHidden(true);
  ui.comboBoxFind->setHidden(true);
  ui.pushButtonFind->setHidden(true);
}

void IQFIREmainwin::showSearchWidgets()
{
  ui.pushButtonCloseFind->setHidden(false);
  ui.labelSearch->setText("Find: ");
  ui.lineEditFind->setHidden(false);
  ui.comboBoxFind->setHidden(false);
  ui.pushButtonFind->setHidden(false);
}

void IQFIREmainwin::searchInTree()
{
  QString text = ui.lineEditFind->text();
  QList<QTreeWidgetItem *> ruleItems, natItems;
  int i, comboIndex, index = 0;
  comboIndex = ui.comboBoxFind->currentIndex();
  QTreeWidget *filterTree, *natTree;
  if((filterTree = qobject_cast<QTreeWidget*> (ruletree_filter)) != NULL)
  {
    /* clear the selected items */
    ruleItems << filterTree->findItems("*", Qt::MatchWildcard|Qt::MatchRecursive);
    for(i = 0; i < ruleItems.size(); i++)
      if(ruleItems[i]->isSelected())
	ruleItems[i]->setSelected(false);
      ruleItems.clear();
    if(comboIndex < filterTree->columnCount())
      ruleItems << filterTree->findItems(text, Qt::MatchWildcard|Qt::MatchRecursive, comboIndex);
    for(i = 0; i < ruleItems.size(); i++)
      ruleItems[i]->setSelected(true);
  }
  else
    qDebug() << "IQFIREmainwin::searchInTree(): cannot cast!";
  if(ui.widgetNat->isVisible() && ((natTree =  qobject_cast<QTreeWidget*> (ruletree_nat)) != NULL))
  {
    natItems << filterTree->findItems("*", Qt::MatchWildcard|Qt::MatchRecursive);
    for(i = 0; i < natItems.size(); i++)
      if(natItems[i]->isSelected())
	natItems[i]->setSelected(false);
      natItems.clear();
    
    if(comboIndex != 8 && comboIndex != 9) /* notify and stateful */
    {
      /*tcp flags has the same position: 10 */
      if(comboIndex > 10)
	index = comboIndex - 3;
      else 
	index = comboIndex;
    }
    if(index < natTree->columnCount())
    {
      natItems << natTree->findItems(text, Qt::MatchWildcard|Qt::MatchRecursive, index);
      for(i = 0; i < natItems.size(); i++)
	natItems[i]->setSelected(true);
    }
  }
  
}

void IQFIREmainwin::activateSearchAction(int page)
{
  if(page == 3) /* rule tree */
    ui.actionSearch->setVisible(true);
  else
    ui.actionSearch->setVisible(false);
}

void IQFIREmainwin::infoAndHelpForRuleScene()
{
  ui.stackedWidgetMain->setInfoAndHelpForPage(6, false);
}

void IQFIREmainwin::infoAndHelpForPage(int page)
{
  if(page == 0 && ui.checkBoxApplyFilter->isChecked())
  {
    /* filter is active and we are showing the console: the info
    * will contain the current setup filter.
    */
    reloadFilterInfo();
  }
  else
    ui.stackedWidgetMain->setInfoAndHelpForPage(page, false);
}

void IQFIREmainwin::blockInterfaceWhileAddingRule(bool block)
{
  ui.menubar->setDisabled(block);
  ui.toolBarNavigation->setDisabled(block);
  ui.toolBarPages->setDisabled(block);
  ui.stackedWidgetMain->setDisabled(block);
}

void IQFIREmainwin::lookForUpdates()
{
  if(!iqfconf->updatesEnabled())
    return;
  updates->lookForUpdates();
}

void IQFIREmainwin::about()
{
  openManualAtPage(QUrl("manual://about.html"));
  presenter->substitute("$VERSION", VERSION);
  presenter->substitute("$FIREDATE", FIREDATE);
  presenter->substitute("$LATEST_KERNEL_SUPPORTED", LATEST_KERNEL_SUPPORTED);
  presenter->substitute("$_CODENAME", _CODENAME);
  presenter->substitute("$AUTHOR", AUTHOR);
  presenter->substitute("$USPACE_BUILD_SYS", USPACE_BUILD_SYS);
  presenter->substitute("$USPACE_BUILD_DATE", USPACE_BUILD_DATE);
}

void IQFIREmainwin::setupButtonIcons()
{
  QSettings s; /* for ICON_PATH */
  ui.pushButtonFind->setIcon(QIcon(ICON_PATH + "search.png"));
  ui.pushButtonCloseFind->setIcon(QIcon(ICON_PATH + "stop.png"));
  ui.pushButtonApply->setIcon(QIcon(ICON_PATH + "ok-gray.png"));
  ui.pushButtonSaveRulesToFile->setIcon(QIcon(ICON_PATH + "save.png"));
  ui.pushButtonUndoRuleTreeChanges->setIcon(QIcon(ICON_PATH + "undo.png"));
  ui.pbConfApply->setIcon(QIcon(ICON_PATH + "ok-gray.png"));
  ui.pbConfCancel->setIcon(QIcon(ICON_PATH + "back.png"));
  ui.pushButtonRemoveSelected->setIcon(QIcon(ICON_PATH + "user-trash.png"));
  ui.pushButtonClearNotified->setIcon(QIcon(ICON_PATH + "clear.png"));
  ui.checkBoxApplyFilter->setIcon(QIcon(ICON_PATH + "filter.png"));
  ui.pushButtonCloseConsoleSettings->setIcon(QIcon(ICON_PATH + "back.png"));
  
}

void IQFIREmainwin::updateWindowTitle(int page)
{
  QSettings s; /* for ICON_PATH */
  switch(page)
  {
    case 0:
      setWindowTitle("IQFire: firewall console window");
      setWindowIcon(QIcon(ICON_PATH + "console.png"));
      break;
    case NOTIFIED_PACKETS:
      setWindowTitle("IQFire: notified packets in this session");
      setWindowIcon(QIcon(ICON_PATH + "notified.png"));
      break;
    case CONF_CONSOLE:
      setWindowTitle("IQFire: console settings and filter");
      setWindowIcon(QIcon(ICON_PATH + "filter.png"));
      break;
    case TREEVIEW:
      setWindowTitle("IQFire: rule tree window");
      setWindowIcon(QIcon(ICON_PATH + "ruletree.png"));
      break;	
    case STATS:
      setWindowTitle("IQFire: statistics window");
      setWindowIcon(QIcon(ICON_PATH + "stats.png"));
      break;	
      case NATURAL_LANGUAGE:
      setWindowTitle("IQFire: Natural language rule editor");
      setWindowIcon(QIcon(ICON_PATH + "natural_language.png"));
      break;
    case PENDING_RULES:
      setWindowTitle("IQFire: connections waiting for authorization...");
      setWindowIcon(QIcon(ICON_PATH + "pending_rules.png"));
      break;	
    case GRAPHICSVIEW:
      setWindowTitle("IQFire: linux routing view and firewalling");
      setWindowIcon(QIcon(ICON_PATH + "ruleview.png"));
      break;		
    case SETTINGS:
      setWindowTitle("IQFire: firewall and user interface configuration");
      setWindowIcon(QIcon(ICON_PATH + "configure.png"));
      break;	
    case DOCBROWSER:
      setWindowTitle("IQFire: the firewall manual");
      setWindowIcon(QIcon(ICON_PATH + "manual.png"));
      break;	
    case STATE_TABLES:
      setWindowTitle("IQFire: kernel state tables");
      break;
    case SNAT_TABLES:
      setWindowTitle("IQFire: kernel source nat tables");
      break;
    case DNAT_TABLES:
      setWindowTitle("IQFire: kernel destination nat tables");
      break;
    case KMEMORY:
      setWindowTitle("IQFire: kernel tables memory usage over time");
      break;
    case LOGS:
      setWindowTitle("IQFire: logs");
      break;
    default:
      setWindowTitle("IQFire: unknown page!!");
      break;	
  }
}

void IQFIREmainwin::newTrafficIface(const QString& name)
{	
  QString title = QString("Traffic toolbar for interface %1").arg(name);
  IQFTrafficToolBar *trafTool = new IQFTrafficToolBar(name, title, this);
  /* insert the dynamic toolbars before the last one */
  insertToolBar(ui.toolBar, trafTool);
}


