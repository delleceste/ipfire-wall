#include "stylesheet_loader.h"
#include "iqfconfig.h"
#include "iqfiredata.h"
#include "iqflog.h"
#include "iqf_updates.h"
#include <ipfire_structs.h>
#include <QSettings>
#include <QString>
#include <QtDebug>
#include <QVBoxLayout>
#include <QDir>
#include <QDate>
#include "iqfinit.h"
#include <dictionary.h> /* for dictionary reload after settings changed */

extern"C"
{
	void init_command(command* cmd);
}

IQFConfig::IQFConfig(QWidget *parent) : QWidget(parent)
{
	ui.setupUi(this);
	styleLoader = NULL;
	QSettings s;
	
	styleLoader = new StylesheetLoader(ui.tabStyle);
	initWidgets(); /* in showEvent */
	QVBoxLayout *lo = new QVBoxLayout(ui.tabStyle);
	if(lo != NULL)
		lo->addWidget(styleLoader);
	
	connect(ui.cbSwUpdatesEnable, SIGNAL(toggled(bool)), ui.labelCheckSwUpdates, SLOT(
		setEnabled(bool)));
	connect(ui.cbSwUpdatesEnable, SIGNAL(toggled(bool)), ui.sBUpdatesInterval, SLOT(
		setEnabled(bool)));
	connect(ui.cbSwUpdatesEnable, SIGNAL(toggled(bool)), ui.groupBoxProxy, SLOT(
		setEnabled(bool)));
	connect(ui.pBCheckUpdates, SIGNAL(clicked()), this, SLOT(checkUpdatesNow()));
	connect(ui.pBDefault1, SIGNAL(clicked()), this, SLOT(restoreDefaults1()));
	connect(ui.pBDefault2, SIGNAL(clicked()), this, SLOT(restoreDefaults2()));
	connect(ui.pbDefaultDictPath, SIGNAL(clicked()), this, SLOT(restoreNaturalLanguageDefaults()));
	connect(ui.rBRectangles, SIGNAL(toggled(bool)), this, SLOT(rectanglesSelected(bool)));
	connect(ui.sbDictUpdatesInterval, SIGNAL(valueChanged(int)), this, SLOT(naturalUpdatesIntervalChanged(int)));
	connect(ui.pbCheckNaturalUpdatesNow, SIGNAL(clicked()), this, SLOT(emit_updateNaturalLanguage()));
}

void IQFConfig::initWidgets()
{
	QSettings s;
	
	styleLoader->setupWidget();
	ui.cBStartIconified->setChecked(s.value("STARTUP_HIDDEN", false).toBool());
	ui.cBAutostart->setChecked(s.value("AUTOSTART", false).toBool());
	ui.cBSaveOnFileDirectly->setChecked(s.value("AUTOSAVE_RULES_ON_CHANGE", true).toBool());
	ui.sBTrafficProxyInterval->setValue(s.value("TRAFFIC_UPDATE_INTERVAL", 1000).toInt());
	
	ui.gBAnimateSystray->setChecked(s.value("ANIMATE_SYSTRAY", true).toBool());
	ui.sBAnimationSpeed->setValue(s.value("SYSTRAY_REFRESH_TIMEOUT_MILLIS", 800).toInt());
	ui.dSBMeanAdjustFactor->setValue(s.value("SYSTRAY_MEAN_ADJUST_FACTOR", 2.5).toDouble());
	ui.cBNeedleArrows->setChecked(s.value("SYSTRAY_ARROWS_ENABLED", true).toBool());
	ui.dSBBlockNeedle->setValue(s.value("SYSTRAY_BLOCK_NEEDLE_LEN", 0.8).toDouble());
	ui.dSBAllowNeedle->setValue(s.value("SYSTRAY_ALLOW_NEEDLE_LEN", 1.0).toDouble());
	ui.rBCircularGauge->setChecked(s.value("ICON_CIRCULAR_GAUGE", true).toBool());
	ui.rBRectangles->setChecked(!s.value("ICON_CIRCULAR_GAUGE", true).toBool());
	ui.spinBoxAlpha->setValue(s.value("SYSTRAY_ALPHA_CHANNEL", 127).toInt());
	
	ui.gBPupNotifier->setChecked(s.value("POPUP_ENABLE", true).toBool());
	ui.cBNotifyListeningOnly->setChecked(s.value("POPUP_NOTIFY_LISTEN_ONLY", true).toBool());
	ui.sbMaxPopupElems->setValue(s.value("POPUP_BUFFER_SIZE", 10).toInt());
	
	
	ui.gBPupMatch->setChecked(s.value("POPUP_ON_MATCH", true).toBool());
	ui.sbMatchPopupTimeout->setValue(s.value("NOTIFY_WIDGET_TIMEOUT", 5).toInt());
	ui.sbBetweenMatches->setValue(s.value("POPUP_PACKET_MATCH_TIMEOUT", 600).toInt());
	ui.checkBoxResolveServices->setChecked(s.value("MATCH_RESOLVE_ENABLE", true).toBool());
	
	QString permission_filename = s.value("PERMISSION_FILENAME", 
				      QVariant(QDir::homePath() + QString("/.IPFIRE/allowed"))).toString();
	QString blacklist_filename = s.value("BLACKLIST_FILENAME", 
				     QVariant(QDir::homePath() + QString("/.IPFIRE/blacklist"))).toString();
	QString translation_filename = s.value("TRANSLATION_FILENAME",
				       QVariant(QDir::homePath() + QString("/.IPFIRE/translation"))).toString();
	QString icon_path = s.value("ICON_PATH", QString("/usr/share/iqfire/icons/")).toString();
	if(!icon_path.endsWith('/'))
		icon_path.append('/');
	
	ui.lEPermissionFile->setText(permission_filename);
	ui.lEDenialFile->setText( blacklist_filename);
	ui.lENatFile->setText( translation_filename);
	ui.lEIconPath->setText( icon_path);
	
	if(getuid() != 0)
	{
		ui.lENatFile->setDisabled(true);
		ui.tabAdvanced->setDisabled(true);
	}
	
	QStringList paths = s.value("BROWSER_PATHS", BROWSER_DEFAULT_PATHS).toStringList();
	if(paths.size() == 3)
	{
		ui.lEDocPaths->setText(paths[0]);
		ui.lEHelpPaths->setText(paths[1]);
		ui.lEManualPaths->setText(paths[2]);	
	}
	
	ui.sBHelpInfoDelay->setValue(s.value("INTERACTIVE_HINTS_TIMEOUT", 750).toInt());
	
	/* software updates */
	ui.lEProxyHost->setText(s.value("PROXY_HOST", "").toString());;
	ui.spinBoxProxyPort->setValue(s.value("PROXY_PORT", 8080).toUInt());
	ui.lEProxyUser->setText(s.value("PROXY_USER", "").toString());
	ui.lEProxyPassword->setText(s.value("PROXY_PASSWORD", "").toString());
	ui.groupBoxProxy->setChecked(s.value("PROXY_ENABLED", false).toBool());
	ui.cbSwUpdatesEnable->setChecked(s.value("UPDATES_ENABLED", true).toBool());
	ui.sBUpdatesInterval->setValue(s.value("UPDATES_INTERVAL", 5).toInt());
	
	/* natural language */
	/* natural language is loaded from the natural language library. It is necessary to have 
	 * DICT_PATH qsettings key always available otherwise the library sets up a default value
	 * 'dictionary', which is not iqfire aware.
	 */
	QVariant v = s.value("DICT_PATH");
	if(v == QVariant()) /* no value was set */
	  s.setValue("DICT_PATH", "/usr/share/iqfire/natural_language/dictionary");
	ui.leDictPath->setText(s.value("DICT_PATH", "/usr/share/iqfire/natural_language/dictionary").toString());
	loadLanguagesInCombo(); /* fill combo with available languages in DICT_PATH and select the one in use */
	ui.cbStrictSyntax->setChecked(s.value("NATURAL_LANGUAGE_STRICT_SYNTAX_CHECK", false).toBool());
	/* hide strict syntax checking widgets: don't know if we use it.. */
	ui.gbStrictSyntax->setHidden(true);
	
	ui.gbDictUpdates->setChecked(s.value("NATURAL_UPDATES_ENABLE", true).toBool());
	ui.sbDictUpdatesInterval->setValue(s.value("NATURAL_UPDATES_INTERVAL", 1).toInt());
	
	refreshUpdateInfoLabel();
	pok("configuration changed: reloading dictionary from directory \"%s\"", qstoc(s.value("DICT_PATH").toString()));
	Dictionary::instance()->reload();
	
	initAdvancedTab();
}

void IQFConfig::undoChanges()
{
	qDebug() << "undo changes";
	initWidgets();
}

QString IQFConfig::styleSheet() 
{
	QString s;
	 if(styleLoader != NULL) 
	 { 
		 s = styleLoader->currentStyle(); 
	 }
	 return s; 
}

QString IQFConfig::currentStyleFilename() 
{
	QString s;
	if(styleLoader != NULL) 
	{ 
		s = styleLoader->currentStyleFilename(); 
	}
	return s; 
}


void IQFConfig::initAdvancedTab()
{
	command com;
	int rmem_max, rmem_default;
	short policy;
	init_command(&com);
	IQFireData::instance()->GetIQFConfigFromFile(&com, NULL);
	
	ui.cbMasq->setChecked(com.masquerade);
	ui.cbNat->setChecked(com.nat);
	ui.sbMaxNatTables->setValue(com.max_nat_entries);
	ui.cbStateful->setChecked(com.stateful);
	ui.sbMaxStateTables->setValue(com.max_state_entries);
	ui.spinBoxLoginfoTimeout->setValue(com.loginfo_lifetime);
	ui.sbMaxLogEntries->setValue(com.max_loginfo_entries);
	ui.cbNoFlush->setChecked(com.noflush_on_exit);
	
// // // 	ui.comboBoxLoguser->setCurrentText(QString("Level: %1").arg(com.loguser));
	ui.cbAllowUser->setChecked(com.user_allowed);
	
	/* proc entries: read the values currently in /proc.
	*/
	IQFInitializer *iqfi = IQFInitializer::instance();
	rmem_default = iqfi->procSysNetCoreMemDefault();
	rmem_max = iqfi->procSysNetCoreMemMax();
	policy = iqfi->procPolicy();
	
	if(policy > 0)
		ui.rBDefPolicyAllow->setChecked(true);
	else
		ui.rBDefPolicyDeny->setChecked(true);
	ui.sBProcRmemDefault->setValue(rmem_default);
	ui.sBProcRmemMax->setValue(rmem_max);
	
}

int IQFConfig::procPolicy()
{
	if(ui.rBDefPolicyAllow->isChecked())
		return 1;
	else 
		return 0;
}

void IQFConfig::showEvent(QShowEvent *e)
{
	refreshUpdateInfoLabel();
	QWidget::showEvent(e);
}

void IQFConfig::refreshUpdateInfoLabel()
{
	QSettings s;
	ui.labelNextUpdate->setText(QString("Next check for updates scheduled on %1"
			" (last check dates back to %2)").arg
			(s.value("NEXT_UPDATE", QDate::currentDate()).toDate().toString()).
			arg(s.value("LAST_UPDATE", QDate::currentDate()).toDate().toString()));
}

void IQFConfig::reloadSettings()
{
	initWidgets();
}

void IQFConfig::loadLanguagesInCombo()
{
  QSettings s;
  QString dictPath = s.value("DICT_PATH", "/usr/share/iqfire/natural_language/dictionary").toString();
  QString language = s.value("NATURAL_LANGUAGE", "italiano").toString();
  QDir dir(dictPath);
  QStringList nameFilters;
  QStringList entries = dir.entryList(nameFilters, QDir::AllDirs, QDir::Name );
  ui.cbLanguage->clear();
  entries.removeAll(QString("."));
  entries.removeAll(QString(".."));
  ui.cbLanguage->insertItems(0, entries);
  qDebug() << "combo cerco " << language << "in entries " << entries;
  int index = ui.cbLanguage->findText(language);
  qDebug() << "index di combo language" << index;
  ui.cbLanguage->setCurrentIndex(index);
}


void IQFConfig::rectanglesSelected(bool s)
{
  if(s)
    ui.spinBoxAlpha->setValue(120);
  else
    ui.spinBoxAlpha->setValue(220);
}

void IQFConfig::saveAdminConfig()
{
	QSettings s;
	if(getuid() == 0)
	{
		/* save the changed options to the file */
		QString optionsFileName = s.value("IPFIRE_CONFDIR", 
				QVariant(QDir::homePath() + QString("/.IPFIRE/options"))).toString();
		QFile optFile(optionsFileName);
		if(!optFile.open(QIODevice::WriteOnly | QIODevice::Text))
		{
			Log::log()->appendFailed(QString("Failed to open file \"%1\" for writing (%2)").
					arg(optionsFileName).arg(optFile.error()));
		}
		else
		{
			QTextStream out(&optFile);
				out << "# Global options for IPFIRE-wall and its GUI version IqFIRE-wall\n"
					"# This file has been generated by IqFIREWALL and is fully\n"
					"# compatible with IPFIRE-wall command line version.\n"
					"# The difference is that IqFIREWALL just considers the administrator's\n"
					"# options and no more the normal user's ones.\n"
					"#\n"
					"# This means that if you mean to use the command line, you must\n"
					"# uncomment the lines below, in the section\n"
					"# \"Normal user IPFIRE-wall options\".\n"
					"# Such options are always commented out by IqFIREWALL, and so they\n"
					"# are lost everytime IqFIREWALL writes on this file.\n"
					"# NOTE: IqFIREWALL never writes on this file if the user is not root!\n"
					"# For normal users  (that are not root), IqFIREWALL does not consider\n"
					"# this file.\n"
					"#\n"
					"# See the documentation of IPFIRE-wall for further details.\n"
					"# Write to delleceste@gmail.com for help/questions.\n"
					"#\n"
					"# Copyright (C) 2007 Giacomo Strangolino.\n"
					"#\n#\n";
				/* get the options from the config ui */
				
				/* 1. NAT */
				if(ui.cbNat->isChecked())
					out << "\n# Nat is globally enabled:\nNAT=YES\n";
				else
					out << "\n# Nat is globally disabled:\nNAT=NO\n";
				
				if(ui.cbMasq->isChecked())
					out << "\n# Masquerade is globally enabled:\nMASQUERADE=YES\n";
				else
					out << "\n# Nat is globally disabled:\nMASQUERADE=NO\n";
				
				out << "\n# Maximum number of NAT tables in the kernel:\n"
					<< QString("MAX_NAT_ENTRIES=%1\n").arg(ui.sbMaxNatTables->value());
				
				/* 2. State connection */
				if(ui.cbStateful->isChecked())
					out << "\n# State machine is globally enabled:\nSTATEFUL=YES\n";
				else
					out << "\n# Nat is globally disabled:\nSTATEFUL=NO\n";
				
				out << "\n# Maximum number of STATE tables in the kernel:\n"
					<< QString("MAX_STATE_ENTRIES=%1\n").arg(ui.sbMaxStateTables->value());
				
				/* 3. kernel/user communication */
				out << "\n# Time to live of an information entry in the kernel:\n";
				out << QString("LOGINFO_LIFETIME=%1\n").arg(ui.spinBoxLoginfoTimeout->value());
				
				out << "\n# Maximum number of information entries in the kernel:\n";
				out << QString("MAX_LOGINFO_ENTRIES=%1\n").arg(ui.sbMaxLogEntries->value());
				
				out << "\n# Log level between kernel and user spaces:\n";
				int logu, curInd = ui.comboBoxLoguser->currentIndex();
				if(curInd == 0)
					logu = 1;
				else if(curInd == 1)
					logu = 0;
				else if(curInd == 2)
					logu = 2;
				else
					logu = curInd + 1;
				
				qDebug() << "loguser set to " << logu;
				out << QString("LOGUSER=%1\n").arg(logu);
					
				if(ui.cbAllowUser->isChecked())
					out << "# User is allowed to insert his rules:\nUSER_ALLOWED=YES\n";
				else
					out << "# User is not allowed to insert his rules:\nUSER_ALLOWED=NO\n";
				
				if(ui.cbNoFlush->isChecked())
					out << "# Do NOT flush rules at exit:\nNOFLUSH_ON_EXIT=YES\n";
				else
					out << "# Flush rules at exit:\nNOFLUSH_ON_EXIT=NO\n";
				
				out << "# Tune the /proc/sys/net/core/rmem_max and rmem_default\n";
				out << "# this must be changed only if you experience problems\n";
				out << "# with the netlink communication.\n#\n";
				out << QString("PROC_RMEM_DEFAULT=%1\n").arg(ui.sBProcRmemDefault->value());
				out << "#\n";
				out << QString("PROC_RMEM_MAX=%1\n").arg(ui.sBProcRmemMax->value());
				out << "#\n";
				out << "# The default policy for the packets which do not match a rule:\n#\n";
				if(ui.rBDefPolicyDeny->isChecked())
					out << QString("PROC_IPFIRE_POLICY=%1\n").arg(0);
				else if(ui.rBDefPolicyAllow->isChecked())
					out << QString("PROC_IPFIRE_POLICY=%1\n").arg(1);
				
				
				out << "\n#\n#\n";
				out << "# Normal user IPFIRE-wall options:\n";
				out << "# RESOLVE_SERVICES=YES\n"
					"# MAILER_OPTIONS_FILENAME=/path/to/mailer/options\n"
					"# LOGFILENAME=/path/to/logfile\n"
					"# LANGUAGE_FILENAME=path/to/filename\n"
					"# LOGLEVEL=\n"
					"# RESOLVE_SERVICES=YES\n"
					"# DNS_RESOLVE=YES\n"
					"# DNS_REFRESH=1800\n"
					"# ...\n"
					"#\n# See the manual for other options\n"
					"#\n"
					"# End of configuration file\n"
					"#\n";
						
			optFile.close();
			
		} /* file open */
	}
}

void IQFConfig::checkUpdatesNow()
{
	IQFUpdates *upd = new IQFUpdates(this);
	connect(upd, SIGNAL(updateFinished()), this, SLOT(refreshUpdateInfoLabel()));
	upd->downloadVersion();
}
void IQFConfig::restoreDefaults1()
{
	QString home = QDir::homePath();
	ui.lEPermissionFile->setText(home + "/.IPFIRE/allowed");
	ui.lEDenialFile->setText(home + "/.IPFIRE/blacklist");
	if(getuid() == 0)
		ui.lENatFile->setText(home + "/.IPFIRE/translation");
	ui.lEIconPath->setText("/usr/share/iqfire/icons/");
}	

void IQFConfig::restoreDefaults2()
{
	ui.lEDocPaths->setText("/usr/share/iqfire/doc/info/");
	ui.lEHelpPaths->setText("/usr/share/iqfire/doc/help/");
	ui.lEManualPaths->setText("/usr/share/iqfire/doc/manual/");
}

void IQFConfig::restoreNaturalLanguageDefaults()
{
  ui.leDictPath->setText("/usr/share/iqfire/natural_language/dictionary");
}

QString IQFConfig::htmlDocPaths()
{
	QString path = ui.lEDocPaths->text();
	if(!path.endsWith('/'))
		   path.append('/');
	return path;
}

QString IQFConfig::htmlHelpPaths()
{
	QString path = ui.lEHelpPaths->text();
	if(!path.endsWith('/'))
		path.append('/');
	return path;
}

QString IQFConfig::htmlManualPaths()
{
	QString path = ui.lEManualPaths->text();
	if(!path.endsWith('/'))
		path.append('/');
	return path;
}

QString IQFConfig::iconPath()
{
	QString path = ui.lEIconPath->text();
	if(!path.endsWith('/'))
		path.append('/');
	return path;
}

bool IQFConfig::defaultStyle()
{
	if(styleLoader != NULL)
		return styleLoader->defaultStyle();
	else
		return true;
}

QString IQFConfig::selectedQTStyle()
{
	if(styleLoader != NULL)
		return styleLoader->selectedQtStyle();
	else
		return "Oxygen";
}

void IQFConfig::naturalDictUpdated(int v)
{
  QSettings s;
  QString lang = s.value("NATURAL_LANGUAGE", "italiano").toString();
  QString dateTime = QDateTime::currentDateTime().toString();
  ui.labelCurrentVersion->setText(QString("Updated %1 dictionary to version %2 on %3").arg(lang).arg(v).arg(dateTime));
}

void IQFConfig::naturalUpdatesIntervalChanged(int i)
{
  if(i > 1)
    ui.labelDictUpdatesDays->setText("days.");
  else
    ui.labelDictUpdatesDays->setText("day.");
}

