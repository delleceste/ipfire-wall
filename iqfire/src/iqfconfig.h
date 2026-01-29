#ifndef IQFCONFIG_H
#define IQFCONFIG_H

#include "iqfwidgets.h"
#include <ui_config.h>
#include <QWidget>

class StylesheetLoader;

class IQFConfig : public QWidget
{
	Q_OBJECT
	public:
		IQFConfig(QWidget *parent);
		
		/* The following four need to provide a terminating '/' in the path
		 * if not provided by the user in the line edit 
		 */
		QString htmlDocPaths();
		QString htmlHelpPaths();
		QString htmlManualPaths();
		QString iconPath();
		QString allowedFilename() { return ui.lEPermissionFile->text(); }
		QString denialFilename() { return ui.lEDenialFile->text(); }
		QString natFilename() { return ui.lENatFile->text(); }
		
		QString styleSheet();
		QString currentStyleFilename();
		bool defaultStyle(); 
		QString selectedQTStyle();
		
		int helpInfoDelay() { return ui.sBHelpInfoDelay->value(); }
		
		QString proxyHost() { return ui.lEProxyHost->text(); }
		unsigned short proxyPort() { return ui.spinBoxProxyPort->value(); }
		QString proxyUser() { return ui.lEProxyUser->text(); }
		QString proxyPassword() { return ui.lEProxyPassword->text(); }
		bool proxyEnabled() {return ui.groupBoxProxy->isChecked(); }
		int updatesInterval() { return ui.sBUpdatesInterval->value(); }
		int updatesEnabled() { return ui.cbSwUpdatesEnable->isChecked(); }
		
		bool systrayAnimationEnabled() { return ui.gBAnimateSystray->isChecked(); }
		int systrayAnimationRefreshInterval() { return ui.sBAnimationSpeed->value(); }
		bool popupAuthorizationEnabled() { return ui.gBPupNotifier->isChecked(); }
		int maxPopupAuthorizationItems() { return ui.sbMaxPopupElems->value(); }
		
		bool popupMatchingPacketsEnabled() { return ui.gBPupMatch->isChecked(); }
		int popupMatchingPacketsTimeout() { return ui.sbMatchPopupTimeout->value(); }
		int popupMatchingPacketsTwoNotificationsInterval() { return ui.sbBetweenMatches->value(); }
		bool popupMatchingPacketsResolveServices() { return ui.checkBoxResolveServices->isChecked(); }
		bool popupNotifierResolveServices() { return ui.cBResolveNotifier->isChecked(); }
		bool popupNotifyActiveServicesOnly() { return ui.cBNotifyListeningOnly->isChecked(); }
		
		unsigned rmemMax() { return ui.sBProcRmemMax->value(); }
		unsigned rmemDefault() { return ui.sBProcRmemDefault->value(); }
		int procPolicy();
		
		bool startupIconified() { return ui.cBStartIconified->isChecked(); }
		bool autostart() { return ui.cBAutostart->isChecked(); }
		
		bool isUserAllowed() { return ui.cbAllowUser->isChecked(); }
		bool autoSaveRules() { return ui.cBSaveOnFileDirectly->isChecked(); }
		int trafficRefreshInterval() { return ui.sBTrafficProxyInterval->value(); }
		
		QString dictionaryPath() { return ui.leDictPath->text(); }
		QString selectedLanguage() { return ui.cbLanguage->currentText(); }
		bool strictSyntaxCheck() { return ui.cbStrictSyntax->isChecked(); }
		int dictUpdatesInterval() { return ui.sbDictUpdatesInterval->value(); }
		bool dictUpdatesEnabled() { return ui.gbDictUpdates->isChecked(); }
		
		void saveAdminConfig();
		
		Ui::IQFConfig ui;
		
	signals:
		void systrayAnimationSpeedChanged(int);
		void enableSystrayAnimation(bool);
		
		void enableUnseenPopup(bool);
		void maxElementsInUnseenPopup(int);
		
		void enablePopupMatching(bool);
		void popupMatchingTimeoutChanged(int);
		void popupMatchingSamePacketTimeoutChanged(int);
		
		void styleChanged(const QString &);
		
		void updateNaturalLanguage();
		
	protected:
		void showEvent(QShowEvent *e);
		
	public slots:
		void undoChanges();
		void refreshUpdateInfoLabel();
		void reloadSettings();
		void naturalDictUpdated(int);
		
	protected slots:
		void checkUpdatesNow();
		void restoreDefaults1();
		void restoreDefaults2();
		void restoreNaturalLanguageDefaults();
		void rectanglesSelected(bool);
		void naturalUpdatesIntervalChanged(int);
		void emit_updateNaturalLanguage() { emit updateNaturalLanguage(); }

	private:
		
		void initWidgets();
		void initAdvancedTab();
		void loadLanguagesInCombo();
		
		StylesheetLoader *styleLoader;
};




#endif


