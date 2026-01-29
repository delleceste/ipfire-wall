#include "iqfire.h"
#include "iqf_message_proxy.h"

#include <QSettings>
#include <QTextBrowser>

void IQFIREmainwin::initSettingsForSidePanel()
{
	QSettings s;
	QString info_s, help_s, navigation_s;
	int i;
	if(!s.contains("INFO_BROWSER_0"))
		s.setValue("INFO_BROWSER_0", false);
	if(!s.contains("HELP_BROWSER_0"))
		s.setValue("HELP_BROWSER_0", false);
	if(!s.contains("NAVIGATION_BROWSER_0"))
		s.setValue("NAVIGATION_BROWSER_0", true);
	
	for(i = 1; i < ui.stackedWidgetMain->count(); i++)
	{
		info_s = QString("INFO_BROWSER_%1").arg(i);
		help_s = QString("HELP_BROWSER_%1").arg(i);
		navigation_s = QString("NAVIGATION_BROWSER_%1").arg(i);
		
		if(!s.contains(info_s))
			s.setValue(info_s, true);
		if(!s.contains(help_s))
			s.setValue(help_s, true);
		if(!s.contains(navigation_s))
			s.setValue(navigation_s, false);
	}
}

void IQFIREmainwin::navigationBrowserLinkClicked(const QString &link)
{
	Q_UNUSED(link);
}

void IQFIREmainwin::showNavigationPanel(bool show)
{
	QSettings s;
	if(show)
	{
		if(infoPanelAct->isChecked())
			infoPanelAct->setChecked(!show);
		if(helpPanelAct->isChecked())
			helpPanelAct->setChecked(!show);
		
		if(ui.stackedWidgetBrowser->isHidden())
			ui.stackedWidgetBrowser->setHidden(false);
		
		if(ui.splitterMain->sizes()[1] == 0)
			if(!ui.splitterMain->beenMoved())
				ui.splitterMain->restoreState(s.value("SPLITTERMAIN_SIZES", splitterDefaultSize).toByteArray());
		
		ui.stackedWidgetBrowser->setCurrentIndex(1);
		if(!ui.splitterMain->beenMoved())
// 			ui.stackedWidgetBrowser->resize(width() * 2 / 5, ui.stackedWidgetBrowser->height());
			ui.splitterMain->restoreState(s.value("SPLITTERMAIN_SIZES", splitterDefaultSize).toByteArray());
// 			ui.splitterMain->setSizes(QList<int>() << 10 << 4);
	}
	else
	{
		ui.stackedWidgetBrowser->setCurrentIndex(0);
		if(!infoPanelAct->isChecked() && !helpPanelAct->isChecked())
			ui.stackedWidgetBrowser->setHidden(true);
	}
}

void IQFIREmainwin::showHelpPanel(bool show)
{
	QSettings s;
	ui.labelHelpOrStats->setVisible(show);
	ui.stackedWidgetHelpOrStats->setVisible(show);
	
	if(ui.stackedWidgetBrowser->currentIndex() == 1) /* navigation shown */
		ui.stackedWidgetBrowser->setCurrentIndex(0);
	
	if(show)
	{
		ui.labelHelpOrStats->setText("Help:");
		if( ui.stackedWidgetHelpOrStats->currentIndex() == 1)
		   ui.stackedWidgetHelpOrStats->setCurrentIndex(0);
		if(navigationPanelAct->isChecked())
			navigationPanelAct->setChecked(false);
		
		if(ui.splitterMain->sizes()[1] == 0)
			if(!ui.splitterMain->beenMoved())
				ui.splitterMain->restoreState(s.value("SPLITTERMAIN_SIZES", splitterDefaultSize).toByteArray());
// 				ui.splitterMain->restoreState(s.value("SPLITTERMAIN_SIZES", splitterDefaultSize).toByteArray());
// 				ui.splitterMain->setSizes(QList<int>() << 10 << 5);
		
		if(ui.stackedWidgetBrowser->isHidden())
			ui.stackedWidgetBrowser->setHidden(false);
		
		if(navigationPanelAct->isChecked())
			navigationPanelAct->setChecked(false);
		
		if(infoPanelAct->isChecked()) /* show both help and info */
		{
				ui.labelInfo->setVisible(true);
				ui.widgetInfoBrowser->setVisible(true);
				ui.splitterInfoHelp->setSizes(QList<int>() << 5 << 5);
		}
		else /* show help but not info */
		{
				ui.labelInfo->setVisible(false);
				ui.widgetInfoBrowser->setVisible(false);
				ui.splitterInfoHelp->setSizes(QList<int>() << 0 << 10);
		}
	}
	else
	{
		if(infoPanelAct->isChecked()) 
			ui.splitterInfoHelp->setSizes(QList<int>() << 10 << 0);
		else /* help and info disabled, navigation disabled */
		{
			ui.stackedWidgetBrowser->setHidden(true);
		}
	}
}
		
void IQFIREmainwin::showInfoPanel(bool show)
{
	QSettings s;
	ui.labelInfo->setVisible(show);
	ui.widgetInfoBrowser->setVisible(show);
	
	if(ui.stackedWidgetBrowser->currentIndex() == 1) /* navigation shown */
		ui.stackedWidgetBrowser->setCurrentIndex(0);
	
	if(show)
	{
		if(navigationPanelAct->isChecked())
			navigationPanelAct->setChecked(false);
		if(ui.splitterMain->sizes()[1] == 0)
			if(!ui.splitterMain->beenMoved())
// 				ui.stackedWidgetBrowser->resize(width() * 2 / 5, ui.stackedWidgetBrowser->height());
				ui.splitterMain->restoreState(s.value("SPLITTERMAIN_SIZES", splitterDefaultSize).toByteArray());
// 				ui.splitterMain->setSizes(QList<int>() << 10 << 5);
		
		if(ui.stackedWidgetBrowser->isHidden())
			ui.stackedWidgetBrowser->setHidden(false);
		
		if(helpPanelAct->isChecked()) /* show both help and info */
		{
				ui.labelHelpOrStats->setHidden(false);
				ui.stackedWidgetHelpOrStats->setHidden(false);
				ui.splitterInfoHelp->setSizes(QList<int>() << 5 << 5);
		}
		else
		{
				ui.labelHelpOrStats->setHidden(true);
				ui.stackedWidgetHelpOrStats->setHidden(true);
				ui.splitterInfoHelp->setSizes(QList<int>() << 10 << 0);
		}
	}
	else
	{
		if(helpPanelAct->isChecked())  /* only help panel */
		{
				ui.labelInfo->setVisible(false);
				ui.widgetInfoBrowser->setVisible(false);
				ui.splitterInfoHelp->setSizes(QList<int>() << 0 << 10);
		}
		else /* nothing visible */
		{
			ui.stackedWidgetBrowser->setHidden(true);
		}
	}
}

void IQFIREmainwin::modifySidePanel(int page_index)
{
	QSettings s;
	QString info_s = QString("INFO_BROWSER_%1").arg(page_index);
	QString help_s = QString("HELP_BROWSER_%1").arg(page_index);
	QString navigation_s = QString("NAVIGATION_BROWSER_%1").arg(page_index);
	bool info_b, help_b, navigation_b;
	
	info_b = s.value(info_s).toBool();
	help_b = s.value(help_s).toBool();
	navigation_b = s.value(navigation_s).toBool();
	
	if(navigation_b)
	{
		if(!navigationPanelAct->isChecked())
			navigationPanelAct->setChecked(true);
	}
	else
	{
		if(!help_b && !info_b) /* nothing to be shown */
		{
			if(navigationPanelAct->isChecked()) /* if something is shown, hide it */
				navigationPanelAct->setChecked(false);
			if(infoPanelAct->isChecked())
				infoPanelAct->setChecked(false);
			if(helpPanelAct->isChecked())
				helpPanelAct->setChecked(false);
		}
		else /* perhaps we show info or help */
		{
			if(infoPanelAct->isChecked() != info_b)
				infoPanelAct->setChecked(info_b);
			if(helpPanelAct->isChecked() != help_b)
				helpPanelAct->setChecked(help_b);
		}
	}
}

void IQFIREmainwin::storeNavigationToolbarButtonsState()
{
	QSettings s;
	int page_index = ui.stackedWidgetMain->currentIndex();
	QString info_s = QString("INFO_BROWSER_%1").arg(page_index);
	QString help_s = QString("HELP_BROWSER_%1").arg(page_index);
	QString navigation_s = QString("NAVIGATION_BROWSER_%1").arg(page_index);
	
	
	/* remember the last decision of the user for this main widget page */
	s.setValue(navigation_s, navigationPanelAct->isChecked());
	
	s.setValue(help_s, helpPanelAct->isChecked());
	
	s.setValue(info_s,  infoPanelAct->isChecked());
}

