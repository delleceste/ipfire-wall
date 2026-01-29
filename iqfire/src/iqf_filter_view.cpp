#include "iqfire.h"
#include "iqf_message_proxy.h"

#include <QtDebug>

void IQFIREmainwin::setupFilterInteraction()
{
	int i;
	ui.stackedWidgetIP->setCurrentIndex(0);
	ui.stackedWidgetIF->setCurrentIndex(0);
	ui.stackedWidgetPorts->setCurrentIndex(0);
	
	connect(ui.comboBoxProtocol, SIGNAL(currentIndexChanged (int)),
		this, SLOT(viewProtocolChanged(int)));
	connect(ui.comboBoxDirection, SIGNAL(currentIndexChanged(int)), 
		this, SLOT(viewDirectionChanged(int)));
	connect(ui.checkBoxApplyFilter, SIGNAL(toggled(bool)), this,
		SLOT(applyFilter(bool)));
	connect(ui.pBUpdateFilter, SIGNAL(clicked()), this, SLOT(updateFilter()));
	connect(ui.pushButtonFilterStateRelated, SIGNAL(clicked()), this, SLOT(viewMoreClicked()));
	
	connect(ui.comboBoxFilterIF, SIGNAL(currentIndexChanged(const QString &)),
		this, SLOT(viewIFGBoxChanged(const QString &)));
	connect(ui.comboBoxFilterIP, SIGNAL(currentIndexChanged(const QString &)),
		this, SLOT(viewIPGBoxChanged(const QString &)));
	connect(ui.comboBoxFilterPorts, SIGNAL(currentIndexChanged(const QString &)),
		this, SLOT(viewPortsGBoxChanged(const QString &)));
	
	QList<IQFCheckBox *> cbs = ui.pageConsoleSettings->findChildren<IQFCheckBox *>();
	for(i = 0; i < cbs.size(); i++)
	{
		cbs[i]->disableInfo(true);
		connect(cbs[i], SIGNAL(clicked()), this, SLOT(reloadFilterInfo()));
	}
	QList<IQFLineEdit *> les = ui.pageConsoleSettings->findChildren<IQFLineEdit *>();
	for(i = 0; i < les.size(); i++)
	{
		les[i]->disableInfo(true);
		connect(les[i], SIGNAL(editingFinished()), this, SLOT(reloadFilterInfo()));
		connect(les[i], SIGNAL(textChanged(const QString &)), this,
			SLOT(enableUpdateFilterButton()));
	}
	QList<IQFComboBox *>cbbs = ui.pageConsoleSettings->findChildren<IQFComboBox *>();
	for(i = 0; i < cbbs.size(); i++)
	{
		cbbs[i]->disableInfo(true);
		connect(cbbs[i], SIGNAL(currentIndexChanged(const QString &)), this,
			SLOT(reloadFilterInfo(const QString &)));
	}
	QList<IQFRadioButton *> rbs = ui.pageConsoleSettings->findChildren<IQFRadioButton *>();
	for(i = 0; i < rbs.size(); i++)
	{
		rbs[i]->disableInfo(true);
		connect(rbs[i], SIGNAL(clicked()), this, SLOT(reloadFilterInfo()));
	}
	QList<IQFSpinBox *>sbs = ui.pageConsoleSettings->findChildren<IQFSpinBox *>();
	for(i = 0; i < sbs.size(); i++)
	{
		sbs[i]->disableInfo(true);
		connect(sbs[i], SIGNAL(valueChanged(const QString &)), this, 
			SLOT(reloadFilterInfo(const QString &)));
	}
	QList<IQFPushButton *>pbs = ui.pageConsoleSettings->findChildren<IQFPushButton *>();
	for(i = 0; i < pbs.size(); i++)
		pbs[i]->disableInfo(true);
}

QString IQFIREmainwin::toFilterString()
{
	QString s;
	if(ui.radioButtonPermission->isChecked())
		s += " accept ";
	else if(ui.radioButtonDenial->isChecked())
		s += " drop ";
	else if(ui.radioButtonImplicit->isChecked())
		s += " implicit ";
	
	/* direction */
	if(ui.comboBoxDirection->currentText() == "INPUT")
		s += " input ";
	else if(ui.comboBoxDirection->currentText() == "OUTPUT")
		s += " output ";
	else if(ui.comboBoxDirection->currentText() == "FORWARD")
		s += " fwd ";
	else if(ui.comboBoxDirection->currentText().contains("PRE"))
		s += " pre ";
	else if(ui.comboBoxDirection->currentText().contains("POST"))
		s += " post ";
	
	/* protocol */
	if(ui.comboBoxProtocol->currentText() == "TCP")
		s += " tcp ";
	else if(ui.comboBoxProtocol->currentText() == "UDP")
		s += " udp ";
	else if(ui.comboBoxProtocol->currentText() == "ICMP")
		s += " icmp ";
	else if(ui.comboBoxProtocol->currentText() == "IGMP")
		s += " igmp ";
	
	/* network interfaces */
	if(ui.comboBoxFilterIF->currentText() == "INPUT OR OUTPUT")
		s += QString(" if %1 ").arg(ui.lineEditIF->text());
	else if(ui.comboBoxFilterIF->currentText() == "INPUT AND OUTPUT")
		s += QString(" inif %1 outif %2").arg(ui.lineEditIFIn->text()).arg(ui.lineEditIFOut->text());
	else if(ui.comboBoxFilterIF->currentText() == "INPUT")
		s += QString(" inif %1 ").arg(ui.lineEditIF->text());
	else if(ui.comboBoxFilterIF->currentText() == "OUTPUT")
		s += QString(" outif %1 ").arg(ui.lineEditIF->text());
	
	/* IPs */
	if(ui.comboBoxFilterIP->currentText() == "SOURCE OR DEST")
		s += QString(" addr %1 ").arg(ui.lineEditIP->text());
	else if(ui.comboBoxFilterIP->currentText() == "SOURCE AND DEST")
		s += QString(" sip %1 dip %2").arg(ui.lineEditIPS->text()).arg(ui.lineEditIPD->text());
	else if(ui.comboBoxFilterIP->currentText() == "SOURCE")
		s += QString(" sip %1 ").arg(ui.lineEditIP->text());
	else if(ui.comboBoxFilterIP->currentText() == "DEST")
		s += QString(" dip %1 ").arg(ui.lineEditIP->text());
	
	/* Ports */
	if(ui.comboBoxFilterPorts->currentText() == "SOURCE OR DEST")
		s += QString(" port %1 ").arg(ui.spinBoxViewPort->value());
	else if(ui.comboBoxFilterPorts->currentText() == "SOURCE AND DEST")
		s += QString(" sport %1 dport %2").arg(ui.spinBoxPort1->value()).arg(ui.spinBoxPort2->value());
	else if(ui.comboBoxFilterPorts->currentText() == "SOURCE")
		s += QString(" sport %1 ").arg(ui.spinBoxViewPort->value());
	else if(ui.comboBoxFilterPorts->currentText() == "DEST")
		s += QString(" dport %1 ").arg(ui.spinBoxViewPort->value());
	
	if(ui.cbStateless->isChecked())
		s += " stateless ";
	if(ui.cbState->isChecked())
		s += " state ";
	if(ui.cbSetup->isChecked())
		s += " setup ";
	if(ui.cbSetupOk->isChecked())
		s += " setupok ";
	if(ui.cbEstablished->isChecked())
		s += " est ";
	if(ui.cbFin->isChecked())
		s += " finwait ";
	if(ui.cbClWait->isChecked())
		s += " closewait ";
	if(ui.cbTimeWait->isChecked())
		s += " timewait ";
	if(ui.cbLastAck->isChecked())
		s += " lastack ";
	if(ui.cbClosed->isChecked())
		s += " closed ";
	
	return s;
}

void IQFIREmainwin::viewProtocolChanged(int i)
{
	switch(i)
	{
		case 3:
			ui.groupBoxPorts->setDisabled(true);
			break;
		default:
			ui.groupBoxPorts->setDisabled(false);
			break;
	}
}
		
void IQFIREmainwin::viewMoreClicked()
{
	if(ui.stackedWidgetFilter->currentIndex() == 0)
	{
		ui.stackedWidgetFilter->setCurrentIndex(1);
		ui.pushButtonFilterStateRelated->setText("Back");
	}
	else
	{
		ui.stackedWidgetFilter->setCurrentIndex(0);
		ui.pushButtonFilterStateRelated->setText("State-related part");
	}
}
		
void IQFIREmainwin::applyFilter(bool enable)
{
	QString filter = "filter:disable";
	if(enable)
	{
		filter = toFilterString();
		qDebug() << "il filtro e`: " << filter;
		ui.stackedWidgetMain->infoEnabledForPage[0] = false;
		
	}
	else
		ui.stackedWidgetMain->infoEnabledForPage[0] = true;
	ui.pBUpdateFilter->setEnabled(false);
	emit filterChanged(filter);
}
		
void IQFIREmainwin::updateFilter()
{
	if(ui.checkBoxApplyFilter->isChecked())
		applyFilter(true);
}
		
void IQFIREmainwin::viewDirectionChanged(int i)
{
	ui.comboBoxFilterIF->clear();
	
	switch(i)
	{
		case 1:
		case 4:
			ui.comboBoxFilterIF->insertItems(0,
				QStringList() << "ANY" << "INPUT");
			ui.lineEditIF->setDisabled(false);
			break;
		case 3:
			ui.comboBoxFilterIF->insertItems(0,
				QStringList() << "ANY" << "INPUT OR OUTPUT" <<
					"INPUT" << "OUTPUT" << "INPUT AND OUTPUT");
			break;
		case 2:
		case 5:
			ui.comboBoxFilterIF->insertItems(0,
				QStringList() << "ANY" << "OUTPUT");
			ui.lineEditIF->setDisabled(false);
			break;
			
	}
}

void IQFIREmainwin::viewIPGBoxChanged(const QString &s)
{
	ui.lineEditIP->setDisabled(false);
	ui.stackedWidgetIP->setCurrentIndex(0);
	if(s == "ANY")
		ui.lineEditIP->setDisabled(true);
	else if(s == "SOURCE AND DEST")
		ui.stackedWidgetIP->setCurrentIndex(1);
}
		
void IQFIREmainwin::viewPortsGBoxChanged(const QString &s)
{
	ui.spinBoxViewPort->setDisabled(false);
	ui.stackedWidgetPorts->setCurrentIndex(0);
	if(s == "ANY")
		ui.spinBoxViewPort->setDisabled(true);
	else if(s == "SOURCE AND DEST")
		ui.stackedWidgetPorts->setCurrentIndex(1);
}

void IQFIREmainwin::viewIFGBoxChanged(const QString &s)
{
	ui.lineEditIF->setEnabled(true);
	ui.stackedWidgetIF->setCurrentIndex(0);
	if(s == "ANY")
		ui.lineEditIF->setEnabled(false);
	else if(s == "INPUT AND OUTPUT")
		ui.stackedWidgetIF->setCurrentIndex(1);
}

void IQFIREmainwin::reloadFilterInfo()
{
	QString s;
	int i, state = 0;
	
	QString h = "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n"
			"<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.1//EN\""
			"\"http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd\">\n";
	
	h += "<html xmlns=\"http://www.w3.org/1999/xhtml\">"
			"<link rel=\"stylesheet\" href=\"info.css\" type=\"text/css\" />\n";
	
	h += "<body>";
	
	s += "<h2 align=\"center\">Filter</h2>";
	
	s += "<ul>";
	
	if(ui.radioButtonPermission->isChecked())
		s += QString("<li><strong>Accepted packets</strong></li>");
	else if(ui.radioButtonDenial->isChecked())
		s += QString("<li><strong>Dropped packets</strong></li>");
	else if(ui.radioButtonImplicit->isChecked())
		s += QString("<li><strong>Implicitly treated packets</strong></li>");
	
	if(ui.comboBoxDirection->currentText() != "ANY")
		s += QString("<li>Direction: <strong>%1</strong></li>").arg(ui.comboBoxDirection->currentText());
	
		
	if(ui.comboBoxProtocol->currentText()!= "ANY")
		s += QString("<li>Protocol: <strong>%1</strong></li>").arg(ui.comboBoxProtocol->currentText());
	
	if(ui.comboBoxFilterIF->currentText() == "INPUT OR OUTPUT")
		s += QString("<li>Interface name: <strong>%1</strong></li>").arg(ui.lineEditIF->text());
	else if(ui.comboBoxFilterIF->currentText() == "INPUT")
		s += QString("<li>Input interface: <strong>%1</strong></li>").arg(ui.lineEditIF->text());
	else if(ui.comboBoxFilterIF->currentText() == "OUTPUT")
		s += QString("<li>Output interface: <strong>%1</strong></li>").arg(ui.lineEditIF->text());
	if(ui.comboBoxFilterIF->currentText() == "INPUT AND OUTPUT")
	{
		s += QString("<li>Input interface: <strong>%1</strong></li>").arg(ui.lineEditIFIn->text());
		s += QString("<li>Output interface: <strong>%1</strong></li>").arg(ui.lineEditIFOut->text());
	}
	
	if(ui.comboBoxFilterIP->currentText() == "SOURCE OR DEST")
		s += QString("<li>Internet address (source or dest.): <strong>%1</strong></li>").arg(ui.lineEditIP->text());
	else if(ui.comboBoxFilterIP->currentText() == "SOURCE")
		s += QString("<li>Source IP address: <strong>%1</strong></li>").arg(ui.lineEditIP->text());
	else if(ui.comboBoxFilterIP->currentText() == "DESTINATION")
		s += QString("<li>Destination IP address: <strong>%1</strong></li>").arg(ui.lineEditIP->text());
	if(ui.comboBoxFilterIP->currentText() == "SOURCE AND DEST")
	{
		s += QString("<li>Source IP address: <strong>%1</strong></li>").arg(ui.lineEditIPS->text());
		s += QString("<li>Destination IP address: <strong>%1</strong></li>").arg(ui.lineEditIPD->text());
	}
	
	if(ui.comboBoxFilterPorts->currentText() == "SOURCE OR DEST")
		s += QString("<li>Source or dest. port: <strong>%1</strong></li>").arg(ui.spinBoxViewPort->value());
	else if(ui.comboBoxFilterPorts->currentText() == "SOURCE")
		s += QString("<li>Source Port: <strong>%1</strong></li>").arg(ui.spinBoxViewPort->value());
	else if(ui.comboBoxFilterPorts->currentText() == "DESTINATION")
		s += QString("<li>Destination Port: <strong>%1</strong></li>").arg(ui.spinBoxViewPort->value());
	if(ui.comboBoxFilterPorts->currentText() == "SOURCE AND DEST")
	{
		s += QString("<li>Source Port: <strong>%1</strong></li>").arg(ui.spinBoxPort1->value());
		s += QString("<li>Destination Port: <strong>%1</strong></li>").arg(ui.spinBoxPort2->value());
	}
	
	
	s += "</ul>";
	
	QList<IQFCheckBox *>cbs = ui.groupBoxState->findChildren<IQFCheckBox *>();
	for(i = 0; i < cbs.size(); i++)
		if(cbs[i]->isChecked())
			state++;
	if(state > 0 && cbs.size() > 0)
	{
		s += "<ul>";
		
		s += "<li><strong>State information:</li>";
		s += "<ul>";
		for(i = 0; i < cbs.size(); i++)
		{
			if(cbs[i]->isChecked())
			{
				s += QString("<li><strong>%1</strong></li>").arg(
					cbs[i]->text().remove("&"));
			}
		}
		s += "</ul></ul>";
	}
	
	
	
	
	h += s;
	
	h += "</body>";
	
	h += "</html>";
	
	IQFInfoBrowser::infoBrowser()->setHtml(h);
	
	/* enable the push button `update Filter' if the check box Apply the Filter is 
	 * checked.
	*/
	enableUpdateFilterButton();
}
		
void IQFIREmainwin::reloadFilterInfo(const QString &s)
{
	Q_UNUSED(s);
	reloadFilterInfo();
}

void IQFIREmainwin::enableUpdateFilterButton()
{
	if(ui.checkBoxApplyFilter->isChecked())
		ui.pBUpdateFilter->setEnabled(true);
}

