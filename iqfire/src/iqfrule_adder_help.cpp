#include "iqfrule_adder.h"
#include "iqf_message_proxy.h"
#include "iqf_utils.h"
#include "iqfruletree.h"
#include "iqfruletree_item.h"
#include "iqfire.h"
#include <QMouseEvent>
#include <QScrollBar>
#include <QSettings>
#include "colors.h"
#include "iqf_validators.h"

void IQFRuleAdder::setupInfo()
{
	/* Name and direction */
	ui.lineEditRuleName->setInfoAndHelp("rulename");
	
	/* Protocol group Box */
	ui.radioButtonProtoTCP->setInfoAndHelp("tcp");
	ui.radioButtonProtoUDP->setInfoAndHelp("udp");
	ui.radioButtonProtocolICMP->setInfoAndHelp("icmp");
	ui.radioButtonProtocolIGMP->setInfoAndHelp("igmp");

	/* network interfaces */
	ui.comboBoxInInterface->setInfoAndHelp("indev");
	ui.comboBoxOutInterface->setInfoAndHelp("indev");
	
	ui.checkBoxAnyInDev->setInfoAndHelp("any_indev");
	ui.checkBoxAnyOutDev->setInfoAndHelp("any_outdev");
	
	/* II. IP */
	/* source */
	ui.lineEditSIP->setInfoAndHelp("sip");
	ui.lineEditSIP2->setInfoAndHelp("sip");
	ui.checkBoxAnySip->setInfoAndHelp("any_sip");
	ui.checkBoxMySip->setInfoAndHelp("my_sip");
	ui.radioButtonSIPSingle->setInfoAndHelp("single");
	ui.radioButtonSIPInterval->setInfoAndHelp("interval");
	ui.radioButtonSIPAddrNetmask->setInfoAndHelp("addr_mask");
	ui.checkBoxSipNot->setInfoAndHelp("not_value");
	ui.lineEditNewSip->setInfoAndHelp("new_sip");
	
	/* dest */
	ui.lineEditDIP->setInfoAndHelp("dip");
	ui.lineEditDIP2->setInfoAndHelp("dip");
	ui.checkBoxAnyDip->setInfoAndHelp("any_dip");
	ui.checkBoxMyDip->setInfoAndHelp("my_dip");
	ui.radioButtonDIPSingle->setInfoAndHelp("single");
	ui.radioButtonDIPInterval->setInfoAndHelp("interval");
	ui.radioButtonDIPAddrNetmask->setInfoAndHelp("addr_mask");
	ui.checkBoxDipNot->setInfoAndHelp("not_value");
	ui.lineEditNewDip->setInfoAndHelp("new_dip");
	/* III. */
	/* source */
	ui.spinBoxSport->setInfoAndHelp("sport");
	ui.spinBoxSport2->setInfoAndHelp("sport");
	ui.checkBoxAnySport->setInfoAndHelp("any_sport");
	ui.radioButtonSPortSingle->setInfoAndHelp("single");
	ui.radioButtonSPortInterval->setInfoAndHelp("interval");
	ui.checkBoxSportNot->setInfoAndHelp("not_value");
	ui.spinBoxNewSport->setInfoAndHelp("new_sport");
	
	
	/// connect all this
	
	/* dest */
	ui.spinBoxDPort->setInfoAndHelp("dport");
	ui.spinBoxDPort2->setInfoAndHelp("dport");
	ui.checkBoxAnyDport->setInfoAndHelp("any_dport");
	ui.radioButtonSPortSingle->setInfoAndHelp("single");
	ui.radioButtonSPortInterval->setInfoAndHelp("interval");
	ui.checkBoxDportNot->setInfoAndHelp("not_value");
	ui.spinBoxNewDPort->setInfoAndHelp("new_dport");
	
	/// connect all this
	
}

void IQFRuleAdder::setupHelp()
{
	/* The 4 push buttons */
	ui.pushButtonApply->setHelp("adder_applyButton");
	ui.pushButtonCancel->setHelp("adder_cancelButton");
	ui.pushButtonPrevious->setHelp("adder_backButton");
	ui.pushButtonNext->setHelp("adder_nextButton");
	
}

void IQFRuleAdder::checkFTPSupportOnUI(bool en)
{
	Q_UNUSED(en);
	if(item != NULL && item->itemPolicy() == ACCEPT && ui.radioButtonProtoTCP->isChecked())
		ui.checkBoxFTPSupport->setEnabled(true);
	else if(_policy == ACCEPT && ui.radioButtonProtoTCP->isChecked())
	  ui.checkBoxFTPSupport->setEnabled(true);
	else
		ui.checkBoxFTPSupport->setEnabled(false);
		
}

void IQFRuleAdder::indevEnabled(bool en)
{
	QSettings s;
	int i;
	ui.comboBoxInInterface->setDisabled(en);
	QString icon_path = s.value("ICON_PATH", DEFAULT_ICON_PATH).toString();
	if(!en)
	{
		ui.comboBoxInInterface->clear();
		/* Network interface list initialization */
		/* Fill in the active network devices first */
		QStringList ndevs = IQFUtils::utils()->activeNetdevs();
		/* Then the other interfaces typed in by the user or initialized by default in 
		 * the QSettings.
		 */
		QStringList other_interfaces = s.value("IN_INTERFACES", 
			QStringList() << "ppp0" << "wlan0" << "eth1").toStringList();
		
		for(i = 0; i < ndevs.size(); i++)
		{
			ui.comboBoxInInterface->addItem(QIcon(icon_path + "if_active.png"), 
					ndevs[i], QVariant(true));
			if(other_interfaces.contains(ndevs[i]))
				other_interfaces.removeAll(ndevs[i]);
		}
		for(i = ndevs.size(); i < ndevs.size() + other_interfaces.size(); i++)
			ui.comboBoxInInterface->addItem(QIcon(icon_path + "if_inactive.png"),
				other_interfaces[i - ndevs.size()], QVariant(false));
		
	}
	else
	{
		ui.comboBoxInInterface->clear();
		ui.comboBoxInInterface->insertItem(0, "any");
	}
}

void IQFRuleAdder::outdevEnabled(bool en)
{
	QSettings s;
	int i;
	ui.comboBoxOutInterface->setDisabled(en);
	QString icon_path = s.value("ICON_PATH", DEFAULT_ICON_PATH).toString();
	if(!en)
	{
		ui.comboBoxOutInterface->clear();
		/* Network interface list initialization */
		QStringList ndevs = IQFUtils::utils()->activeNetdevs();
		
		QStringList other_interfaces = s.value("OUT_INTERFACES", 
			QStringList() << "ppp0" << "wlan0" << "eth1").toStringList();
		
		for(i = 0; i < ndevs.size(); i++) /* remove duplicates */
		{
			ui.comboBoxOutInterface->addItem(QIcon(icon_path + "if_active.png"), 
					ndevs[i], QVariant(true));
			if(other_interfaces.contains(ndevs[i]))
				other_interfaces.removeAll(ndevs[i]);
		}
		for(i = ndevs.size(); i < ndevs.size() + other_interfaces.size(); i++)
			ui.comboBoxOutInterface->addItem(QIcon(icon_path + "if_inactive.png"), 
				other_interfaces[i - ndevs.size()], QVariant(false));
	}
	else
	{
		ui.comboBoxOutInterface->clear();
		ui.comboBoxOutInterface->insertItem(0, "any");
	}
}

void IQFRuleAdder::setupUiLogic()
{
	checkFTPSupportOnUI(false);
	
	connect(ui.radioButtonProtoTCP, SIGNAL(toggled(bool)), ui.pushButtonTCPFlags,
		SLOT(setEnabled(bool)));
	connect(ui.radioButtonProtoTCP, SIGNAL(toggled(bool)), this,
		SLOT(checkFTPSupportOnUI(bool)));
	
	/* Network */
	connect(ui.checkBoxAnyInDev, SIGNAL(toggled(bool)), this, SLOT(indevEnabled(bool)));
	connect(ui.checkBoxAnyOutDev, SIGNAL(toggled(bool)), this, SLOT(outdevEnabled(bool)));
	
	/* 1 source IP */
	ui.frameSipMeaning->setDisabled(true);
	ui.checkBoxSipNot->setDisabled(true);
	connect(ui.checkBoxAnySip, SIGNAL(toggled(bool)), ui.lineEditSIP, SLOT(setDisabled(bool)));
	connect(ui.checkBoxAnySip, SIGNAL(toggled(bool)), ui.frameSipMeaning, SLOT(setDisabled(bool)));
	connect(ui.checkBoxAnySip, SIGNAL(toggled(bool)), ui.checkBoxMySip, SLOT(setDisabled(bool)));
	connect(ui.checkBoxAnySip, SIGNAL(toggled(bool)), ui.checkBoxSipNot, SLOT(setDisabled(bool)));
	connect(ui.checkBoxMySip, SIGNAL(toggled(bool)), ui.checkBoxSipNot, SLOT(setDisabled(bool)));
	connect(ui.checkBoxMySip, SIGNAL(toggled(bool)), ui.frameSipMeaning, SLOT(setDisabled(bool)));
	connect(ui.checkBoxMySip, SIGNAL(toggled(bool)), ui.lineEditSIP2, SLOT(setDisabled(bool)));
	connect(ui.checkBoxMySip, SIGNAL(toggled(bool)), ui.lineEditSIP, SLOT(setDisabled(bool)));
	connect(ui.checkBoxAnySip, SIGNAL(toggled(bool)), ui.checkBoxMySip, SLOT(setDisabled(bool)));
	connect(ui.radioButtonSIPInterval, SIGNAL(toggled(bool)), ui.lineEditSIP2, SLOT(setEnabled(bool)));
	connect(ui.radioButtonSIPAddrNetmask, SIGNAL(toggled(bool)), ui.lineEditSIP2, SLOT(setEnabled(bool)));
	connect(ui.rBSipList, SIGNAL(toggled(bool)), this, SLOT(showIPSList(bool)));
	
	/* destination IP */
	ui.frameDipMeaning->setDisabled(true);
	ui.checkBoxDipNot->setDisabled(true);
	connect(ui.checkBoxAnyDip, SIGNAL(toggled(bool)), ui.lineEditDIP, SLOT(setDisabled(bool)));
	connect(ui.checkBoxAnyDip, SIGNAL(toggled(bool)), ui.frameDipMeaning, SLOT(setDisabled(bool)));
	connect(ui.checkBoxAnyDip, SIGNAL(toggled(bool)), ui.checkBoxMyDip, SLOT(setDisabled(bool)));
	connect(ui.checkBoxAnyDip, SIGNAL(toggled(bool)), ui.checkBoxDipNot, SLOT(setDisabled(bool)));
	connect(ui.checkBoxMyDip, SIGNAL(toggled(bool)), ui.checkBoxDipNot, SLOT(setDisabled(bool)));
	connect(ui.checkBoxMyDip, SIGNAL(toggled(bool)), ui.frameDipMeaning, SLOT(setDisabled(bool)));
	connect(ui.checkBoxMyDip, SIGNAL(toggled(bool)), ui.lineEditDIP2, SLOT(setDisabled(bool)));
	connect(ui.checkBoxMyDip, SIGNAL(toggled(bool)), ui.lineEditDIP, SLOT(setDisabled(bool)));
	connect(ui.checkBoxAnyDip, SIGNAL(toggled(bool)), ui.checkBoxMyDip, SLOT(setDisabled(bool)));
	connect(ui.radioButtonDIPInterval, SIGNAL(toggled(bool)), ui.lineEditDIP2, SLOT(setEnabled(bool)));
	connect(ui.radioButtonDIPAddrNetmask, SIGNAL(toggled(bool)), ui.lineEditDIP2, SLOT(setEnabled(bool)));
	connect(ui.rBDipList, SIGNAL(toggled(bool)), this, SLOT(showIPDList(bool)));
	
	/* source port */
	ui.spinBoxNewSport->setDisabled(true);
	connect(ui.checkBoxAnySport, SIGNAL(toggled(bool)), ui.spinBoxSport, SLOT(setDisabled(bool)));
	connect(ui.checkBoxAnySport, SIGNAL(toggled(bool)), ui.frameSportMeaning, SLOT(setDisabled(bool)));
	connect(ui.checkBoxAnySport, SIGNAL(toggled(bool)), ui.checkBoxSportNot, SLOT(setDisabled(bool)));
	connect(ui.radioButtonSPortInterval, SIGNAL(toggled(bool)), ui.spinBoxSport2, SLOT(setEnabled(bool)));
	connect(ui.checkBoxNewSportEnable, SIGNAL(toggled(bool)), ui.spinBoxNewSport, SLOT(setEnabled(bool)));
	connect(ui.checkBoxSportNot, SIGNAL(toggled(bool)), this, 
		SLOT(sportNotChecked(bool)));
	connect(ui.rBSportList, SIGNAL(toggled(bool)), this, SLOT(showPSList(bool)));
	
	/* destination port */
	ui.spinBoxNewDPort->setDisabled(true);
	connect(ui.checkBoxAnyDport, SIGNAL(toggled(bool)), ui.spinBoxDPort, SLOT(setDisabled(bool)));
	connect(ui.checkBoxAnyDport, SIGNAL(toggled(bool)), ui.frameDportMeaning, SLOT(setDisabled(bool)));
	connect(ui.checkBoxAnyDport, SIGNAL(toggled(bool)), ui.checkBoxDportNot, SLOT(setDisabled(bool)));
	connect(ui.radioButtonDPortInterval, SIGNAL(toggled(bool)), ui.spinBoxDPort2, SLOT(setEnabled(bool)));
	connect(ui.checkBoxNewDport, SIGNAL(toggled(bool)), ui.spinBoxNewDPort, SLOT(setEnabled(bool)));
	
	connect(ui.pushButtonTCPFlags, SIGNAL(clicked()), this, SLOT(showTCPFlags()));
	connect(ui.pushButtonTCPFlagsOk, SIGNAL(clicked()), this, SLOT(hideTCPFlags()));
	connect(ui.pushButtonIPFlags, SIGNAL(clicked()), this, SLOT(showIPOptions()));
	connect(ui.pushButtonIPOptionsOk, SIGNAL(clicked()), this, SLOT(hideIPOptions()));
	connect(ui.checkBoxDportNot, SIGNAL(toggled(bool)), this, 
		SLOT(dportNotChecked(bool)));
	connect(ui.rBDportList, SIGNAL(toggled(bool)), this, SLOT(showPDList(bool)));
	
	/* TCP flags */
	/* disable radios by default... */
	ui.rbSOn->setDisabled(true);
	ui.rbSOff->setDisabled(true);
	ui.rbAOn->setDisabled(true);
	ui.rbAOff->setDisabled(true);
	ui.rbPOn->setDisabled(true);
	ui.rbPOff->setDisabled(true);
	ui.rbFON->setDisabled(true);
	ui.rbFOff->setDisabled(true);
	ui.rbUOn->setDisabled(true);
	ui.rbUOff->setDisabled(true);
	ui.rbROn->setDisabled(true);
	ui.rbROff->setDisabled(true);
	/* and enable radios only when the corresponding checkbox is enabled */
	connect(ui.cBSyn, SIGNAL(toggled(bool)), ui.rbSOn, SLOT(setEnabled(bool)));
	connect(ui.cBSyn, SIGNAL(toggled(bool)), ui.rbSOff, SLOT(setEnabled(bool)));
	connect(ui.cBAck, SIGNAL(toggled(bool)), ui.rbAOn, SLOT(setEnabled(bool)));
	connect(ui.cBAck, SIGNAL(toggled(bool)), ui.rbAOff, SLOT(setEnabled(bool)));
	connect(ui.cBRst, SIGNAL(toggled(bool)), ui.rbROn, SLOT(setEnabled(bool)));
	connect(ui.cBRst, SIGNAL(toggled(bool)), ui.rbROff, SLOT(setEnabled(bool)));
	connect(ui.cBPsh, SIGNAL(toggled(bool)), ui.rbPOn, SLOT(setEnabled(bool)));
	connect(ui.cBPsh, SIGNAL(toggled(bool)), ui.rbPOff, SLOT(setEnabled(bool)));
	connect(ui.cBUrg, SIGNAL(toggled(bool)), ui.rbUOn, SLOT(setEnabled(bool)));
	connect(ui.cBUrg, SIGNAL(toggled(bool)), ui.rbUOff, SLOT(setEnabled(bool)));
	connect(ui.cBFin, SIGNAL(toggled(bool)), ui.rbFON, SLOT(setEnabled(bool)));
	connect(ui.cBFin, SIGNAL(toggled(bool)), ui.rbFOff, SLOT(setEnabled(bool)));
	/* mss options */
	connect(ui.rbMss, SIGNAL(toggled(bool)), ui.sbMss, SLOT(setEnabled(bool)));
	connect(ui.rbClampTcpMSS, SIGNAL(toggled(bool)), ui.sbMss, SLOT(setDisabled(bool)));
	connect(ui.gbMss, SIGNAL(toggled(bool)), ui.rbClampTcpMSS, SLOT(setChecked(bool)));
}

void IQFRuleAdder::dportNotChecked(bool en)
{
	ui.radioButtonDPortInterval->setDisabled(en);
	if(en)
	{
		if(ui.radioButtonDPortInterval->isChecked())
			ui.radioButtonDPortSingle->setChecked(true);
		
	}
	
}
		
void IQFRuleAdder::sportNotChecked(bool en)
{
	ui.radioButtonSPortInterval->setDisabled(en);
	if(en)
	{
		if(ui.radioButtonSPortInterval->isChecked())
			ui.radioButtonSPortSingle->setChecked(true);
		
	}
}

void IQFRuleAdder::showTCPFlags()
{
	ui.stackedWidgetTCP->setCurrentIndex(1);
}

void IQFRuleAdder::hideTCPFlags()
{
	ui.stackedWidgetTCP->setCurrentIndex(0);
}

void IQFRuleAdder::showIPOptions()
{
	ui.stackedWidgetIPFlags->setCurrentIndex(1);
}

void IQFRuleAdder::hideIPOptions()
{
	ui.stackedWidgetIPFlags->setCurrentIndex(0);
}

void IQFRuleAdder::showIPSList(bool en)
{
    if(en)
      ui.stackedWidgetSIP->setCurrentIndex(1);
    else
      ui.stackedWidgetSIP->setCurrentIndex(0);
}
		
void IQFRuleAdder::showIPDList(bool en)
{
  if(en)
      ui.stackedWidgetDIP->setCurrentIndex(1);
    else
      ui.stackedWidgetDIP->setCurrentIndex(0);
}

void IQFRuleAdder::showPSList(bool en)
{
  if(en)
      ui.stackedWidgetSport->setCurrentIndex(1);
    else
      ui.stackedWidgetSport->setCurrentIndex(0);
}

void IQFRuleAdder::showPDList(bool en)
{
  if(en)
      ui.stackedWidgetDport->setCurrentIndex(1);
    else
      ui.stackedWidgetDport->setCurrentIndex(0);
}

void IQFRuleAdder::mouseReleaseEvent(QMouseEvent *e)
{
	qDebug() << "summary?";
	if(e->button() == Qt::LeftButton)
	{
		qDebug() << "summary!";
		rebuildSummary();
	}
}

void IQFRuleAdder::buildConnectionsForSummary()
{
	int i;
	/* line edits */
	QList<QLineEdit *>lineEdits = this->findChildren<QLineEdit *>();
	for(i = 0; i < lineEdits.size(); i++)
		connect(lineEdits[i], SIGNAL(editingFinished()), this, SLOT(rebuildSummary()));
	
	QList<QCheckBox *> checkBoxes = this->findChildren<QCheckBox *>();
	for(i = 0; i < checkBoxes.size(); i++)
		connect(checkBoxes[i], SIGNAL(clicked()), this, SLOT(rebuildSummary()));
	
	QList<QRadioButton *> radios = this->findChildren<QRadioButton *>();
	for(i = 0; i < radios.size(); i++)
		connect(radios[i], SIGNAL(clicked()), this, SLOT(rebuildSummary()));
	
	QList<QComboBox *>combos = findChildren<QComboBox *>();
	for(i = 0; i < combos.size(); i++)
		connect(combos[i], SIGNAL(currentIndexChanged(const QString&)), this, 
			SLOT(rebuildSummary(const QString &)));
	
	
	
}

void IQFRuleAdder::rebuildSummary(const QString& s)
{
	Q_UNUSED(s);
	rebuildSummary();
}

void IQFRuleAdder::rebuildSummary()
{
	QString s;
	QString policy, proto, nat, name;
	IPLineEdit *iple;
	int pos = 0;
	QObject *_sender = sender();
	if(qobject_cast<IPLineEdit *>(_sender) )
	{
		qDebug() << "rebuildSummary: lineedit";
		iple = qobject_cast<IPLineEdit *>(_sender);
		IPValidator vd(iple);
		QString txt = iple->text();
		
		if(vd.validate(txt, pos) != QValidator::Acceptable)
		{
			qDebug() << "bad ip";
			iple->setText(QString("wrong ip: \"%1\"").arg(iple->text()));
			iple->setPalette(QPalette(KRED));
		}
		else
			iple->setPalette(defaultLineEditPalette);
	}
	else
		qDebug() << "niente qObejcTcSt";
	
	QString h = "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n"
			"<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.1//EN\""
			"\"http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd\">\n";
	
	h += "<html xmlns=\"http://www.w3.org/1999/xhtml\">"
			"<link rel=\"stylesheet\" href=\"rule_summary.css\" type=\"text/css\" />\n";
	
	h += "<body>";
	
	h += "<style>";
	
	h += ".warning { color:red; font-style:italic; }";
	h += ".green { color:rgb(58, 195, 55); }";
	h += ".red { color:rgb(181, 0, 47);  }";
	h += ".cyan { color:rgb(179, 221, 245); }";
	h += ".gray { color:rgb(187, 191, 195); }";
	
	h += "</style>";
	
	
	s+= "<ul class=\"title\">";
	name = ui.lineEditRuleName->text();
	
	int rulePolicy = DENIAL;
	if(item != NULL)
		rulePolicy =_policy = item->itemPolicy();
	else
		rulePolicy = _policy;
	
	if(rulePolicy == ACCEPT && ui.checkBoxState->isChecked())
	{
		if(name == QString())
			s += QString("<li><cite class=\"gray\">%1</cite> (<strong>stateful rule</strong>)</li>").arg("No name");
		else
			s += QString("<li><cite >%1</cite> (<strong>stateful rule</strong>)</li>").arg(name);
	}
	else
	{
		if(name == QString())
			s += QString("<li><cite class=\"gray\">%1</cite></li>").arg("No name");
		else
			s += QString("<li><cite >%1</cite></li>").arg(name);
	}
	
	s += QString("</ul>");
	
	s += QString("<ul class=\"contents\">");
	
	QString dir;
	int direction;
	if(item != NULL)
		direction = item->itemDirection();
	else
		direction = _direction;
	switch(direction)
	{
		case IPFI_INPUT:
			dir = "input";
			break;
		case IPFI_OUTPUT:
			dir = "output";
			break;
		case IPFI_INPUT_PRE:
			dir = "pre routing";
			break;
		case IPFI_OUTPUT_POST:
			dir = "post routing";
			break;
		case IPFI_FWD:
			dir = "forward";
			break;
	}
	s += QString("<li>Direction: <strong>%1</strong></li>").arg(dir);
	
	if(rulePolicy == DENIAL)
		s += QString("<li>Policy: <strong class=\"red\">denial</strong></li>");
	else if(rulePolicy  == ACCEPT)
		s += QString("<li>Policy: <strong class=\"green\">permission</strong></li>");
	else if(rulePolicy  == TRANSLATION)
		s += QString("<li>Policy: <strong class=\"cyan\">translation</strong></li>");

	if(ui.radioButtonProtoTCP->isChecked())
		proto = "tcp";
	else if(ui.radioButtonProtoUDP->isChecked())
		proto = "udp";
	else if(ui.radioButtonProtocolICMP->isChecked())
		proto = "icmp";	
	else if(ui.radioButtonProtocolIGMP->isChecked())
		proto = "igmp";	
	s += QString("<li>Protocol: <strong>%1</strong></li>").arg(proto);
	
	if(ui.checkBoxFTPSupport->isChecked())
		s += QString("<li>FTP support: enabled</li>");
	
	int type;
	if(item != NULL)
		type = item->type();
	else
		type = _type;
	
	if(type > IQFRuleTreeItem::NAT)
	{
		if(type  == IQFRuleTreeItem::SNAT)
			nat = "source nat";
		else if(type  == IQFRuleTreeItem::DNAT)
			nat = "destination nat";
		else if(type  == IQFRuleTreeItem::OUTDNAT)
			nat = "output destination nat";
		else if(type  ==  IQFRuleTreeItem::MASQ)
			nat = "masquerade";
		
		s += QString("<li>Nat type: <strong>%1</strong></li>").arg(nat);
	}
	if(!ui.checkBoxAnyInDev->isHidden())
	{
		if(ui.checkBoxAnyInDev->isChecked())
			; //s +=  QString("<li>Input interface: <strong>any</strong></li>");
		else
			s += QString("<li>Input interface: <strong>%1</strong></li>").arg(
				     ui.comboBoxInInterface->currentText());
	}
	if(!ui.checkBoxAnyOutDev->isHidden())
	{
		if(ui.checkBoxAnyOutDev->isChecked())
			; //s +=  QString("<li>Input interface: <strong>any</strong></li>");
		else
			s += QString("<li>Output interface: <strong>%1</strong></li>").arg(
				     ui.comboBoxOutInterface->currentText());
	}
	
	/* source ip */
	if(ui.checkBoxAnySip->isChecked())
	{
// 		s += "<li>Source IP address: <strong>any</strong></li>";
	}
	else if(ui.checkBoxSipNot->isChecked())
	{
		if(ui.radioButtonSIPInterval->isChecked())
		{
			s += QString("<li>Source IP outside the range: <strong>%1</strong>-<strong>%2</strong></li>")
					.arg(ui.lineEditSIP->text()).arg(ui.lineEditSIP2->text());
		}
		else
			s += QString("<li>Source IP: <strong>different from: %1</strong></li>")
					.arg(ui.lineEditDIP->text());
	}
	else if(ui.checkBoxMySip->isChecked())
	{
		if(direction == IPFI_INPUT)
			s += QString("<li class=\"warning\">Source IP:<strong>the address of the network interface selected</strong>"
					"<br/>Beware: you will match the packets <strong>incoming</strong> with source "
					"ip equal to the ip of your network interface :-/</li>");
		else
			s += "<li>Source IP:<strong>the address of the network interface from which the packet is leaving</li>";
		 
	}
	else
	{
		if(ui.radioButtonSIPSingle->isChecked())
		{
			s += QString("<li>Source IP: <strong>%1</strong></li>")
					.arg(ui.lineEditSIP->text());
		}	
		else if(ui.radioButtonSIPInterval->isChecked())
		{
			s += QString("<li>Source IP between: <strong>%1</strong> and <strong>%2</strong></li>")
					.arg(ui.lineEditSIP->text()).arg(ui.lineEditSIP2->text());
		}
		else if(ui.radioButtonSIPAddrNetmask->isChecked())
			s += QString("<li>Source IP (addr./netmask): <strong>%1</strong>/<strong>%2</strong></li>")
					.arg(ui.lineEditSIP->text()).arg(ui.lineEditSIP2->text());
	}
	if(ui.lineEditNewSip->text() != "")
	{
		s += QString("<li>New source IP: <strong>%1</strong></li>")
				.arg(ui.lineEditNewSip->text());
	}
	
	/* destination ip */
	if(ui.checkBoxAnyDip->isChecked())
	{
// 		s += "<li>Destination IP address: <strong>any</strong></li>";
	}
	else if(ui.checkBoxMyDip->isChecked())
	{
		if(item->itemDirection() == IPFI_OUTPUT)
			s += QString("<li class=\"warning\">Source IP:<strong>the address of the network interface selected</strong>"
					"<br/>Beware: you will match the packets <strong>outgoing</strong> with destination "
					"ip equal to the ip of your network interface :-/</li>");
		else
			s += "<li>Destination IP:<strong>the address of the network interface to which the packet is directed</li>";
		 
	}
	else if(ui.checkBoxDipNot->isChecked())
	{
		if(ui.radioButtonDIPInterval->isChecked())
		{
			s += QString("<li>Destination IP outside the range: <strong>%1</strong>-<strong>%2</strong></li>")
					.arg(ui.lineEditDIP->text()).arg(ui.lineEditDIP2->text());
		}
		else
			s += QString("<li>Destination IP: <strong>different from: %1</strong></li>")
					.arg(ui.lineEditDIP->text());
	}
	else
	{	
		if(ui.radioButtonDIPSingle->isChecked())
		{
			s += QString("<li>Destination IP: <strong>%1</strong></li>")
					.arg(ui.lineEditDIP->text());
		}	
		else if(ui.radioButtonDIPInterval->isChecked())
		{
			s += QString("<li>Destination IP between: <strong>%1</strong> and <strong>%2</strong></li>")
					.arg(ui.lineEditDIP->text()).arg(ui.lineEditDIP2->text());
		}
		else if(ui.radioButtonDIPAddrNetmask->isChecked())
			s += QString("<li>Destination IP (addr./netmask): <strong>%1</strong>/<strong>%2</strong></li>")
					.arg(ui.lineEditDIP->text()).arg(ui.lineEditDIP2->text());
	}
	if(ui.lineEditNewDip->text() != "")
	{
		s += QString("<li>New destination IP: <strong>%1</strong></li>")
				.arg(ui.lineEditNewDip->text());
	}
	
	/* transport */
	if(ui.checkBoxAnySport->isChecked())
	{
// 		s += "<li>Source port: <strong>any</strong></li>";
	}
	else if(ui.checkBoxSportNot->isChecked())
	{
		if(ui.radioButtonSPortInterval->isChecked())
		{
			s += QString("<li>Source port outisde the range: <strong>%1</strong>-"
					"<strong>%2</strong></li>").
					arg(ui.spinBoxSport->value()).arg(ui.spinBoxSport2->value());
		}
		else	
			s += QString("<li>Source port different from: <strong>%1</strong></li>").
				arg(ui.spinBoxSport->value());
	}
	else
	{
		if( ui.radioButtonSPortSingle->isChecked())
		{
			s += QString("<li>Source port: <strong>%1</strong></li>").
					arg(ui.spinBoxSport->value());
		}
		else if(ui.radioButtonSPortInterval->isChecked())
		{
			s += QString("<li>Source between: <strong>%1</strong> and <strong>%2</strong></li>").
					arg(ui.spinBoxSport->value()).arg(ui.spinBoxSport2->value());
		}
	}
	if(ui.checkBoxNewSportEnable->isChecked())
	{
		s += QString("<li>New source port: <strong>%1</strong></li>")
				.arg(ui.spinBoxNewSport->value());
	}
	
	if(ui.checkBoxAnyDport->isChecked())
	{
// 		s += "<li>Destination port: <strong>any</strong></li>";
	}
	else if(ui.checkBoxDportNot->isChecked())
	{
		if(ui.radioButtonDPortInterval->isChecked())
		{
			s += QString("<li>Destination port outisde the range: <strong>%1</strong>-"
					"<strong>%2</strong></li>").
					arg(ui.spinBoxDPort->value()).arg(ui.spinBoxDPort2->value());
		}
		else
			s += QString("<li>Destination port different from: <strong>%1</strong></li>").
				arg(ui.spinBoxDPort->value());
	}
	else
	{
		if( ui.radioButtonDPortSingle->isChecked())
		{
			s += QString("<li>Destination port: <strong>%1</strong></li>").
					arg(ui.spinBoxDPort->value());
		}
		else if(ui.radioButtonDPortInterval->isChecked())
		{
			s += QString("<li>Destination between: <strong>%1</strong> and <strong>%2</strong></li>").
					arg(ui.spinBoxDPort->value()).arg(ui.spinBoxDPort2->value());
		}
	}
	
	if(ui.checkBoxNewDport->isChecked())
	{
		s += QString("<li>New destination port: <strong>%1</strong></li>")
				.arg(ui.spinBoxNewDPort->value());
	}
	
	/* TCP flags */
	if(ui.cBSyn->isChecked())
	{
		s += "<li>Syn flag must be <strong>";
		if(ui.rbSOn->isChecked())
			s += "true";
		else 
			s += "false";
		s += "</strong></li>";
	}
	if(ui.cBAck->isChecked())
	{
		s += "<li>Ack flag must be <strong>";
		if(ui.rbAOn->isChecked())
			s += "true";
		else 
			s += "false";
		s += "</strong></li>";
	}
	if(ui.cBPsh->isChecked())
	{
		s += "<li>Push flag must be <strong>";
		if(ui.rbPOn->isChecked())
			s += "true";
		else 
			s += "false";
		s += "</strong></li>";
	}
	if(ui.cBRst->isChecked())
	{
		s += "<li>Reset flag must be <strong>";
		if(ui.rbROn->isChecked())
			s += "true";
		else 
			s += "false";
		s += "</strong></li>";
	}
	if(ui.cBUrg->isChecked())
	{
		s += "<li>Urgent flag must be <strong>";
		if(ui.rbUOn->isChecked())
			s += "true";
		else 
			s += "false";
		s += "</strong></li>";
	}
	if(ui.cBFin->isChecked())
	{
		s += "<li>Fin flag must be <strong>";
		if(ui.rbFON->isChecked())
			s += "true";
		else 
			s += "false";
		s += "</strong></li>";
	}
	if(ui.gbMss->isChecked())
	{
		s += "<li>Maximum Segment Size manipulation: ";
		if(ui.rbMss->isChecked())
			s += QString("will be set to <strong>%1 bytes</strong>").arg(ui.sbMss->value());
		else 
			s += "will be adjusted to the <strong>Path Maximum Transfer Unit</strong> (<em> P-MTU</em>)";
		s += "</li>";
	}
	
	
	s+= "</ul>";
	
	h += s;
	
	h += "</body>";
	h += "\n</html>";
	
	int scrollVal = ui.textBrowser->verticalScrollBar()->value();
	ui.textBrowser->setHtml(h);
	ui.textBrowser->verticalScrollBar()->setValue(scrollVal);
}	
		
		




