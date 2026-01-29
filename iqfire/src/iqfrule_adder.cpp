#include "iqfrule_adder.h"
#include "rule_builder.h"
#include "iqfpolicy.h"
#include "iqflog.h"
#include "iqfire.h"
#include "iqfruletree.h"
#include "iqfruletree_item.h"
#include "iqf_utils.h"
#include "iqf_validators.h"

#include <QString>
#include <QSettings>

#include <arpa/inet.h> /* for inet_ntoa */
#include "iqf_item_delegate.h"

IQFRuleAdder::IQFRuleAdder(QWidget *parent, IQFRuleTreeItem* ruleitem, int act,
			   int _pol, int _dir, int _typ) : QDialog(parent)
{
	_policy = _pol;
	_direction = _dir;
	_type = _typ;
	ui.setupUi(this);
	setupCombos();/* item delegates and insert policy */
	setupComboConnections();
	adder_action = act;
	item = ruleitem;
	setupUiLogic();
	setupForm();
	buildConnectionsForSummary();
	
	memset(&rule, 0, sizeof(rule));
	
	ui.splitter->setStretchFactor(0, 1);
	ui.splitter->setStretchFactor(1, 1);
	
	/* signals/slots */
	connect(ui.pushButtonApply, SIGNAL(clicked()), this, SLOT(apply()));
	connect(ui.pushButtonPrevious, SIGNAL(clicked()), this, SLOT(previousPage()));
	connect(ui.pushButtonNext, SIGNAL(clicked()), this, SLOT(nextPage()));
	connect(ui.pushButtonCancel, SIGNAL(clicked()), this, SLOT(cancel()));
	ui.pushButtonPrevious->setDisabled(true);
	
	setupInfo();
	setupHelp();
	rebuildSummary();
	setWindowModality(Qt::NonModal);
	/* save the palette of one of the line edits */
	defaultLineEditPalette = ui.lineEditSIP->palette();
}

IQFRuleAdder::IQFRuleAdder(QWidget *parent, IQFRuleTreeItem* ruleitem,
			 int act) : QDialog(parent)
{
	ui.setupUi(this);
	setupCombos(); /* item delegates and insert policy */
	setupComboConnections();
	adder_action = act;
	item = ruleitem;
	setupUiLogic();
	setupForm();
	buildConnectionsForSummary();
	
	memset(&rule, 0, sizeof(rule));
	
	ui.splitter->setStretchFactor(0, 1);
	ui.splitter->setStretchFactor(1, 1);
	
	/* signals/slots */
	connect(ui.pushButtonApply, SIGNAL(clicked()), this, SLOT(apply()));
	connect(ui.pushButtonPrevious, SIGNAL(clicked()), this, SLOT(previousPage()));
	connect(ui.pushButtonNext, SIGNAL(clicked()), this, SLOT(nextPage()));
	connect(ui.pushButtonCancel, SIGNAL(clicked()), this, SLOT(cancel()));
	ui.pushButtonPrevious->setDisabled(true);
	
	setupInfo();
	setupHelp();
	rebuildSummary();
	/* save the palette of one of the line edits */
	defaultLineEditPalette = ui.lineEditSIP->palette();
}

IQFRuleAdder::~IQFRuleAdder()
{
}

void IQFRuleAdder::fixDirection(int direction)
{
	_direction = direction;
	/* _policy and _type are set by fixPolicy() and fixNatType(), which 
	 * are called by the add rule in the rule scene-
	 */
	switch(direction)
	{
		case IPFI_INPUT_PRE:
			ui.labelSummary->setText("Pre routing destination NAT rule");
			if(!ui.labelOutDevname->isHidden())
			{
				ui.labelOutDevname->setHidden(true);
				ui.comboBoxOutInterface->setHidden(true);
				ui.checkBoxAnyOutDev->setHidden(true);
			}
			ui.gbMss->setHidden(true);
			break;
		case IPFI_INPUT:
			if((item != NULL && item->itemPolicy() == ACCEPT) ||
				(_policy == ACCEPT))
				ui.labelSummary->setText("Input permission rule");
			else if((item != NULL && item->itemPolicy() == DENIAL)
				|| _policy == DENIAL)
				ui.labelSummary->setText("Input denial rule");
			if(!ui.labelOutDevname->isHidden())
			{
				ui.labelOutDevname->setHidden(true);
				ui.comboBoxOutInterface->setHidden(true);
				ui.checkBoxAnyOutDev->setHidden(true);
			}
			ui.gbMss->setHidden(false);
			break;
		case IPFI_FWD:
			if( (item != NULL && item->itemPolicy() == ACCEPT) ||
				(_policy == ACCEPT))
				ui.labelSummary->setText("Forward permission rule");
			else if((item != NULL && item->itemPolicy() == DENIAL) ||
					_policy == DENIAL)
				ui.labelSummary->setText("Forward denial rule");
			if(ui.labelOutDevname->isHidden())
			{
				ui.labelOutDevname->setHidden(false);
				ui.comboBoxOutInterface->setHidden(false);
				ui.checkBoxAnyInDev->setHidden(false);
			}
			if(ui.labelInDevname->isHidden())
			{
				ui.labelInDevname->setHidden(false);
				ui.comboBoxInInterface->setHidden(false);
				ui.checkBoxAnyInDev->setHidden(false);
			}
			ui.gbMss->setHidden(false);
			break;
		case IPFI_OUTPUT:
			if((item != NULL && item->itemPolicy() == ACCEPT) ||
						 _policy ==  ACCEPT)
				ui.labelSummary->setText("Output permission rule");
			else if((item != NULL && item->itemPolicy() == DENIAL) ||
						      _policy == DENIAL) 
				ui.labelSummary->setText("Output denial rule");
	
			if(!ui.labelInDevname->isHidden())
			{
				ui.labelInDevname->setHidden(true);
				ui.comboBoxInInterface->setHidden(true);
				ui.checkBoxAnyInDev->setHidden(true);
			}
			if((item != NULL && item->itemPolicy() == TRANSLATION) || _policy == TRANSLATION)
			  ui.gbMss->setHidden(true);
			else
			  ui.gbMss->setHidden(false);
			break;
		case IPFI_OUTPUT_POST:
			if((item != NULL && item->type() == IQFRuleTreeItem::SNAT) ||
						 _type ==  IQFRuleTreeItem::SNAT)
				ui.labelSummary->setText("Post routing source NAT rule");
			else if((item != NULL && item->type() == IQFRuleTreeItem::MASQ) ||
						      _type == IQFRuleTreeItem::MASQ)
				ui.labelSummary->setText("Post routing masquerade rule");
			if(!ui.labelInDevname->isHidden())
			{
				ui.labelInDevname->setHidden(true);
				ui.comboBoxInInterface->setHidden(true);
				ui.checkBoxAnyInDev->setHidden(true);
			}
			ui.gbMss->setHidden(true);
			break;
		default:
			break;
	}


}
		
void IQFRuleAdder::fixPolicy(int policy)
{
	_policy = policy;
	if(policy != TRANSLATION)
	{
		if(!ui.labelNewSip->isHidden())
		{
			ui.labelNewSip->setHidden(true);
			ui.lineEditNewSip->setHidden(true);
		}
		if(!ui.labelNewDip->isHidden())
		{
			ui.labelNewDip->setHidden(true);
			ui.lineEditNewDip->setHidden(true);
		}
		if(!ui.labelNewSport->isHidden())
		{
			ui.labelNewSport->setHidden(true);
			ui.spinBoxNewSport->setHidden(true);
			ui.checkBoxNewSportEnable->setHidden(true);
		}
		if(!ui.labelNewDPort->isHidden())
		{
			ui.labelNewDPort->setHidden(true);
			ui.spinBoxNewDPort->setHidden(true);
			ui.checkBoxNewDport->setHidden(true);
		}
	}
	switch(policy)
	{
		case ACCEPT:
			setWindowTitle("New Permission Rule ");	
				
			break;
		case DENIAL:
			setWindowTitle("New Denial Rule ");
			ui.checkBoxState->setChecked(false);
			ui.checkBoxState->setDisabled(true);
			break;
		case TRANSLATION:
			setWindowTitle("New Translation Rule ");
			ui.checkBoxState->setChecked(false);
			ui.checkBoxState->setDisabled(true);
			
			break;
		default:
			break;
	}
}

void IQFRuleAdder::fixNatType(QString type)
{
	
	ui.checkBoxState->setHidden(true);
	
	if(type == "MASQUERADE")
	{
		setWindowTitle(windowTitle() + "(MASQUERADE)");
		fixDirection(IPFI_OUTPUT_POST);
		ui.lineEditNewSip->setHidden(true);
		ui.labelNewSip->setHidden(true);
		ui.labelNewDip->setHidden(true);
		ui.lineEditNewDip->setHidden(true);
		ui.labelNewSport->setHidden(true);
		ui.spinBoxNewSport->setHidden(true);
		ui.checkBoxNewSportEnable->setHidden(true);
		ui.labelNewDPort->setHidden(true);
		ui.spinBoxNewDPort->setHidden(true);
		ui.checkBoxNewDport->setHidden(true);
		_type = IQFRuleTreeItem::MASQ;
	}
	else if(type == "SNAT")
	{
		setWindowTitle(windowTitle() + "(SNAT)");
		fixDirection(IPFI_OUTPUT_POST);
		ui.lineEditNewSip->setHidden(false);
		ui.labelNewSip->setHidden(false);
		ui.labelNewDip->setHidden(true);
		ui.lineEditNewDip->setHidden(true);
		ui.labelNewSport->setHidden(false);
		ui.spinBoxNewSport->setHidden(false);
		ui.checkBoxNewSportEnable->setHidden(false);
		ui.labelNewDPort->setHidden(true);
		ui.spinBoxNewDPort->setHidden(true);
		ui.checkBoxNewDport->setHidden(true);
		_type = IQFRuleTreeItem::SNAT;
		
	}
	else 	if(type == "DNAT")
	{
		setWindowTitle(windowTitle() + "(DNAT)");
		fixDirection(IPFI_INPUT_PRE);
		ui.lineEditNewSip->setHidden(true);
		ui.labelNewSip->setHidden(true);
		ui.labelNewDip->setHidden(false);
		ui.lineEditNewDip->setHidden(false);
		ui.labelNewSport->setHidden(true);
		ui.spinBoxNewSport->setHidden(true);
		ui.checkBoxNewSportEnable->setHidden(true);
		ui.labelNewDPort->setHidden(false);
		ui.spinBoxNewDPort->setHidden(false);
		ui.checkBoxNewDport->setHidden(false);
		_type = IQFRuleTreeItem::DNAT;
	}
	else 	if(type == "OUTDNAT")
	{
		setWindowTitle(windowTitle() + "(OUTPUT DNAT)");
		fixDirection(IPFI_OUTPUT);
		ui.lineEditNewSip->setHidden(true);
		ui.labelNewSip->setHidden(true);
		ui.labelNewDip->setHidden(false);
		ui.lineEditNewDip->setHidden(false);
		ui.labelNewSport->setHidden(true);
		ui.spinBoxNewSport->setHidden(true);
		ui.checkBoxNewSportEnable->setHidden(true);
		ui.labelNewDPort->setHidden(false);
		ui.spinBoxNewDPort->setHidden(false);
		ui.checkBoxNewDport->setHidden(false);
		_type = IQFRuleTreeItem::OUTDNAT;
	}
	else
		qDebug() << "keyword " << type << " not recognized!";	
}

void IQFRuleAdder::previousPage()
{
	if(ui.stackedWidget->currentIndex() > 0)
	{
		ui.stackedWidget->setCurrentIndex(ui.stackedWidget->currentIndex() - 1);
		if(ui.stackedWidget->currentIndex() == 0)
			ui.pushButtonPrevious->setDisabled(true);
	}
	if(ui.stackedWidget->currentIndex() < ui.stackedWidget->count() - 1)
		if(!ui.pushButtonNext->isEnabled())
			ui.pushButtonNext->setEnabled(true);
	
}
		
void IQFRuleAdder::nextPage()
{
	
	if(ui.stackedWidget->currentIndex() < ui.stackedWidget->count() - 1)
	{
		ui.stackedWidget->setCurrentIndex(ui.stackedWidget->currentIndex() + 1);
		if(ui.stackedWidget->currentIndex() == ui.stackedWidget->count() - 1 ||
		  ui.radioButtonProtocolICMP->isChecked() || ui.radioButtonProtocolIGMP->isChecked())
			ui.pushButtonNext->setDisabled(true);
	}
	if(ui.stackedWidget->currentIndex() > 0)
		if(!ui.pushButtonPrevious->isEnabled())
			ui.pushButtonPrevious->setEnabled(true);
}

void IQFRuleAdder::readRuleAndFill()
{
	
}

void IQFRuleAdder::setupCombos()
{
  /* combo boxes insert policy and item delegates */
	IPValidator *ipv = new IPValidator(this);
	ui.cBSipList->setValidator(ipv);
	ui.cBDipList->setValidator(ipv);
	PortValidator *pv = new PortValidator(this);
	ui.cBSportList->setValidator(pv);
	ui.cBDportList->setValidator(pv);
	
	ui.cBDportList->setInsertPolicy(QComboBox::InsertAtBottom);
	ui.cBSportList->setInsertPolicy(QComboBox::InsertAtBottom);
	ui.cBDipList->setInsertPolicy(QComboBox::InsertAtBottom);
	ui.cBSipList->setInsertPolicy(QComboBox::InsertAtBottom);
}

void IQFRuleAdder::setupComboConnections()
{
  connect(ui.pBAddSip, SIGNAL(clicked()), ui.cBSipList, SLOT(clearEditText()));
  connect(ui.pBRemSip, SIGNAL(clicked()), this, SLOT(removeSipFromList()));
  connect(ui.pBApplySipList, SIGNAL(clicked()), this, SLOT(applySipList()));
  
  connect(ui.pBAddDip, SIGNAL(clicked()), ui.cBDipList, SLOT(clearEditText()));
  connect(ui.pBRemDip, SIGNAL(clicked()), this, SLOT(removeDipFromList()));
  connect(ui.pBApplyDipList, SIGNAL(clicked()), this, SLOT(applyDipList()));
  
  connect(ui.pBAddSport, SIGNAL(clicked()), ui.cBSportList, SLOT(clearEditText()));
  connect(ui.pBRemSport, SIGNAL(clicked()), this, SLOT(removeSportFromList()));
  connect(ui.pBApplySportList, SIGNAL(clicked()), this, SLOT(applySportList()));
  
   connect(ui.pBAddDport, SIGNAL(clicked()), ui.cBDportList, SLOT(clearEditText()));
  connect(ui.pBRemDport, SIGNAL(clicked()), this, SLOT(removeDportFromList()));
  connect(ui.pBApplyDportList, SIGNAL(clicked()), this, SLOT(applyDportList()));
}

void IQFRuleAdder::removeSipFromList()
{
  ui.cBSipList->removeItem(ui.cBSipList->currentIndex());
}

void IQFRuleAdder::removeDipFromList()
{
  ui.cBDipList->removeItem(ui.cBDipList->currentIndex());
}

void IQFRuleAdder::removeSportFromList()
{
  ui.cBSportList->removeItem(ui.cBSportList->currentIndex());
}

void IQFRuleAdder::removeDportFromList()
{
  ui.cBDportList->removeItem(ui.cBDportList->currentIndex());
}

void IQFRuleAdder::applySipList()
{
  ui.cBSipList->addItem(ui.cBSipList->currentText());
}

void IQFRuleAdder::applyDipList()
{
  ui.cBDipList->addItem(ui.cBDipList->currentText());
}

void IQFRuleAdder::applySportList()
{
    ui.cBSportList->addItem(ui.cBSportList->currentText());
}

void IQFRuleAdder::applyDportList()
{
  ui.cBDportList->addItem(ui.cBDportList->currentText());
}

void IQFRuleAdder::setupForm()
{  
	char address[INET_ADDRSTRLEN];
	/* 1. Setup the fields which cannot be modified */
	if(item != NULL)
	{
		if(item->hasPolicy())
			fixPolicy(item->itemPolicy());
				
		if(item->hasDirection())
			fixDirection(item->itemDirection());
		
		if(item->type() > IQFRuleTreeItem::NAT)
		{
			if(item->type() == IQFRuleTreeItem::SNAT)
				fixNatType("SNAT");
			else if(item->type() == IQFRuleTreeItem::DNAT)
				fixNatType("DNAT");
			else if(item->type() == IQFRuleTreeItem::OUTDNAT)
				fixNatType("OUTDNAT");
			else if(item->type() == IQFRuleTreeItem::MASQ)
				fixNatType("MASQUERADE");
			ui.checkBoxMySip->setHidden(true);
			ui.checkBoxMyDip->setHidden(true);
			ui.checkBoxState->setHidden(true);
			ui.checkBoxFTPSupport->setHidden(true);
			ui.checkBoxNotify->setHidden(true);
		}
	}
	
	/* 2. initialize the form with the rule to modify */
	if(adder_action == IQFRuleAdder::Modify && item != NULL && item->hasRule())
	{
		
		ipfire_rule r = item->ItemRule();
		/* the rule name */
#ifdef ENABLE_RULENAME
		ui.lineEditRuleName->setText(r.rulename);
#endif
		struct in_addr addr;
		switch(r.ip.protocol)
		{
			case IPPROTO_TCP:
				ui.radioButtonProtoTCP->setChecked(true);
				if(r.nflags.syn)
				{
					ui.cBSyn->setChecked(true);
					if(r.tp.syn)
						ui.rbSOn->setChecked(true);
				}
				if(r.nflags.ack)
				{
					ui.cBAck->setChecked(true);
					if(r.tp.ack)
						ui.rbAOn->setChecked(true);
				}
				if(r.nflags.urg)
				{
					ui.cBUrg->setChecked(true);
					if(r.tp.urg)
						ui.rbUOn->setChecked(true);
				}	
				if(r.nflags.psh)
				{
					ui.cBPsh->setChecked(true);
					if(r.tp.psh)
						ui.rbPOn->setChecked(true);
				}
				if(r.nflags.fin)
				{
					ui.cBFin->setChecked(true);
					if(r.tp.fin)
						ui.rbFON->setChecked(true);
				}
				if(r.nflags.rst)
				{
					ui.cBRst->setChecked(true);
					if(r.tp.rst)
						ui.rbROn->setChecked(true);
				}
				if(r.pkmangle.mss.enabled)
				{
				  ui.gbMss->setChecked(true);
				  if(r.pkmangle.mss.option == MSS_VALUE)
				  {
				    ui.rbMss->setChecked(true);
				    ui.sbMss->setEnabled(true);
				    ui.sbMss->setValue(r.pkmangle.mss.mss);
				  }
				  else if(r.pkmangle.mss.option == ADJUST_MSS_TO_PMTU)
				  {
				    ui.rbClampTcpMSS->setChecked(true);
				    ui.sbMss->setEnabled(false);
				  }
				}
				else
				  ui.gbMss->setChecked(false);
				break;
			case IPPROTO_UDP:
				ui.radioButtonProtoUDP->setChecked(true);
				break;
			case IPPROTO_ICMP:
				ui.radioButtonProtocolICMP->setChecked(true);
				break;
			case IPPROTO_IGMP:
				ui.radioButtonProtocolIGMP->setChecked(true);
				break;
			default:
				break;
		}
		
		if(r.nflags.ftp)
			ui.checkBoxFTPSupport->setChecked(true);
		else
		{
			if(ui.checkBoxFTPSupport->isChecked())
				ui.checkBoxFTPSupport->setChecked(false);	
		}
		if(r.state)
			ui.checkBoxState->setChecked(true);
		else
		{
			if(ui.checkBoxState->isChecked())
				ui.checkBoxState->setChecked(false);
		}
		
		if(r.notify)
			ui.checkBoxNotify->setChecked(true);
		{
			if(ui.checkBoxNotify->isChecked())
				ui.checkBoxNotify->setChecked(false);
		}
		
		/* Network device */
		if(r.nflags.indev)
		{
			QString s(r.devpar.in_devname);
			ui.checkBoxAnyInDev->setChecked(false);
			ui.comboBoxInInterface->setEntry(s);
			
		}
		else
			ui.checkBoxAnyInDev->setChecked(true);
		
		if(r.nflags.outdev)
		{
			QString s(r.devpar.out_devname);
			ui.checkBoxAnyOutDev->setChecked(false);
			ui.comboBoxOutInterface->setEntry(s);	
		}
		else
			ui.checkBoxAnyOutDev->setChecked(true);
		
// 		/* enable all widgets in the IP address section */
// 		QList<QWidget *>widgets = ui.groupBoxIP->findChildren<QWidget *>();
// 		for(int j = 0; j < widgets.size(); j++)
// 			if(!widgets[j]->isEnabled())
// 				widgets[j]->setEnabled(true);

		switch(r.nflags.src_addr)
		{
			case NOADDR:
				ui.checkBoxAnySip->setChecked(true);
				break;
			case ONEADDR:
				ui.frameSipMeaning->setEnabled(true);
				ui.checkBoxAnySip->setChecked(false);
				
				if(r.parmean.samean == DIFFERENT_FROM ||
					r.parmean.samean == INTERVAL_DIFFERENT_FROM)
				{
					ui.checkBoxSipNot->setChecked(true);
					ui.radioButtonSIPInterval->setChecked(true);
					ui.stackedWidgetSIP->setCurrentIndex(0);
					addr.s_addr = r.ip.ipsrc[0];
					ui.lineEditSIP->setText(inet_ntoa(addr));
					ui.lineEditSIP->setEnabled(true);
				}
				else if(r.parmean.samean == MULTI_DIFFERENT)
				{
				  ui.checkBoxSipNot->setChecked(true);
				  ui.rBSipList->setChecked(true);
				  ui.stackedWidgetSIP->setCurrentIndex(1);
				  for(int i = 0; i < MAXMULTILEN && r.ip.ipsrc[i] != 0; i++)
				  {
				    if(inet_ntop(AF_INET, &r.ip.ipsrc[i], address, INET_ADDRSTRLEN))
				      ui.cBSipList->addItem(address);
				    else
				      printf("\e[1;31m* \e[0merror setting up UI: inet_ntop() failed\n");
				  }
				}
				else if(r.parmean.samean == MULTI)
				{
				  ui.checkBoxSipNot->setChecked(false);
				  ui.rBSipList->setChecked(true);
				  ui.stackedWidgetSIP->setCurrentIndex(1);
				  for(int i = 0; i < MAXMULTILEN && r.ip.ipsrc[i] != 0; i++)
				  {
				    if(inet_ntop(AF_INET, &r.ip.ipsrc[i], address, INET_ADDRSTRLEN))
				      ui.cBSipList->addItem(address);
				    else
				      printf("\e[1;31m* \e[0merror setting up UI: inet_ntop() failed\n");
				  }
				}
				else
				{
					ui.checkBoxSipNot->setChecked(false);
					ui.checkBoxSipNot->setEnabled(true);
					ui.radioButtonSIPSingle->setChecked(true);
					ui.stackedWidgetSIP->setCurrentIndex(0);
					addr.s_addr = r.ip.ipsrc[0];
					ui.lineEditSIP->setText(inet_ntoa(addr));
					ui.lineEditSIP->setEnabled(true);
				}
				
				if(r.parmean.samean == INTERVAL || r.parmean.samean 
					== INTERVAL_DIFFERENT_FROM)
				{
					addr.s_addr = r.ip.ipsrc[1];
					ui.radioButtonSIPInterval->setChecked(true);
					ui.stackedWidgetSIP->setCurrentIndex(0);
					ui.lineEditSIP2->setText(inet_ntoa(addr));
				}
				else
					ui.lineEditSIP2->setEnabled(false);
				break;
			case MYADDR:
				ui.checkBoxMySip->setChecked(true);
				ui.checkBoxAnySip->setChecked(false);
				if(ui.frameSipMeaning->isEnabled())
					ui.frameSipMeaning->setDisabled(true);
				break;
			default:
				qDebug() << "Invalid nflags.src_addr";
				break;
		}
		
		switch(r.nflags.dst_addr)
		{
			case NOADDR:
				ui.checkBoxAnyDip->setChecked(true);
				break;
			case ONEADDR:
				ui.frameDipMeaning->setEnabled(true);
				ui.checkBoxAnyDip->setChecked(false);
				if(r.parmean.damean == DIFFERENT_FROM ||
					r.parmean.damean == INTERVAL_DIFFERENT_FROM)
				{
					ui.checkBoxDipNot->setChecked(true);
					ui.radioButtonDIPInterval->setChecked(true);
					addr.s_addr = r.ip.ipdst[0];
					ui.lineEditDIP->setText(inet_ntoa(addr));
					ui.stackedWidgetDIP->setCurrentIndex(0);
				}
				else if(r.parmean.damean == MULTI_DIFFERENT)
				{
				  ui.checkBoxDipNot->setChecked(true);
				  ui.rBDipList->setChecked(true);
				  ui.stackedWidgetDIP->setCurrentIndex(1);
				  for(int i = 0; i < MAXMULTILEN && r.ip.ipdst[i] != 0; i++)
				  {
				    if(inet_ntop(AF_INET, &r.ip.ipdst[i], address, INET_ADDRSTRLEN))
				      ui.cBDipList->addItem(address);
				    else
				      printf("\e[1;31m* \e[0merror setting up UI: inet_ntop() failed\n");
				  }
				}
				else if(r.parmean.damean == MULTI)
				{
				  ui.checkBoxDipNot->setChecked(false);
				  ui.rBDipList->setChecked(true);
				  ui.stackedWidgetDIP->setCurrentIndex(1);
				  for(int i = 0; i < MAXMULTILEN && r.ip.ipdst[i] != 0; i++)
				  {
				    if(inet_ntop(AF_INET, &r.ip.ipdst[i], address, INET_ADDRSTRLEN))
				      ui.cBDipList->addItem(address);
				    else
				      printf("\e[1;31m* \e[0merror setting up UI: inet_ntop() failed\n");
				  }
				}
				else
				{
					ui.checkBoxDipNot->setChecked(false);
					ui.radioButtonDIPSingle->setChecked(true);
					addr.s_addr = r.ip.ipdst[0];
					ui.lineEditDIP->setText(inet_ntoa(addr));
					ui.stackedWidgetDIP->setCurrentIndex(0);
				}
				if(r.parmean.damean == INTERVAL || r.parmean.damean 
					== INTERVAL_DIFFERENT_FROM)
				{
					ui.radioButtonDIPInterval->setChecked(true);
					addr.s_addr = r.ip.ipdst[1];
					ui.lineEditDIP2->setText(inet_ntoa(addr));
					ui.stackedWidgetDIP->setCurrentIndex(0);
				}
				else
				{
					ui.lineEditDIP2->setEnabled(false);
				}
				break;
			case MYADDR:
				ui.checkBoxAnyDip->setChecked(false);
				ui.checkBoxMyDip->setChecked(true);
				if(ui.frameDipMeaning->isEnabled())
					ui.frameDipMeaning->setDisabled(true);
				break;
			default:
				qDebug() << "Invalid nflags.dst_addr";
				break;
		}
		
		if(r.nflags.src_port)
		{
			ui.checkBoxAnySport->setChecked(false);
			if(r.parmean.spmean == DIFFERENT_FROM ||
				r.parmean.spmean == INTERVAL_DIFFERENT_FROM)
			{
				ui.checkBoxSportNot->setChecked(true);
				ui.checkBoxSportNot->setEnabled(true);
				ui.spinBoxSport->setValue(ntohs(r.tp.sport[0]));
				ui.spinBoxSport->setEnabled(true);
				ui.stackedWidgetSport->setCurrentIndex(0);
			}
			else if(r.parmean.spmean == MULTI_DIFFERENT)
			{
			  ui.checkBoxSportNot->setChecked(true);
			  ui.rBSportList->setChecked(true);
			  ui.stackedWidgetSport->setCurrentIndex(1);
			  for(int i = 0; i < MAXMULTILEN && r.tp.sport[i] != 0; i++)
			      ui.cBSportList->addItem(QString().number(ntohs(r.tp.sport[i])));
			}
			else if(r.parmean.spmean == MULTI)
			{
			  ui.checkBoxSportNot->setChecked(false);
			  ui.rBSportList->setChecked(true);
			  ui.stackedWidgetSport->setCurrentIndex(1);
			  for(int i = 0; i < MAXMULTILEN && r.tp.sport[i] != 0; i++)
			      ui.cBSportList->addItem(QString().number(ntohs(r.tp.sport[i])));
			}
			else
			{
				ui.checkBoxSportNot->setChecked(false);
				ui.checkBoxSportNot->setEnabled(true);
				ui.spinBoxSport->setValue(ntohs(r.tp.sport[0]));
				ui.spinBoxSport->setEnabled(true);
				ui.stackedWidgetSport->setCurrentIndex(0);
			}
			if(r.parmean.spmean == INTERVAL || 
				r.parmean.spmean == INTERVAL_DIFFERENT_FROM)
			{
				ui.radioButtonSPortInterval->setChecked(true);
				ui.spinBoxSport2->setValue(ntohs(r.tp.sport[1]));
				ui.radioButtonSPortInterval->setEnabled(true);
				ui.spinBoxSport2->setEnabled(true);
				ui.stackedWidgetSport->setCurrentIndex(0);
			}
		}
		else
		{
			ui.checkBoxAnySport->setChecked(true);
			ui.checkBoxAnySport->setEnabled(true);
			if(ui.frameSportMeaning->isEnabled())
				ui.frameSportMeaning->setDisabled(true);
			if(ui.checkBoxSportNot->isEnabled())
				ui.checkBoxSportNot->setDisabled(true);
			ui.stackedWidgetSport->setCurrentIndex(0);
		}
		
		if(r.nflags.dst_port)
		{
			ui.checkBoxAnyDport->setChecked(false);
			ui.checkBoxAnyDport->setEnabled(true);
			if(r.parmean.dpmean == DIFFERENT_FROM ||
						r.parmean.dpmean == INTERVAL_DIFFERENT_FROM)
			{
				ui.checkBoxDportNot->setChecked(true);
				ui.checkBoxDportNot->setEnabled(true);
				ui.stackedWidgetDport->setCurrentIndex(0);
				ui.spinBoxDPort->setValue(ntohs(r.tp.dport[0]));
			}
			else if(r.parmean.dpmean == MULTI_DIFFERENT)
			{
			  ui.checkBoxDportNot->setChecked(true);
			  ui.rBDportList->setChecked(true);
			  ui.stackedWidgetDport->setCurrentIndex(1);
			  for(int i = 0; i < MAXMULTILEN && r.tp.dport[i] != 0; i++)
			      ui.cBDportList->addItem(QString().number(ntohs(r.tp.dport[i])));
			}
			else if(r.parmean.dpmean == MULTI)
			{
			  ui.checkBoxDportNot->setChecked(false);
			  ui.rBDportList->setChecked(true);
			  ui.stackedWidgetDport->setCurrentIndex(1);
			  for(int i = 0; i < MAXMULTILEN && r.tp.dport[i] != 0; i++)
			      ui.cBDportList->addItem(QString().number(ntohs(r.tp.dport[i])));
			}
			else
			{
				ui.checkBoxDportNot->setChecked(false);
				ui.checkBoxDportNot->setEnabled(true);
				ui.stackedWidgetDport->setCurrentIndex(0);
				ui.spinBoxDPort->setValue(ntohs(r.tp.dport[0]));
			}
			if(r.parmean.dpmean == INTERVAL || 
						r.parmean.dpmean == INTERVAL_DIFFERENT_FROM)
			{
				ui.radioButtonDPortInterval->setChecked(true);
				ui.spinBoxDPort2->setValue(ntohs(r.tp.dport[1]));
				ui.spinBoxDPort2->setEnabled(true);
				ui.radioButtonDPortInterval->setEnabled(true);
				ui.stackedWidgetDport->setCurrentIndex(0);
			}
		}
		else
		{
			ui.checkBoxAnyDport->setChecked(true);
			ui.checkBoxAnyDport->setEnabled(true);
			if(ui.frameDportMeaning->isEnabled())
				ui.frameDportMeaning->setDisabled(true);
			if(ui.checkBoxDportNot->isEnabled())
				ui.checkBoxDportNot->setDisabled(true);
			ui.stackedWidgetDport->setCurrentIndex(0);
		}
		
		if(r.notify)
			ui.checkBoxNotify->setChecked(true);
		else
			ui.checkBoxNotify->setChecked(false);
	
		/* initialize NAT fields */
		if(item->type() > IQFRuleTreeItem::NAT)
		{
			struct in_addr newadd;
			
			if(r.nflags.newaddr)
			{
				newadd.s_addr = r.newaddr;
				ui.lineEditNewDip->setText(inet_ntoa(newadd));
			}
			if(r.nflags.newport)
			{
				ui.spinBoxNewDPort->setValue(ntohs(r.newport));
				ui.checkBoxNewDport->setChecked(true);
			}
		}
	}
	else
		qDebug() << "setupForm(): qualcosa null";
}

int IQFRuleAdder::buildRuleFromForm()
{
	RuleBuilder rb;
	memset(&rule, 0, sizeof(rule));
	int direction;
	
	/* rule name */
	rb.setName(ui.lineEditRuleName->text());
	
	/* policy */
	if(item != NULL)
		rb.setPolicy(item->itemPolicy()); /* ftom a tree item */
	else
		rb.setPolicy(_policy); /* from the rule view */
	
	/* Protocol */
	if(ui.radioButtonProtoTCP->isChecked())
		rb.setProtocol("TCP");
	else if(ui.radioButtonProtoUDP->isChecked())
		rb.setProtocol("UDP");
	else if(ui.radioButtonProtocolICMP->isChecked())
		rb.setProtocol("ICMP");
	else if(ui.radioButtonProtocolIGMP->isChecked())
		rb.setProtocol("IGMP");
	else
	{
		qDebug() << "int IQFRuleAdder::buildRuleFromForm(): protocol error!";
		return -1;
	}
	if(item != NULL)
		direction = item->itemDirection();
	else /* we come from the rule view */
		direction = _direction;
	
	/* Direction and device name */
	switch(direction)
	{
		case IPFI_INPUT: /* INPUT */
			rb.setDirection("INPUT");
			if(!ui.checkBoxAnyInDev->isChecked())
				rb.setInDevname(ui.comboBoxInInterface->currentText());
			break;
		case IPFI_OUTPUT:
			rb.setDirection("OUTPUT");
			if(!ui.checkBoxAnyOutDev->isChecked())
				rb.setOutDevname(ui.comboBoxOutInterface->currentText());
			break;
		case IPFI_FWD:
			rb.setDirection("FORWARD");
			if(!ui.checkBoxAnyInDev->isChecked())
				rb.setInDevname(ui.comboBoxInInterface->currentText());
			if(!ui.checkBoxAnyOutDev->isChecked())
				rb.setOutDevname(ui.comboBoxOutInterface->currentText());
			
			break;
		case IPFI_INPUT_PRE:
			rb.setDirection("PRE");
			if(!ui.checkBoxAnyInDev->isChecked())
				rb.setInDevname(ui.comboBoxInInterface->currentText());
			break;
		case IPFI_OUTPUT_POST:
			rb.setDirection("POST");
			if(!ui.checkBoxAnyOutDev->isChecked())
				rb.setOutDevname(ui.comboBoxOutInterface->currentText());
			break;
		default:
			qDebug() << "int IQFRuleAdder::buildRuleFromForm(): direction error";
			return -1;
	}
	/* nat type */
	int natType;
	if(item != NULL)
		natType = item->type();
	else/* we come from the rule view */
		natType = _type;
	
	if(natType > IQFRuleTreeItem::NAT)
	{
		if(natType == IQFRuleTreeItem::SNAT)
			rb.setNatType("SNAT");
		else if(natType == IQFRuleTreeItem::DNAT)
		{
			qDebug() << "rule adder: Setto DNAT";
			rb.setNatType("DNAT");
		}
		else if(natType == IQFRuleTreeItem::MASQ)
			rb.setNatType("MASQUERADE");
		else if(natType == IQFRuleTreeItem::OUTDNAT)
			rb.setNatType("DNAT");
		else 
		{
			qDebug() << "int IQFRuleAdder::buildRuleFromForm(): NAT type error!";
			return -1;
		}
	}
	/* Source IP */
	if(! ui.checkBoxAnySip->isChecked())
	{
		QString sip;
		int i;
		if(ui.checkBoxMySip->isChecked())
			sip = "MY";
		else if(ui.radioButtonSIPSingle->isChecked())
			sip = ui.lineEditSIP->text();
		else if(ui.radioButtonSIPInterval->isChecked())
			sip = ui.lineEditSIP->text() + "-" + ui.lineEditSIP2->text();
		else if(ui.radioButtonSIPAddrNetmask->isChecked())
			sip = ui.lineEditSIP->text() + "/" + ui.lineEditSIP2->text();
		else if(ui.rBSipList->isChecked())
		{
		  for(i = 0; i < ui.cBSipList->count(); i++)
		  {
		    QString qssip = ui.cBSipList->itemText(i);
		    if(qssip != QString())
		      sip += QString("%1,").arg(qssip);
		  }
		  if(i > 0) /* remove last comma */
		    sip.remove(sip.length() - 1, 1);
		}
		if(ui.checkBoxSipNot->isChecked())
			sip = "!" + sip;
		  qDebug() << "sip per rule builder: " << sip;
		rb.setSip(sip);
	}
	/* New SIP and new DIP. New Sport and new dport */
	if(natType > IQFRuleTreeItem::NAT)
	{
		if(natType == IQFRuleTreeItem::SNAT)
		{
			if(! ui.lineEditNewSip->text().isEmpty())
				rb.setNewIP(ui.lineEditNewSip->text());
			if(ui.checkBoxNewSportEnable->isChecked())
			{
				QString sp = QString("%1").arg(ui.spinBoxNewSport->value());
				rb.setNewPort(sp);
			}
		}
		else if(natType == IQFRuleTreeItem::DNAT || natType == IQFRuleTreeItem::OUTDNAT)
		{
			qDebug() << "e nat";
			if(! ui.lineEditNewDip->text().isEmpty())
				rb.setNewIP(ui.lineEditNewDip->text());
			if(ui.checkBoxNewDport->isChecked())
			{
				QString dp = QString("%1").arg(ui.spinBoxNewDPort->value());
				rb.setNewPort(dp);
			}
		}
	}
	/* Destination IP */
	if(! ui.checkBoxAnyDip->isChecked())
	{
		QString dip;
		int i;
		if(ui.checkBoxMyDip->isChecked())
			dip = "MY";
		else if(ui.radioButtonDIPSingle->isChecked())
			dip = ui.lineEditDIP->text();
		else if(ui.radioButtonDIPInterval->isChecked())
			dip = ui.lineEditDIP->text() + "-" + ui.lineEditDIP2->text();
		else if(ui.radioButtonDIPAddrNetmask->isChecked())
			dip = ui.lineEditDIP->text() + "/" + ui.lineEditDIP2->text();
		else if(ui.rBDipList->isChecked())
		{
		  for(i = 0; i < ui.cBDipList->count(); i++)
		  {
		    QString qsdip = ui.cBDipList->itemText(i);
		    if(qsdip != QString())
		      dip += QString("%1,").arg(qsdip);
		  }
		  if(i > 0) /* remove last comma */
		    dip.remove(dip.length() - 1, 1);
		}
		
		if(ui.checkBoxDipNot->isChecked())
			dip = "!" + dip;
		  qDebug() << "dip per rule builder: " <<dip;
		rb.setDip(dip);
	}
	/* Source port */
	if(! ui.checkBoxAnySport->isChecked())
	{
		QString sport;
		int i;
		if(ui.radioButtonSPortSingle->isChecked())
			sport = QString("%1").arg(ui.spinBoxSport->value());
		else if(ui.radioButtonSPortInterval->isChecked())
			sport = QString("%1-%2").arg(ui.spinBoxSport->value()).
					arg(ui.spinBoxSport2->value());
		else if(ui.rBSportList->isChecked())
		{
		  for(i = 0; i < ui.cBSportList->count(); i++)
		  {
		    QString qssport = ui.cBSportList->itemText(i);
		    if(qssport != QString())
		     sport += QString("%1,").arg(qssport);
		  }
		  if(i > 0) /* remove last comma */
		    sport.remove(sport.length() - 1, 1);
		}
		if(ui.checkBoxSportNot->isChecked())
			sport = "!" + sport;
		
		  qDebug() << "sport per rule builder: " << sport;
		rb.setSport(sport);
	}
	
	/* Destination port */
	if(! ui.checkBoxAnyDport->isChecked())
	{
		QString dport;
		int i;
		if(ui.radioButtonDPortSingle->isChecked())
			dport = QString("%1").arg(ui.spinBoxDPort->value());
		else if(ui.radioButtonDPortInterval->isChecked())
			dport = QString("%1-%2").arg(ui.spinBoxDPort->value()).
					arg(ui.spinBoxDPort2->value());
		else if(ui.rBDportList->isChecked())
		{
		  for(i = 0; i < ui.cBDportList->count(); i++)
		  {
		    QString qsdport = ui.cBDportList->itemText(i);
		    if(qsdport != QString())
		     dport += QString("%1,").arg(qsdport);
		  }
		  if(i > 0) /* remove last comma */
		    dport.remove(dport.length() - 1, 1);
		}
		
		if(ui.checkBoxDportNot->isChecked())
			dport = "!" + dport;
		
		  qDebug() << "dport per rule builder: " << dport;
		rb.setDport(dport);
	}
	
	/* TCP flags */
	if(rb.Rule()->ip.protocol == IPPROTO_TCP)
	{
		QString f;
		if(ui.cBSyn->isChecked())
		{
			if(ui.rbSOn->isChecked())
				f += " SYN on ";
			else
				f += " SYN off ";
		}
		if(ui.cBAck->isChecked())
		{
			if(ui.rbAOn->isChecked())
				f += " ACK on ";
			else
				f += " ACK off ";
		}
		if(ui.cBFin->isChecked())
		{
			if(ui.rbFON->isChecked())
				f += " FIN on ";
			else
				f += " FIN off ";
		}
		if(ui.cBRst->isChecked())
		{
			if(ui.rbROn->isChecked())
				f += " RST on ";
			else
				f += " RST off ";
		}
		if(ui.cBUrg->isChecked())
		{
			if(ui.rbUOn->isChecked())
				f += " URG on ";
			else
				f += " URG off ";
		}
		if(ui.cBPsh->isChecked())
		{
			if(ui.rbPOn->isChecked())
				f += " PSH on ";
			else
				f += " PSH off ";
		}
		rb.setFlags(f);
		/* mss option */
		if(ui.gbMss->isChecked())
		{
		  if(ui.rbMss->isChecked())
		  {
		    rb.setMssOption(MSS_VALUE);
		    rb.setMssValue(ui.sbMss->value());
		  }
		  else if(ui.rbClampTcpMSS->isChecked())
		  {
		    rb.setMssOption(ADJUST_MSS_TO_PMTU);
		  }
		}
	}
	
	/* State */
	if(ui.checkBoxState->isChecked())
		rb.setState("YES");
	/* FTP support */
	if(ui.checkBoxFTPSupport->isChecked())
		rb.setFTP("YES");
	if(ui.checkBoxNotify->isChecked())
		rb.setNotify("YES");
	
	/* Finally assign the rule built with the builder to the rule adder rule */
	if(rb.ruleValid())
	{
		memcpy(&rule, rb.Rule(), sizeof(rule));
		_ruleValid = true;
	}
	else
	{
		_ruleValid = false;
		return -1;
	}
	
	return 0;
}

void IQFRuleAdder::closeEvent(QCloseEvent *e)
{
	emit applyCancel();
	QWidget::closeEvent(e);
}

void IQFRuleAdder::cancel()
{
	emit applyCancel();
	close(); 
}

void IQFRuleAdder::apply()
{
	QSettings s;
	if(buildRuleFromForm() >= 0)
	{
		/* The QDialog returns accept() */
		QStringList inactive_inif, inactive_outif;
		
		/* Save in qsettings the combo box for the network interfaces typed in */
		for(int i = 0; i < ui.comboBoxInInterface->count(); i++)
		{
			//if(ui.comboBoxInInterface->itemData(i).toBool() == false /* false == inactive */
			//|| ui.comboBoxInInterface->itemData(i) == QVariant()) /* QVariant() == inserted by the user */
				inactive_inif.push_back(ui.comboBoxInInterface->itemText(i));
		}
		if(!inactive_inif.contains(ui.comboBoxInInterface->currentText()) && 
				  ui.comboBoxInInterface->currentText() != QString())
			inactive_inif.push_back(ui.comboBoxInInterface->currentText());
		
		s.setValue("IN_INTERFACES", inactive_inif);
		
		for(int i = 0; i < ui.comboBoxOutInterface->count(); i++)
		{
			//if(ui.comboBoxOutInterface->itemData(i).toBool() == false/* false == inactive */
		//	|| ui.comboBoxInInterface->itemData(i) == QVariant()) /* QVariant() == inserted by the user */
				inactive_outif.push_back(ui.comboBoxOutInterface->itemText(i));
		}
		if(!inactive_outif.contains(ui.comboBoxOutInterface->currentText()) && 
				  ui.comboBoxOutInterface->currentText() != QString())
			inactive_outif.push_back(ui.comboBoxOutInterface->currentText());
		s.setValue("OUT_INTERFACES", inactive_outif);
// 		accept();
		emit applyOk();
		close();
	}
	else
	{
		Log::log()->appendFailed(QString("void IQFRuleAdder::apply(): failed to build\n"
		"the new rule from the form."));
		/* Tells the caller that nothing really took place */
		emit applyCancel();
	}
	
	
}





