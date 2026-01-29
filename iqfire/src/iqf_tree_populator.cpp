#include "iqf_message_proxy.h"
#include "iqfwidgets.h"
#include "iqfruletree.h"
#include "iqfruletree_item.h"
#include <QHeaderView>
#include <QByteArray>
#include <QString>
#include <QSettings>
#include <QMenu>
#include <QtDebug>
#include <arpa/inet.h>
#include "iqfire.h"
#include <naturalRuleHash.h>

void IQFRuleTree::populateTree()
{
  QSettings s; /* for ICON_PATH macro */
  int i, colcount_filter = 12, colcount_nat = 11;
  QString owner;
  NaturalRuleHash *ruleHashMap = NaturalRuleHash::naturalRuleHashMap();
  
  struct passwd* pwd;
  pwd = getpwuid(getuid());
  
  disconnect(header(), SIGNAL(sectionResized(int, int, int)));
  
  QIcon filterAdmIcon, filterAdmAccIcon, filterAdmDenIcon, userIcon, userAccIcon, userDenIcon;
  filterAdmIcon.addPixmap(QPixmap(QString(ICON_PATH) + "folder_locked.png"), QIcon::Normal, QIcon::Off);
  filterAdmIcon.addPixmap(QPixmap(QString(ICON_PATH) + "folder_locked_open.png"), QIcon::Normal, QIcon::On);
  filterAdmAccIcon.addPixmap(QPixmap(QString(ICON_PATH) + "acc_locked_close.png"), QIcon::Normal, QIcon::Off);
  filterAdmAccIcon.addPixmap(QPixmap(QString(ICON_PATH) + "acc_locked_open.png"), QIcon::Normal, QIcon::On);
  filterAdmDenIcon.addPixmap(QPixmap(QString(ICON_PATH) + "folder_red_locked.png"), QIcon::Normal, QIcon::Off);
  filterAdmDenIcon.addPixmap(QPixmap(QString(ICON_PATH) + "folder_red_locked_open.png"), QIcon::Normal, QIcon::On);
  
  userIcon.addPixmap(QPixmap(QString(ICON_PATH) + "folder.png"), QIcon::Normal, QIcon::Off);
  userIcon.addPixmap(QPixmap(QString(ICON_PATH) + "folder_open.png"), QIcon::Normal, QIcon::On);
  userAccIcon.addPixmap(QPixmap(QString(ICON_PATH) + "folder_green.png"), QIcon::Normal, QIcon::Off);
  userAccIcon.addPixmap(QPixmap(QString(ICON_PATH) + "folder_green_open.png"), QIcon::Normal, QIcon::On);
  userDenIcon.addPixmap(QPixmap(QString(ICON_PATH) + "folder_red.png"), QIcon::Normal, QIcon::Off);
  userDenIcon.addPixmap(QPixmap(QString(ICON_PATH) + "folder_red_open.png"), QIcon::Normal, QIcon::On);
  
  QIcon admAccInIcon, admAccOutIcon, admAccFwdIcon, admDenInIcon, admDenOutIcon, admDenFwdIcon;
  admAccInIcon.addPixmap(QPixmap(QString(ICON_PATH) + "acc_in_locked_close.png"), QIcon::Normal, QIcon::Off );
  admAccInIcon.addPixmap(QPixmap(QString(ICON_PATH) + "acc_in_locked_open.png"), QIcon::Normal, QIcon::On );
  admAccOutIcon.addPixmap(QPixmap(QString(ICON_PATH) + "acc_out_locked_close.png"), QIcon::Normal, QIcon::Off );
  admAccOutIcon.addPixmap(QPixmap(QString(ICON_PATH) + "acc_out_locked_open.png"), QIcon::Normal, QIcon::On );
  admAccFwdIcon.addPixmap(QPixmap(QString(ICON_PATH) + "acc_fwd_locked_close.png"), QIcon::Normal, QIcon::Off );
  admAccFwdIcon.addPixmap(QPixmap(QString(ICON_PATH) + "acc_fwd_locked_open.png"), QIcon::Normal, QIcon::On );
  
  admDenInIcon.addPixmap(QPixmap(QString(ICON_PATH) + "den_in_locked_close.png"), QIcon::Normal, QIcon::Off );
  admDenInIcon.addPixmap(QPixmap(QString(ICON_PATH) + "den_in_locked_open.png"), QIcon::Normal, QIcon::On );
  admDenOutIcon.addPixmap(QPixmap(QString(ICON_PATH) + "den_out_locked_close.png"), QIcon::Normal, QIcon::Off );
  admDenOutIcon.addPixmap(QPixmap(QString(ICON_PATH) + "den_out_locked_open.png"), QIcon::Normal, QIcon::On );
  admDenFwdIcon.addPixmap(QPixmap(QString(ICON_PATH) + "den_fwd_locked_close.png"), QIcon::Normal, QIcon::Off );
  admDenFwdIcon.addPixmap(QPixmap(QString(ICON_PATH) + "den_fwd_locked_open.png"), QIcon::Normal, QIcon::On );
  
  QIcon accInIcon, accOutIcon, accFwdIcon, denInIcon, denOutIcon, denFwdIcon;
  accInIcon.addPixmap(QPixmap(QString(ICON_PATH) + "acc_in_close.png"), QIcon::Normal, QIcon::Off );
  accInIcon.addPixmap(QPixmap(QString(ICON_PATH) + "acc_in_open.png"), QIcon::Normal, QIcon::On );
  accOutIcon.addPixmap(QPixmap(QString(ICON_PATH) + "acc_out_close.png"), QIcon::Normal, QIcon::Off );
  accOutIcon.addPixmap(QPixmap(QString(ICON_PATH) + "acc_out_open.png"), QIcon::Normal, QIcon::On );
  accFwdIcon.addPixmap(QPixmap(QString(ICON_PATH) + "acc_fwd_close.png"), QIcon::Normal, QIcon::Off );
  accFwdIcon.addPixmap(QPixmap(QString(ICON_PATH) + "acc_fwd_open.png"), QIcon::Normal, QIcon::On );
  
  denInIcon.addPixmap(QPixmap(QString(ICON_PATH) + "den_in_close.png"), QIcon::Normal, QIcon::Off );
  denInIcon.addPixmap(QPixmap(QString(ICON_PATH) + "den_in_open.png"), QIcon::Normal, QIcon::On );
  denOutIcon.addPixmap(QPixmap(QString(ICON_PATH) + "den_out_close.png"), QIcon::Normal, QIcon::Off );
  denOutIcon.addPixmap(QPixmap(QString(ICON_PATH) + "den_out_open.png"), QIcon::Normal, QIcon::On );
  denFwdIcon.addPixmap(QPixmap(QString(ICON_PATH) + "den_fwd_close.png"), QIcon::Normal, QIcon::Off );
  denFwdIcon.addPixmap(QPixmap(QString(ICON_PATH) + "den_fwd_open.png"), QIcon::Normal, QIcon::On );
  
  QIcon natAdminIcon, natAdminIconR, snatIcon, snatIconR,  masqIcon, masqIconR, staticSnatIcon,
  staticSnatIconR, dnatIcon, dnatIconR, dnatIcon2, dnatIcon2R;
  
  natAdminIcon.addPixmap(QPixmap(QString(ICON_PATH) + "folder.png"), QIcon::Normal, QIcon::Off );
  natAdminIcon.addPixmap(QPixmap(QString(ICON_PATH) + "folder_open.png"), QIcon::Normal, QIcon::On );
  natAdminIconR.addPixmap(QPixmap(QString(ICON_PATH) + "folder_locked.png"), QIcon::Normal, QIcon::Off );
  natAdminIconR.addPixmap(QPixmap(QString(ICON_PATH) + "folder_locked_open.png"), QIcon::Normal, QIcon::On );
  snatIcon.addPixmap(QPixmap(QString(ICON_PATH) + "nat_post_close.png"), QIcon::Normal, QIcon::Off );
  snatIcon.addPixmap(QPixmap(QString(ICON_PATH) + "nat_post_locked_open.png"), QIcon::Normal, QIcon::On );
  snatIconR.addPixmap(QPixmap(QString(ICON_PATH) + "nat_post_locked_close.png"), QIcon::Normal, QIcon::Off );
  snatIconR.addPixmap(QPixmap(QString(ICON_PATH) + "nat_post_locked_open.png"), QIcon::Normal, QIcon::On );
  masqIcon.addPixmap(QPixmap(QString(ICON_PATH) + "nat_post_close.png"), QIcon::Normal, QIcon::Off );
  masqIcon.addPixmap(QPixmap(QString(ICON_PATH) + "nat_post_locked_open.png"), QIcon::Normal, QIcon::On );
  masqIconR.addPixmap(QPixmap(QString(ICON_PATH) + "nat_post_locked_close.png"), QIcon::Normal, QIcon::Off );
  masqIconR.addPixmap(QPixmap(QString(ICON_PATH) + "nat_post_locked_open.png"), QIcon::Normal, QIcon::On );
  staticSnatIcon.addPixmap(QPixmap(QString(ICON_PATH) + "nat_post_close.png"), QIcon::Normal, QIcon::Off );
  staticSnatIcon.addPixmap(QPixmap(QString(ICON_PATH) + "nat_post_locked_open.png"), QIcon::Normal, QIcon::On );
  staticSnatIconR.addPixmap(QPixmap(QString(ICON_PATH) + "nat_post_locked_close.png"), QIcon::Normal, QIcon::Off );
  staticSnatIconR.addPixmap(QPixmap(QString(ICON_PATH) + "nat_post_locked_open.png"), QIcon::Normal, QIcon::On );
  dnatIcon.addPixmap(QPixmap(QString(ICON_PATH) + "nat_pre_close.png"), QIcon::Normal, QIcon::Off );
  dnatIcon.addPixmap(QPixmap(QString(ICON_PATH) + "nat_pre_locked_open.png"), QIcon::Normal, QIcon::On );
  dnatIconR.addPixmap(QPixmap(QString(ICON_PATH) + "nat_pre_locked_close.png"), QIcon::Normal, QIcon::Off );
  dnatIconR.addPixmap(QPixmap(QString(ICON_PATH) + "nat_pre_locked_open.png"), QIcon::Normal, QIcon::On );
  dnatIcon2.addPixmap(QPixmap(QString(ICON_PATH) + "nat_pre_close.png"), QIcon::Normal, QIcon::Off );
  dnatIcon2.addPixmap(QPixmap(QString(ICON_PATH) + "nat_pre_locked_open.png"), QIcon::Normal, QIcon::On );
  dnatIcon2R.addPixmap(QPixmap(QString(ICON_PATH) + "nat_pre_locked_close.png"), QIcon::Normal, QIcon::Off );
  dnatIcon2R.addPixmap(QPixmap(QString(ICON_PATH) + "nat_pre_locked_open.png"), QIcon::Normal, QIcon::On );
  
  /* get the rules loaded into the kernel. 
  * The vectors are passed by reference.
  * GetKernelRules does a clear() on every vector
  * passed before returning it 
  */
  policy->GetKernelRules(v_den, v_acc, v_tr);
  
  if(pwd == NULL)
    owner = QString("owner?");
  else
    owner = QString(pwd->pw_name);	
  
  /* Clear the tree before repopulating it */
  this->clear();
  itemlist.clear();
  
  if(type != TRANSLATION) /* FILTER */
  {
    setColumnCount(colcount_filter);
    setHeaderLabels(QStringList() <<
    "Rule policy/owner/name"  <<  "Proto" << "Source IP address" <<
    "Dest IP address" << "Src PORT"
    << "Dst PORT" << "In dev." << "Out dev." << "STATEFUL" << "NOTIFY" 
    << "TCP FLAGS" << "OPTIONS");
    
    /* the constructor below sets direction to NOIQFRuleTreeItem::DIRECTION.
    * This avoids drop events. 
    */
    IQFRuleTreeItem *accoutitem_adm = NULL, *accinitem_adm = NULL;
    IQFRuleTreeItem *accfwditem_adm = NULL, *deninitem_adm = NULL, *denoutitem_adm = NULL, *denfwditem_adm = NULL;
      
      if(getuid() != 0)
      {
	IQFRuleTreeItem *admin_rules = NULL;
	admin_rules = new IQFRuleTreeItem(this);
	admin_rules->setText(0, "Admin");
	admin_rules->setType(IQFRuleTreeItem::OWNER);
	admin_rules->setFlags(Qt::ItemIsSelectable | Qt::ItemIsEnabled);
	admin_rules->setIcon(0, filterAdmIcon);
	admin_rules->setIconPath(ICON_PATH + "folder_locked_open.png");
	
	IQFRuleTreeItem *accitem_adm = NULL;
	IQFRuleTreeItem *denitem_adm = NULL;
	accitem_adm = new IQFRuleTreeItem(admin_rules);
	accitem_adm->setText(0, "Permission");
	accitem_adm->setPolicy(ACCEPT);
	accitem_adm->setType(IQFRuleTreeItem::POLICY);
	accitem_adm->setFlags(Qt::ItemIsSelectable | Qt::ItemIsEnabled);
	accitem_adm->setIconPath(ICON_PATH + "acc_locked_open.png");
	accitem_adm->setIcon(0, filterAdmAccIcon);
	
	denitem_adm = new IQFRuleTreeItem(admin_rules);
	denitem_adm->setText(0, "Denial");
	denitem_adm->setFlags(Qt::ItemIsSelectable | Qt::ItemIsEnabled);
	denitem_adm->setPolicy(DENIAL);
	denitem_adm->setType(IQFRuleTreeItem::POLICY);
	denitem_adm->setIconPath(ICON_PATH + "folder_red_locked_open.png");
	denitem_adm->setIcon(0, filterAdmDenIcon);
	
	accinitem_adm = new IQFRuleTreeItem(accitem_adm);
	accinitem_adm->setText(0, "INPUT");
	accinitem_adm->setType(IQFRuleTreeItem::DIRECTION);
	accinitem_adm->setDirection(IPFI_INPUT);
	accinitem_adm->setOwner(0);
	accinitem_adm->setPolicy(ACCEPT);
	accinitem_adm->setIcon(0, admAccInIcon);
	accinitem_adm->setIconPath(ICON_PATH + "acc_in_locked_open.png");
	
	accoutitem_adm = new IQFRuleTreeItem(accitem_adm);
	accoutitem_adm->setText(0, "OUTPUT");
	accoutitem_adm->setType(IQFRuleTreeItem::DIRECTION);
	accoutitem_adm->setDirection(IPFI_OUTPUT);
	accoutitem_adm->setOwner(0);
	accoutitem_adm->setPolicy(ACCEPT);
	accoutitem_adm->setIcon(0, admAccOutIcon);
	accoutitem_adm->setIconPath(ICON_PATH + "acc_out_locked_open.png");
	
	accfwditem_adm = new IQFRuleTreeItem(accitem_adm);
	accfwditem_adm->setText(0, "FORWARD");
	accfwditem_adm->setType(IQFRuleTreeItem::DIRECTION);
	accfwditem_adm->setDirection(IPFI_FWD);
	accfwditem_adm->setOwner(0);
	accfwditem_adm->setPolicy(ACCEPT);
	accfwditem_adm->setIcon(0, admAccFwdIcon);
	accfwditem_adm->setIconPath(ICON_PATH + "acc_fwd_locked_open.png");
	
	deninitem_adm = new IQFRuleTreeItem(denitem_adm);
	deninitem_adm->setText(0, "INPUT");
	deninitem_adm->setType(IQFRuleTreeItem::DIRECTION);
	deninitem_adm->setDirection(IPFI_INPUT);
	deninitem_adm->setPolicy(DENIAL);
	deninitem_adm->setOwner(0);
	deninitem_adm->setIcon(0, admDenInIcon);
	deninitem_adm->setIconPath(ICON_PATH + "den_in_locked_open.png");
	
	denoutitem_adm = new IQFRuleTreeItem(denitem_adm);
	denoutitem_adm->setText(0, "OUTPUT");
	denoutitem_adm->setType(IQFRuleTreeItem::DIRECTION);
	denoutitem_adm->setDirection(IPFI_OUTPUT);
	denoutitem_adm->setPolicy(DENIAL);
	denoutitem_adm->setOwner(0);
	denoutitem_adm->setIcon(0, admDenOutIcon);
	denoutitem_adm->setIconPath(ICON_PATH + "den_out_locked_open.png");
	
	denfwditem_adm = new IQFRuleTreeItem(denitem_adm);
	denfwditem_adm->setText(0, "FORWARD");
	denfwditem_adm->setType(IQFRuleTreeItem::DIRECTION);
	denfwditem_adm->setDirection(IPFI_FWD);
	denfwditem_adm->setOwner(0);
	denfwditem_adm->setPolicy(DENIAL);
	denfwditem_adm->setIcon(0, admDenFwdIcon);
	denfwditem_adm->setIconPath(ICON_PATH + "den_fwd_locked_open.png");	
      }	
      
      IQFRuleTreeItem *user_rules = new IQFRuleTreeItem(this);
      user_rules->setText(0, owner );
      user_rules->setType(IQFRuleTreeItem::OWNER);
      user_rules->setFlags(Qt::ItemIsSelectable | Qt::ItemIsEnabled);
      user_rules->setExpanded(true);
      user_rules->setIconPath(ICON_PATH + "folder_open.png");
      user_rules->setIcon(0, userIcon);
      
      IQFRuleTreeItem *accitem = new IQFRuleTreeItem(user_rules);
      accitem->setText(0, "Permission");
      accitem->setFlags(Qt::ItemIsSelectable | Qt::ItemIsEnabled);
      accitem->setPolicy(ACCEPT);
      accitem->setExpanded(true);
      accitem->setType(IQFRuleTreeItem::POLICY);
      accitem->setIconPath(ICON_PATH + "folder_green_open.png");
      accitem->setIcon(0, userAccIcon);
      
      IQFRuleTreeItem *denitem = new IQFRuleTreeItem(user_rules);
      denitem->setText(0, "Denial");
      denitem->setFlags(Qt::ItemIsSelectable | Qt::ItemIsEnabled);
      denitem->setPolicy(DENIAL);
      denitem->setExpanded(true);
      denitem->setType(IQFRuleTreeItem::POLICY);
      denitem->setIcon(0, userDenIcon);
      accitem->setIconPath(ICON_PATH + "folder_red_open.png");
      
      /* the following are private class members: they must be visible 
      * by addNaturalItem() in iqfruletree.cpp */
      accinitem = new IQFRuleTreeItem(accitem);
      accinitem->setText(0, "INPUT");
      accinitem->setType(IQFRuleTreeItem::DIRECTION);
      accinitem->setDirection(IPFI_INPUT);
      accinitem->setOwner(getuid());
      accinitem->setPolicy(ACCEPT);
      accinitem->setIcon(0, accInIcon);
      accinitem->setIconPath(ICON_PATH + "acc_in_open.png");
      
      accoutitem = new IQFRuleTreeItem(accitem);
      accoutitem->setText(0, "OUTPUT");
      accoutitem->setType(IQFRuleTreeItem::DIRECTION);
      accoutitem->setDirection(IPFI_OUTPUT);
      accoutitem->setOwner(getuid());
      accoutitem->setPolicy(ACCEPT);
      accoutitem->setIcon(0, accOutIcon);
      accoutitem->setIconPath(ICON_PATH + "acc_out_open.png");
      
      accfwditem = new IQFRuleTreeItem(accitem);
      accfwditem->setText(0, "FORWARD");
      accfwditem->setType(IQFRuleTreeItem::DIRECTION);
      accfwditem->setDirection(IPFI_FWD);
      accfwditem->setOwner(getuid());
      accfwditem->setPolicy(ACCEPT);
      accfwditem->setIcon(0, accFwdIcon);
      accfwditem->setIconPath(ICON_PATH + "acc_fwd_open.png");
      
      deninitem = new IQFRuleTreeItem(denitem);
      deninitem->setText(0, "INPUT");
      deninitem->setType(IQFRuleTreeItem::DIRECTION);
      deninitem->setDirection(IPFI_INPUT);
      deninitem->setOwner(getuid());
      deninitem->setPolicy(DENIAL);
      deninitem->setIcon(0, denInIcon);
      deninitem->setIconPath(ICON_PATH + "den_in_open.png");
      
      denoutitem = new IQFRuleTreeItem(denitem);
      denoutitem->setText(0, "OUTPUT");
      denoutitem->setType(IQFRuleTreeItem::DIRECTION);
      denoutitem->setDirection(IPFI_OUTPUT);
      denoutitem->setOwner(getuid());
      denoutitem->setPolicy(DENIAL);
      denoutitem->setIcon(0, denOutIcon);
      denoutitem->setIconPath(ICON_PATH + "den_out_open.png");
      
      denfwditem = new IQFRuleTreeItem(denitem);
      denfwditem->setText(0, "FORWARD");
      denfwditem->setType(IQFRuleTreeItem::DIRECTION);
      denfwditem->setDirection(IPFI_FWD);
      denfwditem->setOwner(getuid());
      denfwditem->setPolicy(DENIAL);
      denfwditem->setIcon(0, denFwdIcon);
      denfwditem->setIconPath(ICON_PATH + "den_fwd_open.png");
      
      for(i = 0; i < v_den.size(); i++)
      {
	IQFRuleTreeItem *item = NULL;
	int direction = v_den[i].direction;
	
	if(direction == IPFI_INPUT)
	{
	  if(deninitem_adm != NULL && v_den[i].owner == 0) /* root */
	  {
	    item = new IQFRuleTreeItem(deninitem_adm,  buildHeaderFromRule(&v_den[i]), v_den[i]);
	    item->setIconPath(ICON_PATH + "rule_in_locked.png");
	  }	
	  else /* other user */
	  {
	    item = new IQFRuleTreeItem(deninitem, buildHeaderFromRule(&v_den[i]), v_den[i]);
	    item->setIconPath(ICON_PATH + "rule_in.png");
	  }
	}
	else if(direction == IPFI_OUTPUT)
	{
	  if(denoutitem_adm != NULL && v_den[i].owner == 0)
	  {
	    item = new IQFRuleTreeItem(denoutitem_adm, buildHeaderFromRule(&v_den[i]), v_den[i]);
	    item->setIconPath(ICON_PATH + "rule_out_locked.png");
	  }
	  else
	  {
	    item = new IQFRuleTreeItem(denoutitem, buildHeaderFromRule(&v_den[i]), v_den[i]);
	    item->setIconPath(ICON_PATH + "rule_out.png");
	  }
	}
	else if(direction == IPFI_FWD)
	{
	  if(denfwditem_adm != NULL && v_den[i].owner == 0)
	  {
	    item = new IQFRuleTreeItem(denfwditem_adm, buildHeaderFromRule(&v_den[i]), v_den[i]);
	    item->setIconPath(ICON_PATH + "rule_fwd_locked.png");
	  }
	  else
	  {
	    item = new IQFRuleTreeItem(denfwditem, buildHeaderFromRule(&v_den[i]), v_den[i]);
	    item->setIconPath(ICON_PATH + "rule_fwd_open.png");
	  }
	}
	
	if((v_den[i].owner == 0 && getuid() != 0) || (v_den[i].natural))
	  item->setFlags(Qt::ItemIsSelectable |  Qt::ItemIsEnabled);
	else
	  item->setFlags(Qt::ItemIsSelectable | Qt::ItemIsEditable | Qt::ItemIsDragEnabled |  Qt::ItemIsEnabled);
	
	if((v_den[i].natural))
	{
	  ipfire_rule r = item->ItemRule();
	  NaturalSentence ns = ruleHashMap->naturalSentenceForRule(&r);
	  item->setAssociatedNaturalSentence(ns);
	  item->setIsNatural(true);
	  item->setIconPath(ICON_PATH + "natural_language.png");
	  QColor itemColor(KDARKRED);
	  item->colourItem(itemColor);
	}
	/* Setup the icon for the item */
	item->setIcon(0, QIcon(item->iconPath()));	
	/* Add the item to the vector, since there is not a method to 
	* retrieve each element of the tree 
	*/
	itemlist.push_back(item);
      }
      
      for(i = 0; i < v_acc.size(); i++)
      {
	int direction = v_acc[i].direction;
	IQFRuleTreeItem *item;
	if(direction == IPFI_INPUT)
	{
	  if(accinitem_adm != NULL && v_acc[i].owner == 0)
	  {
	    QStringList slist = buildHeaderFromRule(&v_acc[i]);
	    item = new IQFRuleTreeItem(accinitem_adm, slist, v_acc[i]);
	    item->setIconPath(ICON_PATH + "rule_in_locked.png");
	  }
	  else
	  {
	    item = new IQFRuleTreeItem(accinitem, buildHeaderFromRule(&v_acc[i]), v_acc[i]);
	    item->setIconPath(ICON_PATH + "rule_in.png");
	  }			
	}
	else if(direction == IPFI_OUTPUT)
	{
	  if(accoutitem_adm != NULL && v_acc[i].owner == 0)
	  {
	    item = new IQFRuleTreeItem(accoutitem_adm, buildHeaderFromRule(&v_acc[i]), v_acc[i]);
	    item->setIconPath(ICON_PATH + "rule_out_locked.png");
	  }
	  else
	  {
	    item = new IQFRuleTreeItem(accoutitem, buildHeaderFromRule(&v_acc[i]), v_acc[i]);
	    item->setIconPath(ICON_PATH + "rule_out.png");
	  }
	}
	else if(direction == IPFI_FWD)
	{
	  if(accfwditem_adm != NULL && v_acc[i].owner == 0)
	  {
	    item = new IQFRuleTreeItem(accfwditem_adm, buildHeaderFromRule(&v_acc[i]), v_acc[i]);
	    item->setIconPath(ICON_PATH + "rule_fwd_locked.png");
	  }
	  else
	  {
	    item = new IQFRuleTreeItem(accfwditem, buildHeaderFromRule(&v_acc[i]), v_acc[i]);
	    item->setIconPath(ICON_PATH + "rule_fwd.png");
	  }
	}
	if((v_acc[i].owner == 0 && getuid() != 0) || (v_acc[i].natural))
	  item->setFlags(Qt::ItemIsSelectable |  Qt::ItemIsEnabled);
	else
	  item->setFlags(Qt::ItemIsSelectable | Qt::ItemIsEditable | Qt::ItemIsDragEnabled | Qt::ItemIsEnabled);
	
	if((v_acc[i].natural))
	{
	  ipfire_rule r = item->ItemRule();
	  NaturalSentence ns = ruleHashMap->naturalSentenceForRule(&r);
	  item->setAssociatedNaturalSentence(ns);
	  item->setIsNatural(true);
	  item->setIconPath(ICON_PATH + "natural_language.png");
	  QColor itemColor(KDARKGREEN);
	  item->colourItem(itemColor);
	}
	/* Setup the icon for the item */
	item->setIcon(0, QIcon(item->iconPath()));		
	itemlist.push_back(item);
      }
  }
  else /* TRANSLATION rules */
  {
    setColumnCount(colcount_nat);
    setHeaderLabels(QStringList() <<
    "Rule owner/NAT type/name"  <<  "Proto" << "Source IP addr." <<
    "Dest IP addr."  << "Src PORT"
    << "Dst PORT" << "In dev." << "Out dev." 
    << "New IP addr." << "New PORT." << "TCP FLAGS");
    /* Root items */
    IQFRuleTreeItem *natitem = new IQFRuleTreeItem(this);
    natitem->setText(0, "Admin");
    natitem->setType(IQFRuleTreeItem::OWNER);
    natitem->setPolicy(TRANSLATION);
    if(getuid()) /* not root */
    {
      natitem->setIcon(0, natAdminIconR);
      natitem->setIconPath(ICON_PATH + "folder_locked_open.png");
    }
    else
    {
      natitem->setIcon(0, natAdminIcon);
      natitem->setIconPath(ICON_PATH + "folder_open.png");
    }
    IQFRuleTreeItem *snatroot = new IQFRuleTreeItem(natitem);
    snatroot->setText(0, "SNAT");
    snatroot->setType(IQFRuleTreeItem::NAT);
    snatroot->setOwner(getuid());
    snatroot->setPolicy(TRANSLATION);
    snatroot->setDirection(IPFI_OUTPUT_POST);
    if(getuid() != 0)
    {
      snatroot->setIconPath(ICON_PATH + "nat_post_locked_open.png");
      snatroot->setIcon(0, snatIconR);
    }
    else
    {
      snatroot->setIconPath(ICON_PATH + "nat_post_open.png");
      snatroot->setIcon(0, snatIcon);
    }
    IQFRuleTreeItem *dnatroot = new IQFRuleTreeItem(natitem);
    dnatroot->setText(0, "DNAT");
    dnatroot->setPolicy(TRANSLATION);
    dnatroot->setExpanded(true);
    dnatroot->setType(IQFRuleTreeItem::NAT);
    dnatroot->setOwner(getuid());
    
    if(getuid() != 0)
    {
      dnatroot->setIconPath(ICON_PATH + "nat_pre_locked_open.png");
      dnatroot->setIcon(0, dnatIconR);
    }
    else
    {
      dnatroot->setIconPath(ICON_PATH + "nat_pre_open.png");
      dnatroot->setIcon(0, dnatIcon);
    }
    IQFRuleTreeItem *masqroot = new IQFRuleTreeItem(snatroot);
    masqroot->setText(0, "MASQUERADE");
    masqroot->setPolicy(TRANSLATION);
    masqroot->setExpanded(true);
    masqroot->setType(IQFRuleTreeItem::MASQ);
    masqroot->setOwner(getuid());
    masqroot->setDirection(IPFI_OUTPUT_POST);
    if(getuid() != 0)
    {
      masqroot->setIconPath(ICON_PATH + "nat_post_locked_open.png");
      masqroot->setIcon(0, dnatIconR);
    }
    else
    {
      masqroot->setIconPath(ICON_PATH + "nat_post_open.png");
      masqroot->setIcon(0, dnatIcon);
    }
    
    IQFRuleTreeItem *snatr = new IQFRuleTreeItem(snatroot);
    snatr->setText(0, "STATIC SNAT");
    snatr->setPolicy(TRANSLATION);
    snatr->setExpanded(true);
    snatr->setType(IQFRuleTreeItem::SNAT);
    snatr->setOwner(getuid());
    snatr->setDirection(IPFI_OUTPUT_POST);
    if(getuid() != 0)
    {
      snatr->setIconPath(ICON_PATH + "nat_post_locked_open.png");
      snatr->setIcon(0, dnatIconR);
    }
    else
    {
      snatr->setIconPath(ICON_PATH + "nat_post_open.png");
      snatr->setIcon(0, dnatIcon);
    }
    IQFRuleTreeItem *outdnatr = new IQFRuleTreeItem(dnatroot);
    outdnatr->setText(0, "OUTPUT DNAT");
    outdnatr->setPolicy(TRANSLATION);
    outdnatr->setExpanded(true);
    outdnatr->setType(IQFRuleTreeItem::OUTDNAT);
    outdnatr->setToolTip(0, "Output Destination NAT");
    outdnatr->setOwner(getuid());
    outdnatr->setDirection(IPFI_OUTPUT);
    if(getuid() != 0)
    {
      outdnatr->setIconPath(ICON_PATH + "nat_post_locked_open.png");
      outdnatr->setIcon(0, dnatIconR);
    }
    else
    {
      outdnatr->setIconPath(ICON_PATH + "nat_post_open.png");
      outdnatr->setIcon(0, dnatIcon);
    }
    
    IQFRuleTreeItem *dnatr = new IQFRuleTreeItem(dnatroot);
    dnatr->setText(0, "PRE DNAT");
    dnatr->setToolTip(0, "Pre routing Destination NAT");
    dnatr->setPolicy(TRANSLATION);
    dnatr->setExpanded(true);
    dnatr->setType(IQFRuleTreeItem::DNAT);
    dnatr->setOwner(getuid());
    dnatr->setDirection(IPFI_INPUT_PRE);
    
    if(getuid() != 0)
    {
      dnatr->setIconPath(ICON_PATH + "nat_pre_locked_open.png");
      dnatr->setIcon(0, dnatIconR);
    }
    else
    {
      dnatr->setIconPath(ICON_PATH + "nat_pre_open.png");
      dnatr->setIcon(0, dnatIcon);
    }
    for(i = 0; i < v_tr.size(); i++)
    {	 
      IQFRuleTreeItem *item= NULL;
      
      if(v_tr[i].snat && v_tr[i].nat) /* SNAT */
      {
	item = new IQFRuleTreeItem(snatr,  buildNatHeaderFromRule(&v_tr[i]), v_tr[i]);
	item->setType(IQFRuleTreeItem::SNAT);
	if(getuid() != 0)
	{
	  item->setIconPath(ICON_PATH + "nat_post_locked_open.png");
	  item->setIcon(0, dnatIconR);
	}
	else
	{
	  item->setIconPath(ICON_PATH + "nat_post_open.png");
	  item->setIcon(0, dnatIcon);
	}
      }
      else if(v_tr[i].nat && ! v_tr[i].snat && v_tr[i].direction == IPFI_INPUT_PRE)
      {
	item = new IQFRuleTreeItem(dnatr,  buildNatHeaderFromRule(&v_tr[i]), v_tr[i]);
	item->setType(IQFRuleTreeItem::DNAT);
	if(getuid() != 0)
	{
	  item->setIconPath(ICON_PATH + "nat_pre_locked_open.png");
	  item->setIcon(0, dnatIconR);
	}
	else
	{
	  item->setIconPath(ICON_PATH + "nat_pre_open.png");
	  item->setIcon(0, dnatIcon);
	}
      }
      else if(v_tr[i].nat && ! v_tr[i].snat && v_tr[i].direction == IPFI_OUTPUT)
      {
	item = new IQFRuleTreeItem(outdnatr,  buildNatHeaderFromRule(&v_tr[i]), v_tr[i]);
	item->setType(IQFRuleTreeItem::OUTDNAT);
	if(getuid() != 0)
	{
	  item->setIconPath(ICON_PATH + "nat_post_locked_open.png");
	  item->setIcon(0, dnatIconR);
	}
	else
	{
	  item->setIconPath(ICON_PATH + "nat_post_open.png");
	  item->setIcon(0, dnatIcon);
	}
      }
      else if(v_tr[i].masquerade)
      {
	item = new IQFRuleTreeItem(masqroot,  buildNatHeaderFromRule(&v_tr[i]), v_tr[i]);
	item->setType(IQFRuleTreeItem::MASQ);
	if(getuid() != 0)
	{
	  item->setIconPath(ICON_PATH + "nat_post_locked_open.png");
	  item->setIcon(0, dnatIconR);
	}
	else
	{
	  item->setIconPath(ICON_PATH + "nat_post_open.png");
	  item->setIcon(0, dnatIcon);
	}
      }
      if(item != NULL)
      {
	item->setOwner(getuid());
	if(v_tr[i].owner == 0 && getuid() != 0)
	  item->setFlags(Qt::ItemIsSelectable);
	else
	  item->setFlags(Qt::ItemIsSelectable | Qt::ItemIsEditable  | Qt::ItemIsDragEnabled | Qt::ItemIsDropEnabled | Qt::ItemIsEnabled);
	item->setPolicy(TRANSLATION);
	itemlist.push_back(item);	
      }
    }	
  }
  header()->setResizeMode(0, QHeaderView::ResizeToContents);
  header()->setResizeMode(QHeaderView::Interactive);
  
  QByteArray headerState = s.value("TREE_HEADER_STATE", QByteArray()).toByteArray();
  if(headerState != QByteArray())
    header()->restoreState(headerState);
  
  expandItems();
  connect(header(), SIGNAL(sectionResized(int, int, int)), this, SLOT(saveTreeState(int, int, int)));
}


