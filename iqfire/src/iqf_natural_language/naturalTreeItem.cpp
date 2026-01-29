#include "naturalTreeItem.h"
#include <ipfire_structs.h>

NaturalTreeItem::NaturalTreeItem(QTreeWidget * parent, NaturalItemEvent *ev) : QTreeWidgetItem(parent)
{
  QString sp, sd;
  int policy, direction;
  policy = ev->policy();
  direction = ev->direction();
 
  switch(direction)
  {
    case IPFI_INPUT:
      sd = "INPUT";
      break;
    case IPFI_OUTPUT:
      sd = "OUTPUT";
      break;
    case IPFI_FWD:
      sd = "FORWARD";
      break;
    case IPFI_INPUT_PRE:
      sd = "PRE ROUTING";
      break;
    case IPFI_OUTPUT_POST:
      sd = "POST ROUTING";
      break;
    default:
      sd = "NO DIRECTION";
      break;
  }
  switch(policy)
  {
    case ACCEPT:
      sp = "ACCEPT";
      break;
    case DENIAL:
      sp = "DENY";
      break;
    case TRANSLATION:
      sp = "NAT";
      break;
    default:
      break;
  }
  QStringList items;
  items << sp << sd;
  items += ev->itemStrings();
  if(items.size() > 3)
    items.removeAt(2);
  
  for(int i = 0; i < items.size(); i++)
  {
    /* avoid including rule name and owner */
    setText(i, items[i]);
  }
}

