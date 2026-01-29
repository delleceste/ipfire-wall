#ifndef NATURAL_TREE_ITEM_H
#define NATURAL_TREE_ITEM_H

#include <QTreeWidgetItem>
#include <QTreeWidget>
#include <NaturalSentence.h>
#include <machineTextToRules.h>

class NaturalTreeItem : public QTreeWidgetItem
{
  public:
    NaturalTreeItem(QTreeWidget *parentTree, NaturalItemEvent* ev);
    NaturalSentence associatedNaturalSentence() { return d_naturalSentence; }
    
  private:
    NaturalSentence d_naturalSentence;
    
};

#endif
