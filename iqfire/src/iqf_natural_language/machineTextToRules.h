#ifndef MACHINE_TEXT_TO_RULE_H
#define MACHINE_TEXT_TO_RULE_H

#include <natural_language.h>
#include <naturalMessageEvents.h>
#include <QEvent>

#define NEWITEMEVENT (QEvent::Type) 4540
#define CLEARITEMSEVENT (QEvent::Type) 4541
#define EXTRACTION_END_EVENT (QEvent::Type) 4551

class NaturalItemEvent : public QEvent
{
  public:
   NaturalItemEvent(QEvent::Type, int p, uid_t o, int d, QStringList& sl, NaturalSentence& nSentence) : QEvent(NEWITEMEVENT)
    { d_owner = o; d_direction = d; d_strings = sl; d_policy = p; d_naturalSentence = nSentence; }
      
   int policy() { return d_policy; }
   uid_t owner() { return d_owner; }
   int direction() { return d_direction; }
   QStringList itemStrings() { return d_strings; }
   NaturalSentence naturalSentence() { return d_naturalSentence; }
   
  private:
    int d_policy, d_direction;
    uid_t d_owner;
    QStringList d_strings;
    NaturalSentence d_naturalSentence;
};

class ClearNaturalItemsEvent : public QEvent
{
  public:
    ClearNaturalItemsEvent() : QEvent(CLEARITEMSEVENT) {};
};

class NaturalRuleExtractionEndEvent : public QEvent
{
  public:
    NaturalRuleExtractionEndEvent() : QEvent(EXTRACTION_END_EVENT) {};
};


class MachineTextToRules : public QObject
{
  Q_OBJECT /* for signal-slot */
  public:
    MachineTextToRules(const MachineText &txt, QObject *parent);
    
    void extractRules();
    
  signals:
    void error(const QString&, const QString &);
    void newRuleItem(const QStringList &);
    void extractionProgress(int, int, const QString&);
    
  private:
    MachineText d_mtext;
};


#endif
