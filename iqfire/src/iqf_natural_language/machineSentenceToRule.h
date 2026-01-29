#ifndef MACHINE_SENTENCE_TO_RULE_H
#define MACHINE_SENTENCE_TO_RULE_H

#include <MachineSentence.h>
#include <QStringList>
#include <QList>
#include <QPair>

class MachineSentenceToRule
{
  public:
    MachineSentenceToRule(MachineSentence& ms);
    
    /** Builds a string list containing the correct elements 
     *  aimed at making up a new IQFTreeWidgetItem in the rule
     *  tree.
     */
    QStringList toRuleItem();
    int direction() { return d_direction; }
    int policy() { return d_policy; }
    uid_t owner() { return d_owner; }
    
    bool conversionOk() { return d_conversionOk; }
    bool warnings() { return d_warnings; }
    QString errmsg() { return d_errmsg; }
    QStringList warningsList() { return d_warn; }
    
  protected:
    
    bool sipSet() { return sip != QString(); }
    bool dipSet() { return dip != QString(); }
    bool dportSet() { return dport != QString(); }
    bool sportSet() { return sport != QString(); }
    bool ipSet() { return ip != QString(); }
    bool ip1Set() { return ip1 != QString(); }
    bool ip2Set() { return ip2 != QString(); }
    bool genericIpSet() { return ip1 != QString() || ip2 != QString(); }
    bool portSet() { return port != QString(); }
    bool port1Set() { return port1 != QString(); }
    bool port2Set() { return port2 != QString(); }
    bool genericPortSet() { return port1 != QString() || port2 != QString(); }
    bool flagsSet() { return flags != QString(); }
    bool protocolSet() { return protocol != QString(); }
    
    bool inifSet() { return inif != QString(); }
    bool outifSet() { return outif != QString(); }
    bool ifSet() { return iface != QString(); }
    
    bool stateSet() { return d_state != QString(); }
    bool notifySet() { return d_notify != QString(); }
    
    QString sdirection();
    QString spolicy();
    QString sowner();
    QString genericPort();
    QString genericIp();
    QString state() { return d_state; }
    QString notify() { return d_notify; }
    
  private:
  
    MachineSentence d_ms;
    bool d_conversionOk;
    QString d_errmsg;
    
    QStringList d_keywords;
    QStringList d_sections;
    QStringList d_uniqueKeywords;
    
    QStringList d_warn;
    bool d_warnings;
    
    /* look if there is something to filter or to arrange before splitting. Maybe some redundant
    * keywords must be changed. For example: 'SOURCE IP' might become the keyword 'SIP'
    */
    void preFilter();
    
    void splitSentenceByKeywords();
    /* takes each section and tries to fill in sip, dip, sport, direction...
     * and all we need to understand the fields of the item to build.
     */
    bool buildConverter();
    
    /* analyzes the information gathered by buildConverter() and tries to 
     * understand what to do with the item to create. This should fix all
     * the strings sip, dip, sport, dport.. needed to finally build the
     * string list for the rule item.
     */
    bool analyzeContents();
    
    /* returns true if any keyword is unique in the sentence, otherwise it returns false.
     * For instance, there cannot be more than one keyword SIP or DIP..
     */
    bool checkKeywordUniqueness();
    
    QList<int> d_sectionsPos;
    
    void setPortionRead(int, int);
    bool alreadyRead(int);
    
    QList<QPair<int,int> > portionsRead;
    
    QString ip, sip, dip, sport, dport, port, flags, protocol, ip1, ip2;
    QString port1, port2;
    QString inif, outif, iface, d_state, d_notify;
    
    int d_direction, d_policy;
    uid_t d_owner;
    bool d_snat, d_dnat, d_masq;
};




#endif

