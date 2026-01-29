#ifndef SECTION_ANALYZER_H
#define SECTION_ANALYZER_H

#include <QString>

class SentenceSectionAnalyzer : public QString
{
  public:
    SentenceSectionAnalyzer(QString s);
    
    bool isProtocol();
    QString protocol();
    
    bool isDirection();
    int direction();
    
    bool isPolicy();
    int policy();
    
    bool isSnat();
    bool isDnat();
    bool isMasquerade();
    
    /* network interfaces */
    bool containsInif();
    bool containsOutif();
    bool containsIf();
    
    bool isSip();
    bool isDip();
    bool isIpNot();
    bool isIp();
    
    bool containsIp();
    bool containsIpInterval();
    bool containsIpList();
    
    QString inIf(bool *ok);
    QString outIf(bool *ok);
    QString iface(bool *ok);
    
    QString ip(bool *ok);
    QString ipInterval(bool *ok);
    QString ipList(bool *ok);
    
    bool isPort();
    bool isSport();
    bool isDport();
    bool containsPort();
    bool containsPortList();
    bool containsPortInterval();
    bool isPortNot();
    QString port(bool *ok);
    QString portInterval(bool *ok);
    QString portList(bool *ok);
    
    bool isState();
    QString state();
    
    bool isNotify();
    QString notify();
    
  
  private:
  
    /* QString's count(QRegExp) counts also overlapping sequences.
     * This is a function that counts regexp occurrences, non overlapping
     */
    int nonOverlapCount(QString regexp);
    
    bool checkIp(QString &ip);
    bool checkPort(QString &port);
};

#endif


