#ifndef NATURAL_RULE_HASH
#define NATURAL_RULE_HASH

#include <ipfire_structs.h>
#include <QMap>
#include <QString>


class NaturalRuleHash
{
  public:
    
    static NaturalRuleHash *naturalRuleHashMap();
    
    ~NaturalRuleHash();
    
    void addNaturalRule(const ipfire_rule *r, const QString &naturalSentence);
    QString naturalSentenceForRule(const ipfire_rule *r);
    
    void save();
    void clearNatMap() { d_natMap.clear(); }
    void clearFilterMap() { d_map.clear(); }
    
  private:
    NaturalRuleHash();
    
    QMap<QString, QString> d_map;
    QMap<QString, QString> d_natMap;
    static NaturalRuleHash *_instance;
};

#endif
