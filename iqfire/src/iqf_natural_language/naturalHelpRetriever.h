#ifndef NATURAL_HELP_RETRIEVER
#define NATURAL_HELP_RETRIEVER

#include <QString>
#include <QChar>

class NaturalHelpRetriever
{
  public:
    NaturalHelpRetriever(QString action);
    QString getHelp();
    
  private:
    QString d_category;
    QChar d_char;
    
};



#endif
