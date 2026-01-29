#include "naturalHelpRetriever.h"
#include "HtmlHelper.h"
#include <dictionary.h>
#include <QStringList>

NaturalHelpRetriever::NaturalHelpRetriever(QString action)
{
   QStringList list = action.split('/', QString::SkipEmptyParts);
   if(list.size() == 2)
   {
     d_category = list.first();
     if(list.last().size() > 0)
      d_char = QChar(list.last()[0]);
     else 
       d_char = 'a';
     d_char = d_char.toUpper();
   }
}

QString NaturalHelpRetriever::getHelp()
{
  HtmlHelper hh(d_category);
  QString ret = hh.htmlHelp(d_char);
  return ret;
}

