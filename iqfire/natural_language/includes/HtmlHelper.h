#ifndef HTML_HELPER_H
#define HTML_HELPER_H

#include <QString>
#include <QMultiMap>

class HtmlHelper
{
  public:
    /** category: keyword describing the category. The corresponding filename is calculated
     * added ".txt" to the category.
     * For instance category = "verbs" will open file verbs.txt.
     */
    HtmlHelper(const QString &category);
    
    QString htmlHelp(QChar c);
    
  protected:
    QMultiMap<QString, QString> map;
    
  private:
    QString d_help, d_category;
    int d_def, d_desc;
    QString helpForChar(QChar c);
    bool charHasHelp(QChar c);
};





#endif
