#include "includes/HtmlHelper.h"
#include <QFile>
#include <QTextStream>
#include <QStringList>
#include <QSettings>
#include <QtDebug>
#include "includes/macros.h"


HtmlHelper::HtmlHelper(const QString &category)
{
  QSettings s;
  QString filename;
  /* depending on the category, the corresponding files have definitions and descriptions in 
   * different places.
   */
  d_def = 0;
  d_desc = 1;
  
  d_category = category;
  
  QString lang = s.value("NATURAL_LANGUAGE", "italiano").toString();
  QString folderPath = s.value(QString("DICT_PATH"), QString("dictionary")).toString();
  folderPath += QString("/%1/").arg(lang);
  filename = folderPath + category + ".txt";
  
  QFile file(filename);
  int linecnt = 0;
  if(file.open(QIODevice::ReadOnly | QIODevice::Text))
  {
     pok("HtmlHelper: opened file \"%s\"" , qstoc(filename));
     QTextStream in(&file);
     while (!in.atEnd())
     {
       linecnt++;
       QString line = in.readLine();
       QString cleanLine;
       if(line.contains(QRegExp("#\\s+DOC\\s+")))
       {
	  cleanLine = line.remove(QRegExp("#\\s+DOC\\s+"));
	  QStringList list = cleanLine.split("::", QString::SkipEmptyParts);
	  if(list.size() > d_def && list.size() > d_desc)
	  {
	    /* # DOC lines can contain multiple keys in one line, separated by ;; */
	    QString definition = list.at(d_def);
	    QStringList defList;
	    if(definition.contains(";;")) /* verbs and names might contain it */
	      defList = definition.split(";;", QString::SkipEmptyParts);
	    else
	      defList << definition;
	      
	    foreach(QString d, defList)
	    {
	      map.insert(d, list.at(d_desc));
	      qDebug() << "inserting couple " << d << list.at(d_desc);
	      }
	  }
	  else
	  {
	    pwarn("line \"%s\" (n. %d), file \"%s\": there are %d sections but definition should be at %d and description at %d",
		  qstoc(line), linecnt, qstoc(filename), list.size(), d_def, d_desc);
	    pwarn("line %d not added to help", linecnt);
	  }
	  
	}
      }
      file.close();
      qDebug() << "loaded map" << map << "for " << d_category;
   }
   else
    perr("failed to open file \"%s\" for reading", qstoc(filename));
}

bool HtmlHelper::charHasHelp(QChar c)
{
  QList<QString> definitions = map.keys();
  foreach(QString def, definitions)
  {
    if(def.startsWith(c, Qt::CaseInsensitive ))
      return true;
  }
  return false;
}

QString HtmlHelper::helpForChar(QChar c)
{
  QString html;
  QList<QString> definitions = map.keys();
  foreach(QString def, definitions)
  {
    if(def.startsWith(c, Qt::CaseInsensitive ))
      html += QString("<li><a href=\"action://naturallanguage_appendtext/%1\" title=\"click to add %2 to the text editor\">%3</a>: <em>%4</em></li>").arg(def).arg(def).arg(def).arg(map.value(def));
  }
  return html;
}

QString HtmlHelper::htmlHelp(QChar c)
{
  QString html = "<html><head>";
  html += "<style type=\"text/css\" rel=\"stylesheet\">\n";
  html += "h3 { font-size:10pt; font-weight:bold; text-align:center; }";
  html += "h4 { font-size:9.5pt; font-weight:bold; text-align:center; }";
  html += "h5 { font-size:9pt; font-weight:bold; text-align:center; }";
  html += "ul, li { font-size:8pt; }";
  html += "p { font-size:8pt; }";
  html += "a { font-size:8pt;  color:rgb(0, 148, 213); font-weight:bold; text-decoration:none; }";
  html += ".lettersLinks { color:rgb(0, 138, 200); font-weight:bold; text-decoration:none; padding-left:5px; }";
  html += ".alphabet { color:rgb(180,180,182); font-size:9pt; text-decoration:none; }";
  html += ".alphabetElement { border-color:rgb(200,200,205); border-width:1px; margin:2px; }";
  html += "h4 { font-size:11pt; font-weight:bold; text-align:center; }";
  html += ".header { color:rgb(0, 151, 84); }";
  html += "</style>";
  html += "</head>\n<body>\n";
  html += "<div id=\"content\">\n";
  html += QString("<h3 align=\"center\">Natural language %1</h3>\n").arg(d_category);
  
  html += "<div class=\"pageIntro\">";
  html += "<p>Back to <a href=\"browserHelp://natural_language\" title=\"back to natural language help\">natural language</a> help.</p>";
  html += "<p>Click on the blue links to automatically add the text to the natural language editor.</p>";
  html += "</div>";
  
  html += "<div class=\"alphabet\">"; 
  for(int i = 'A'; i <= 'Z'; i++)
    html += QString("<a class=\"lettersLinks\" href=\"action://naturalhelp/%1/%2\">%3</a> ").arg(d_category).arg(QChar(i)).arg(QChar(i));
  html += "</div>";
  
  html += "<div id=\"content\">\n";
  
  
  if(c != '.')
  {
    html += "\n<ul>";
    html += helpForChar(c);
    html += "</ul>";
  }
  else
  {
    html += QString("<div class=\"header\"><h4 align=\"center\">%1 list</h4></div>").arg(d_category);
    for(int i = 'A'; i <= 'Z'; i++)
    {
      if(charHasHelp(i))
      {
	html += "<div class=\"alphabetElement\">";
	html += QString("<span><a class=\"lettersLinks\" href=\"action://naturalhelp/%1/%2\">%3</a></span>").arg(d_category).arg(QChar(i)).arg(QChar(i));
	html += "<ul>";
	html += helpForChar(i);
	html += "</ul>";
	html += "</div>";
      }
    }
  }
  
  
  html += "<p>Back to <a href=\"browserHelp://natural_language\" title=\"back to natural language help\">natural language</a> help.</p>";
  html += "</div></body></html>";
  qDebug() << html;
  return html;
}






