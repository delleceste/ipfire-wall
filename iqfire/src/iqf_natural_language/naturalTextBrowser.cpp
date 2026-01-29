#include "naturalTextBrowser.h"
#include <macros.h>
#include <QFile>
#include <QTextStream>
#include <QString>
#include <QDir>

NaturalTextBrowser::NaturalTextBrowser(QWidget *parent) : QTextBrowser(parent)
{
  setReadOnly(false);
  setUndoRedoEnabled(true);
  setAcceptRichText(false);
  d_error = false;
  QString filename = QDir::home().absolutePath() + "/.IPFIRE/natural_rules";
  QFile file(filename);
  if(file.open(QIODevice::ReadOnly | QIODevice::Text))
  {
    QTextStream in(&file);
    while (!in.atEnd())
    {
         QString line = in.readLine();
	 append(line);
    }
    file.close();
  }
  else
    perr("failed to open file \"%s\" for writing, while trying to load natural rules", qstoc(filename));
}

void NaturalTextBrowser::save()
{
   pok("saving natural rules...");
  QString filename = QDir::home().absolutePath() + "/.IPFIRE/natural_rules";
  QFile file(filename);
  if(file.open(QIODevice::WriteOnly | QIODevice::Text))
  {
    QTextStream out(&file);
    out << toPlainText();
    file.close();
    pok("saved natural rules, closing file");
  }
  else
    perr("failed to open file \"%s\" for writing, while trying to save natural rules", qstoc(filename));
}

NaturalTextBrowser::~NaturalTextBrowser()
{
  
}

void NaturalTextBrowser::initSearch()
{
   moveCursor(QTextCursor::Start, QTextCursor::MoveAnchor);
}







