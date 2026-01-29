#include <QRegExp>
#include <QCoreApplication>
#include <macros.h>
#include <iqflog.h>
#include "naturalMessageEvents.h"
#include "naturalTextResolverThread.h"
#include <errno.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>

extern int h_errno;

NaturalTextResolverThread::NaturalTextResolverThread(NaturalText* text, QObject *parent)
  : QThread(parent)
{
  d_txt = text;
}

void NaturalTextResolverThread::run()
{
  struct hostent* he;
  char address[INET_ADDRSTRLEN];
  /* regular expression to capture text to resolve */
  QRegExp resRe("\\\"[a-zA-Z0-9\\.;:/\\-_+()@#$]*\\\"");
  QString progressMsg;
  QString name, quotedName;
  QString resolvedAddr = QString(), resolvedPort = QString();
  int pos = 0, count  = d_txt->text().count(resRe);
  pos = resRe.indexIn(d_txt->text(), pos);
  while(pos >= 0)
  {
    resolvedAddr = QString();
    QStringList capt = resRe.capturedTexts();
    if(capt.size() == 1)
    {
      name = capt.at(0);
      quotedName = name;
      name.remove("\"");
      he = gethostbyname(name.toStdString().c_str());
      if(he != NULL)
      {
	int i = 0;
	while(he->h_addr_list[i] != NULL)
	{
	  if(inet_ntop(AF_INET, he->h_addr_list[i], address, INET_ADDRSTRLEN) > 0)
	  {
	    QString addr = QString("%1").arg(address);
	    QString sokme = QString("<strong>resolved</strong> name \"<cite>%1</cite>\" into address %2").arg(name).arg(addr);
	    OkMessageEvent *okme = new OkMessageEvent(sokme);
	    qApp->postEvent(parent(), okme);
	    resolvedAddr += QString("%1,").arg(addr);
	    emit resolutionProgress(i, count, QString("resolving \"%1\"").arg(name));
	  }
	  i++;
	}
	resolvedAddr.remove(resolvedAddr.size() -1, 1); /* last ',' */
	pok("resolved correctly name \"%s\" into address(es) %s", qstoc(name), qstoc(resolvedAddr));
	QString oldText = d_txt->text();
	printf("\e[1;32m rimpiazzo \"%s\" con \"%s\"\n", qstoc(quotedName), qstoc(resolvedAddr));
	QString newText = oldText.replace(quotedName, resolvedAddr);
	printf("nuovo testo: \e[0m\"%s\"\n", qstoc(newText));
	d_txt->setText(newText);
      }
      else
      {
	/* The  getservent(),  getservbyname()  and  getservbyport() functions return a pointer to a statically allocated servent structure, or a NULL
         * pointer if an error occurs or the end of the file is reached. (man page)
	 */ 
	struct servent *se = getservbyname(name.toStdString().c_str(), NULL);
	if(se)
	{
	  resolvedPort = QString("%1 %2").arg(ntohs(se->s_port)).arg(se->s_proto);
	  QString okmsg = QString("<strong>resolved</strong> service name \"<cite>%1</cite>\" into port %2").
	    arg(name).arg(resolvedPort);
	  OkMessageEvent *okme = new OkMessageEvent(okmsg);
	  qApp->postEvent(parent(), okme);
	  QString oldText = d_txt->text();
	  QString newText = oldText.replace(quotedName, resolvedPort);
	  d_txt->setText(newText);
	}
	else /* he null also */
	{
	  QString err = QString("<strong>error</strong>: could not resolve name \"<cite>%1</cite>\""
	  "<br/>The error was: \"<cite>%2</cite>\".<br/><em>Remember</em>: words inside <strong>\"</strong>"
	  "quotes<strong>\"</strong> are interpreted as Internet names or services").arg(name).
	    arg(hstrerror(h_errno));
	  ErrorMessageEvent *eme = new ErrorMessageEvent(err);
	  qApp->postEvent(parent(), eme);
	}
      }
    }
    pos += resRe.matchedLength();
    pos = resRe.indexIn(d_txt->text(), pos);
  } /* end while */
  if(resolvedAddr  != QString())
  {
    /* warn to use this feature with caution */
    QString warn = QString("<strong>Beware</strong>: note that specifying any name to be resolved "
      "with a remote query such as DNS is a really bad idea. Numeric Internet addresses might change "
      "frequently and you should often re-evaluate your natural text! <strong>This is not done automatically "
      "by the firewall!</strong>");
    WarningMessageEvent *wme = new WarningMessageEvent(warn);
    qApp->postEvent(parent(), wme);
  }
}


