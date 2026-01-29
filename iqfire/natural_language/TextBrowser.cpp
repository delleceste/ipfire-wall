#include "TextBrowser.h"
#include "includes/NaturalText.h"
#include "includes/toMachine.h"
#include "includes/MachineText.h"
#include "includes/dictionary.h"
#include "includes/grammar.h"
#include "ServiceProcessor.h"

TextBrowser::TextBrowser(QWidget *parent) : QTextBrowser(parent)
{
  setReadOnly(false);
  setText("1. Apri la porta 22 da 192.168.0.11/255.255.255.0.\n2.Consenti il traffico dalla porta  25 "
    "per l'indirizzo destinazione 192.168.11.1 sottorete 255.255.255.4.\n"
    "3. Chiudi la porta 22 e apri la 23\n4) Consenti l'accesso da 192.168.0.1, aprire la porta 22202\n" 
    "4) Consenti l'accesso all'interno dell'intervallo di indirizzi 192.168.1.100 e 192.168.1.200, aprire la porta 22202\n"
    "5) permetti il traffico tra 192.168.0.1 netmask 255.255.255.16 e 192.168.1.100\n"
     "6) trasmetti il traffico da 1.12.111.121 a 22.33.44.1"
		"\n7) blocca la trasmissione da 192.168.1.100 a 192.168.1.104, porta destinazione 22, tcp"
		"\n8) blocca la trasmissione tra 192.168.1.105 e 192.168.1.110, porta destinazione 20022"
		"\n9) blocca la trasmissione tra  192.169.1.110 e 192.169.1.114, porta destinazione 22"	
		"\n10) consenti l'accesso da 192.168.1.100 netmask 24 porte 22-32 porte sorgente all'interno dell'intervallo 20000-25000"
		"\n11) consenti l'accesso da 192.168.7.100 sottorete 24 syn disattivato ack on"
		"\n12) blocca la trasmissione tra  192.169.1.110/24 e 192.169.1.114/24, porta destinazione 22"	
	"\n13) consenti l'accesso agli indirizzi ip 192.168.0.0/255.255.255.0, 192.168.1.0/24 e 192.168.2.11, connessione in\nfase di setup"
	""
	""
	""
	""
	""
	 );
//   setText("Consenti il traffico eMule");
}

void TextBrowser::process()
{
  bool res;
  NaturalText *nt = new NaturalText(this->toPlainText(), this);
  connect(nt, SIGNAL(error(const QString &, const QString &)), this, 
    SLOT(popupError(const QString &, const QString &)));
    
  ServiceProcessor *servProcessor = new ServiceProcessor();
  nt->setCustomProcessor(servProcessor);
  
  nt->startProcessing();
  
  if(nt->error())
    perr("An error occurred in NaturalText->separateSentences(): %s", qstoc(nt->lastError()));
  else
  {
    QList<NaturalSentence> sentences = nt->sentences();
    foreach(NaturalSentence ns, sentences)
      qDebug() << "separate sentences: " << ns << ", ";
    /* conversion */
    NaturalTextToMachine toMachine(nt, this);
    connect(&toMachine, SIGNAL(error(const QString &, const QString &)), this, 
      SLOT(popupError(const QString &, const QString &)));
    res = toMachine.convertToMachine();
      QString processedText;
    if(res) /* res == true, conversion succeeded */
    {
      MachineText *mt = toMachine.machineText();
      QList<MachineSentence> machineSentences = mt->machineSentences();
      int i;
      for(i = 0; i < machineSentences.size(); i++)
      {
	processedText += QString("%1. %2\n").arg(i).arg(machineSentences[i]);
      }
    }
    else
      processedText = QString("There was an error processing the text.\n"
	"The reported error was: \"%1\"").arg(toMachine.lastErrorMessage());
	
    emit processed(processedText);
  }
}

void  TextBrowser::reloadDict()
{
  Dictionary::instance()->reload();
  Grammar::instance()->reload();
}

void  TextBrowser::popupError(const QString& origin, const QString& msg)
{
  QMessageBox::information(this, origin, msg);
}




