#ifndef SERVICE_PROCESSOR_H
#define SERVICE_PROCESSOR_H

#include "includes/NaturalCustomProcessor.h"
#include <QMap>

class ServiceProcessor : public NaturalCustomProcessor
{
  public:
  ServiceProcessor();
  bool preProcess(QString &) { return true; }
  
  bool processSeparateSentences(QList<NaturalSentence>& );
  
  QString serviceDescription(const NaturalWord& serviceName);
  
  private:
  /* NaturalWord is the natural word describing the service. 
   * NOTE: it is the first word in each line of the services.txt text file.
   * For example, if services.txt contains a line as:
   * "eMule;;the Mule;;the eMule application::{tcp 4099}{udp 5003}::the peer to peer application.."
   * then the map entry for eMule will be like
   * <"eMule", "the peer to peer application..">
   */
  QMap<NaturalWord, QString> d_serviceDescriptionMap;
  
  /* the substitutions map */
  QMap<NaturalWord, NaturalWord> d_substitutionsMap;
  
  QStringList d_linesFromFile;
  
  QString d_filename;
  
  /* read from configuration file and fill d_linesFromFile */
  bool gatherLinesFromFile();
  
  /* read d_linesFromFile strings and fill in the two main maps */
  bool fillMaps();
  
  QString d_objectName;
};


#endif
