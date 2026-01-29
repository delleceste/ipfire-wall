#ifndef NATURAL_TEXT_H
#define NATURAL_TEXT_H

#include <QStringList>
#include <QtDebug>
#include <QObject>
#include <QMap>
#include "NaturalSentence.h"
#include "macros.h"
#include "dictionary.h"


class NaturalCustomProcessor;

/** the NaturalText class is a text containing one ore more
 *  NaturalSentences. It is constructed by passing a natural 
 *  text as input argument and a QObject as a parent.
 *  Natural Text is a QObject so that it is able to emit() 
 *  signals. They are used to notify in case of errors.
 */
class NaturalText : public QObject
{
Q_OBJECT
  public:
    /** The constructor
     * @param text the text to setup the NaturalText object
     * @param parent the QObject which will be the parent of the Natural text.
     * NaturalText is a QObject to allow communication through signal/slot 
     * mechanism. The parent receives also an event when an ok, warning or
     * error message is to be sent by the natural text processor.
     *
     */
    NaturalText(QString text, QObject* parent);
     
    /**
     *  The method starts processing the natural text doing the following:
     *  1. executes preliminary substitutions looking into pre_sostitutions.txt;
     *  2. removes unwanted text specified in the regexps in unwanted_regexps.txt;
     *  3. separates text into sentences, which are made available through the 
     *     sentences() method.
     *  Each sentence is recognized and excerpted from the text looking for a verb.
     *  Each sentence must contain one verb.
     *  You must call startProcessing() after NaturalText constructor.
     *  If you need pre processing or post processing, create a NaturalCustomProcessor
     *  and set it with setCustomProcessor().
     *  NaturalCustomProcessor::preProcess() is called <strong>before</strong> anything is
     *  done to the natural text.
     *  NaturalCustomProcessor::postProcess() is called <strong>on the separate sentences</strong> 
     *  individuated by the separateSentences() private method called by startProcessing(). 
     *  
     *  When natural text is processed, i.e. separated into sentences, the sentences themselves
     *  become the real protagonist of the Natural Text.
     */
    void startProcessing();
    
    /** set of sentences recognized in the text */
    QList<NaturalSentence> sentences() { return d_sentences; }
    
    /** @return the last error that took place */
    QString lastError() { return errmsg; }
    /** @return true if an error happened */
    bool error() { return d_error; }
    
    /** If you need special processing 
     *  - on the pure natural text, <strong>before</strong> any operation is done on it
     *    inside startProcess(), or
     *  - on the just separated sentences, at the end of the method startProcessing(),
     *  you must inherit from NaturalCustomProcessor and implement 
     *  void preProcess(NaturalText &); and
     *  void processSeparateSentences(QList<NaturalSentence> &);
     *  The first method operates on the Natural text, the second on the list of already
     *  separated sentences.
     */
    void setCustomProcessor(NaturalCustomProcessor *ncp);
    
    /** This removes the NaturalCustomProcessor, if previously set, from the NaturalText.
     *  Beware that this does not delete it.
     */
    void removeCustomProcessor() { if(d_naturalCustomProc) d_naturalCustomProc = NULL; }
    
    /** The following emits a warning event to the parent, if parent is set */
    void warning(QString message);
     /** The following emits an error event to the parent, if parent is set */
    void error(QString err);
     /** The following emits a message event to the parent, if parent is set */
    void message(QString msg);
    
    QString text() { return d_text; }
    
    void setText(const QString txt) { d_text = txt; }
    
    signals:
    
      /** This signal is emitted when an error is detected.
       * @param origin the name of the method in which the problem originated
       * @param message the error message
       */
      void error(const QString& origin, const QString& message);
      
      
  protected:
    
  private:
    
    void clearUnwantedText();
    void preSubstitutions();
    
    void setPortionRead(int start, int len);
    bool portionNotRead(int start, int len);
    
    QList<NaturalSentence> separateSentences();
    
    QList<NaturalSentence> d_sentences;
    Dictionary* dictionary;
    
    QMap<int, QString> d_verbsPositionMap;
    QMap<NaturalWord, NaturalWord> d_substitutionsMap;
    
    NaturalCustomProcessor *d_naturalCustomProc;
    QList<QPair <int, int> > d_portionsRead;
    
    QString d_text; /* the text */
    QString d_lang; /* string representing the language: it, en, es... */
    bool d_error;
    QString errmsg;
};


#endif
