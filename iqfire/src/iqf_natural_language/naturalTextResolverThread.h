#ifndef NATURAL_TEXT_RESOLVER_THREAD
#define NATURAL_TEXT_RESOLVER_THREAD

#include <QString>
#include <QThread>
#include <NaturalText.h>

class NaturalTextResolverThread : public QThread
{
  Q_OBJECT
  public:
    NaturalTextResolverThread(NaturalText* text, QObject *parent);
    
    NaturalText *text() { return d_txt; }
    
  signals:
    /* emitted by the thread in the run() method: QueuedConnection ! */
    void resolutionProgress(int, int, const QString&);
    
  protected:
    void run();
    
  private:
    NaturalText *d_txt;
};

#endif

