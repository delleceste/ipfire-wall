#ifndef NATURAL_TEXT_BROWSER
#define NATURAL_TEXT_BROWSER

#include <iqfwidgets.h>

class NaturalTextBrowser : public QTextBrowser
{
  Q_OBJECT
  public:
    NaturalTextBrowser(QWidget *parent);
    ~NaturalTextBrowser();
    
    void save();
    void setHasErrors(bool err) { d_error = err; }
    bool hasErrors() { return d_error; }
    
    /** positions the cursor at the beginning of the document */
    void initSearch();
    bool d_error;
};


#endif
