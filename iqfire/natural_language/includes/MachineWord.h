#ifndef MACHINE_WORD_H
#define MACHINE_WORD_H

#include <QString>

class MachineWord : public QString
{
  public:
    MachineWord(QString s = QString());
    
    void setError(bool err) { d_error = err; }
    void setErrorMessage(QString msg) { d_errMsg = msg; }
    
    QString errorMessage() { return d_errMsg; }
    bool error() { return d_error; }
   
    
  private:
    QString d_errMsg;
    bool d_error;
};


#endif
