#ifndef IQFIRE_MODULE_FAIL_CHECK
#define IQFIRE_MODULE_FAIL_CHECK

#include <QString>

class ModuleLoadCheck
{
  public:
    ModuleLoadCheck();
    
    bool loadFailed();
    
    QString errorMessage() { return d_errMsg; }
    
  private:
    QString d_errMsg;
};

#endif

