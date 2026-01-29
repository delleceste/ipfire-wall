#include "iqfire_module_load_check.h"
#include <QFileInfo>
#include <QDateTime>

ModuleLoadCheck::ModuleLoadCheck()
{
   
}

bool ModuleLoadCheck::loadFailed()
{
   QFileInfo fi("/tmp/ipfire.fail.log");
   if(fi.exists())
   {
     d_errMsg = QString("The \"ipfire-wall\" kernel module failed to load on %1\n").arg(fi.created().toString());
      d_errMsg += QString("This is likely dued to a recent kernel upgrade/rebuild:\n"
	"please run, as root (or with sudo) \"/usr/bin/ipfire-kernel-updater\"");
     return true;
   }
   return false;
}
