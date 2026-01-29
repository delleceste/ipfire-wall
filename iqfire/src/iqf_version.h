#ifndef IQF_VERSION_H
#define IQF_VERSION_H

#include <QString>
#include <ipfire_structs.h> /* contains the definition of ipfire version */


#define IQFIRE_VERSION QString(VERSION)
#define IPFIRE_VERSION QString(VERSION)

class IQFVersion
{
	public:
		IQFVersion() {}
		QString iqf_versionString() { return IQFIRE_VERSION; }	
		QString ipf_versionString() { return IPFIRE_VERSION; }
		int iqf_version();
};





#endif


