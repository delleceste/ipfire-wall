#include "iqf_version.h"
#include <QStringList>

/* removes the dots from the version and returns 
 * the so obtained string converted to int.
 */
int IQFVersion::iqf_version()
{
	QString verWithoutDots;
	QStringList parts;
	QString iqfv = iqf_versionString();
	int v = 0;
	parts = iqfv.split('.');
	/* suppose that the version is like 
	 * xx.yy.zz, whit at most 2 version numbers per part.
	 */
	if(parts.size() == 3)
	{
		v = parts[2].toInt() + parts[1].toInt() * 100 + parts[0].toInt() * 10000;
	}
	return v;
}

