#ifndef IQF_OLDCONF_REMOVER
#define IQF_OLDCONF_REMOVER

#include <QString>

class IQFOldconfRemover
{
	public:
		IQFOldconfRemover();
		bool remove();
		QString error() { return _error; }
		
	private:
		int _code;
		QString rmdirnam;
		QString _error;
		
};

#endif

