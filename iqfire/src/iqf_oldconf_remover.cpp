#include "iqf_oldconf_remover.h"
#include <QDir>
#include <QString>


IQFOldconfRemover::IQFOldconfRemover()
{
	rmdirnam = QDir::homePath() + "/IPFIRE";
}

bool IQFOldconfRemover::remove()
{
	bool ret;
	QDir rmdir(rmdirnam);
	if(!rmdir.exists())
	{
		_error = QString("The directory \"%1\" does not exist.").
				arg(rmdirnam);
		ret = false;
	}
	else
	{
		QDir homedir(QDir::homePath());
		ret = homedir.rmpath(rmdirnam);
		if(!ret)
			_error = QString("Error removing the directory \"%1\"").
					arg(rmdirnam);
	}
	return ret;
}
