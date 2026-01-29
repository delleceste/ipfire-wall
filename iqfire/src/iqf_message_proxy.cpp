#include "iqf_message_proxy.h"
#include "iqfwidgets.h" /* for BROWSER_DEFAULT_PATHS */

#include <QFile>
#include <QtDebug>
#include <QTextStream>
#include <QSettings>

IQFMessageProxy* IQFMessageProxy::_instance = NULL;

IQFMessageProxy::IQFMessageProxy()
{
	QSettings s;
	opened_info_filename = opened_help_filename = "no file opened in the constructor";
	QStringList paths = s.value("BROWSER_PATHS", BROWSER_DEFAULT_PATHS).toStringList();
	if(paths.size() == 3)
	{
		setInfoPath(paths[0]);
		setHelpPath(paths[1]);
		setManPath(paths[2]);
	}
	setExtension();
}

IQFMessageProxy* IQFMessageProxy::msgproxy()
{
	if(_instance == NULL)
		return (_instance = new IQFMessageProxy() );
	else
		return _instance;
}

QString IQFMessageProxy::getInfo(QString key)
{
	QString info = "Info unavailable";
	QString filename = _infopath + key + _extension;
	
	if(filename == opened_info_filename)
		return current_info;
	
	QFile file(filename);
	if(!file.open(QIODevice::ReadOnly | QIODevice::Text))
	{
		QString action;
		action = QString("cp %1 %2").arg(_infopath + "sample.html").arg(filename);
		if(system(action.toStdString().c_str()) == 0)
		  qDebug() << "Created sample info file: " << filename;
		else
		  printf("\e[1;31m*\e[0m IQFMessageProxy::getInfo(): could not create sample info file\n");
		opened_info_filename = "failed to open file";
	}
	else
	{
		info = "";
		opened_info_filename = filename;
		QTextStream in(&file);
		while(!in.atEnd())
		{
			info += in.readLine();
		}
		file.close();
		current_info = info;
	}
	
	return info;
}

QString IQFMessageProxy::getHelp(QString key)
{
	QString help = "Help unavailable";
	QString filename = _helppath + key + _extension;
	
	if(filename == opened_help_filename)
		return current_help;
	
	QFile file(filename);
	if(!file.open(QIODevice::ReadOnly | QIODevice::Text))
	{
		QString action;
		action = QString("cp %1 %2").arg(_infopath + "sample.html").arg(filename);
		if(system(action.toStdString().c_str()) == 0)
		  qDebug() << "Created sample help file: " << filename;
		else
		  printf("\e[1;31m*\e[0m IQFMessageProxy::getHelp(): could not create sample help file\n");
		opened_help_filename = "failed to open file";
// 		help = QString("<p>Help file <strong>\"%1\"</strong> not available</p>").arg(filename);
	}
	else
	{
		help  = "";
		opened_help_filename = filename;
		QTextStream in(&file);
		while(!in.atEnd())
		{
			help += in.readLine();
		}
		file.close();
		current_help = help;
	}
	
	return help;
}

QString IQFMessageProxy::getMan(QString key)
{
	QString man = "Man unavailable";
	QString filename = _manpath + key + _extension;
	
	if(filename == opened_man_filename)
		return current_man;
	
	QFile file(filename);
	if(!file.open(QIODevice::ReadOnly | QIODevice::Text))
	{
	//	qDebug() << "Failed to open file: " << filename;
		opened_man_filename = "failed to open file";
		man = QString("<p>Manual file <strong>\"%1\"</strong> not available</p>").arg(filename);
	}
	else
	{
		man  = "";
		opened_man_filename = filename;
		QTextStream in(&file);
		while(!in.atEnd())
		{
			man += in.readLine();
		}
		file.close();
		current_man = man;
	}
	
	return man;
}


QString IQFMessageProxy::insertInfoIntoHtmlHeader(QString s)
{
	QString h = "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n"
		"<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.1//EN\""
		"\"http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd\">\n";
	
	h += "<html xmlns=\"http://www.w3.org/1999/xhtml\">"
		"<link rel=\"stylesheet\" href=\"info.css\" type=\"text/css\" />\n";
	
	h += s;
	
	h += "\n</html>";
	
//	qDebug() << h;
	
	return h;
}

QString IQFMessageProxy::insertHelpIntoHtmlHeader(QString s)
{
	QString h = "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n"
			"<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.1//EN\""
			"\"http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd\">\n";
	
	h += "<html xmlns=\"http://www.w3.org/1999/xhtml\">"
			"<link rel=\"stylesheet\" href=\"help.css\" type=\"text/css\" />\n";
	
	h += s;
	
	h += "\n</html>";
	
//	qDebug() << h;
	
	return h;
}




