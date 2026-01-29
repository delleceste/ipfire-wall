#include "iqf_utils.h"
#include "iqflog.h"

#include <QStringList>
#include <QFile>
#include <QDir>
#include <QSettings>
#include <QTextStream>
#include <QMessageBox>
#include <QDialog>
#include <QGridLayout>
#include <QPushButton>
#include <QTextBrowser>
#include <QRegExp>
#include <QtDebug>
#include <errno.h>
#include "rule_builder.h"
#include "iqf_validators.h" /* validators */


IQFUtils* IQFUtils::_instance = NULL;

IQFUtils* IQFUtils::utils(QObject *parent)
{
	if(_instance == NULL)
		_instance = new IQFUtils(parent);
	
	return _instance;
}

IQFUtils::IQFUtils(QObject *parent) : QObject(parent)
{
	ipv6_enabled = true;
}

IQFUtils::~IQFUtils()
{
}

QString IQFUtils::styleSheet(QString filename)
{
	QString sheet = "";
	QFile stylesheetFile( filename);
	if (!stylesheetFile.open(QIODevice::ReadOnly | QIODevice::Text))
		QMessageBox::information(0, "Error", 
				QString("Unable to open the style sheet\n"
				"\"%1\"").arg(filename));

	QTextStream in(&stylesheetFile);
	
	while (!in.atEnd()) {
		sheet += in.readLine();
	}
	return sheet;
}

QStringList IQFUtils::activeNetdevs()
{
	QStringList devs, procrow;
	QString devname;
	QSettings s;
	QString procfile = s.value("PROC_NET_DEV", QString("/proc/net/dev")).toString();
	QFile file(procfile);
	if (!file.open(QIODevice::ReadOnly | QIODevice::Text))
	{
		Log::log()->appendFailed(QString("Failed to open the proc file \"%1\".\n"
			"Check the settings and verify that the proc file name is correct\n"
			"and that you have the permission to read it.").arg(procfile));
		return devs;
	}
	QTextStream in(&file);
	QString line = in.readLine();
	
	while(!line.isNull())
	{
		if(line.contains(":"))
		{
			procrow = line.split(':');
			devname = procrow[0];
			devname = devname.remove(' ').remove('\t');
			devs.push_back(devname);	
		}
		line = in.readLine();
	}
	
	return devs;
}

void IQFUtils::htmlDialog(QString msg)
{
	QDialog *dlg = new QDialog(0);
	QPushButton pbOk("Ok", dlg);
	QTextBrowser *tb = new QTextBrowser(dlg);
	QGridLayout *lo = new QGridLayout(dlg);
	lo->addWidget(tb, 0, 0, 3, 3);
	lo->addWidget(&pbOk, 3, 3, 1, 1);
	tb->setHtml(msg);
	connect(&pbOk, SIGNAL(clicked()), dlg, SLOT(close()));
	dlg->exec();
	
	
}

bool IQFUtils::checkDir(QString s)
{
	RuleBuilder rb;
	rb.setDirection(s);
	return rb.ruleValid();
}
		
bool IQFUtils::checkProto(QString s)
{
	RuleBuilder rb;
	rb.setProtocol(s);
	return rb.ruleValid();
}

		
bool IQFUtils::checkIP(QString ips)
{
	int pos = 0;
	IPValidator ipv(this);
	ipv.setAnyEnabled(true); /* ok "-" and "any" */

	if(ipv.validate(ips, pos) != QValidator::Acceptable)
		return false;
	return true;
}

		
bool IQFUtils::checkGenericIP(QString s)
{
	int pos = 0;
	/* check if we have ip first */
	IPGenericValidator ipv(this);
	
	if(ipv.validate(s, pos) == QValidator::Acceptable) /* true if "-" or an ip */
		return true;
	else
		return false;
}

		
bool IQFUtils::checkPort(QString s)
{
	int pos = 0;
	PortValidator pv(this);
	pv.setAnyEnabled(true); 
	if(pv.validate(s, pos) == QValidator::Acceptable)
		return true;
	return false;
}

		
bool IQFUtils::checkPortOrInterval(QString s)
{
	int pos = 0;
	PortGenericValidator pi(this);
	if(pi.validate(s, pos) == QValidator::Acceptable)
		return true;
	qDebug() << "validazione porta fallita con regexp " << pi.regExp().pattern();
	return false;
	
}

bool IQFUtils::checkDev(QString s)
{
	RuleBuilder rb;
	rb.setInDevname(s);
	return rb.ruleValid();
}

bool IQFUtils::checkMssOption(QString s)
{
  RuleBuilder rb;
  rb.setOptions(s);
  return rb.ruleValid();
}
		
bool IQFUtils::checkNotify(QString s)
{
	return ( s.compare("no", Qt::CaseInsensitive) == 0
			|| s.compare("yes", Qt::CaseInsensitive) == 0);
}

bool IQFUtils:: checkState(QString s)
{
	return ( s.compare("no", Qt::CaseInsensitive) == 0
			|| s.compare("yes", Qt::CaseInsensitive) == 0);
}		

bool IQFUtils::autostartEnabled()
{
	/* .config/autostart is used by gnome ;) */
	QStringList confDirs = QStringList() << ".kde/Autostart" << ".kde4/Autostart" << ".config/autostart";
	for(int i = 0; i < confDirs.size(); i++)
	{
		if(QFile(confDirs[i] + "/iqfire_autostart.desktop").exists()) 
			return true;
	}
	return false;
}

bool IQFUtils::enableAutostart(bool en)
{
	bool ret = false;
	unsigned short installedEntries = 0;
	/* .config/autostart is used by gnome, tried with "Sessions" dialog ;) */
	QStringList confDirs = QStringList() << ".kde/Autostart" << ".kde4/Autostart" << ".config/autostart";
	QString autofilenam = "/usr/share/iqfire/config/iqfire_autostart.desktop";
	QString autodirname, autostartfilenam;
	QFile autofile(autofilenam);
	if(en)
	{
		if(!autofile.exists())
		{
			QMessageBox::critical(0, "iqfirewall", QString("The file \"%1\" for the "
				"automatic startup of iqfirewall does not exist.\n"
				"Check the program installation, or try reinstalling iqfirewall").arg
						(autofilenam));
		}
		else
		{
			/* home/user/.config/autostart directory could not exist if the user
			 * never configured the gnome session to austostart something. So we
			 * create it.
			 */
			QDir configAutostartDir(QDir::homePath() + "/.config/autostart");
			if(!configAutostartDir.exists())
			{
				qDebug() << "I: creating directory " << 
					QDir::homePath() + "/.config/autostart" 
					<< " for gnome desktop compatibility";
				if(configAutostartDir.mkpath(QDir::homePath() + "/.config/autostart"))
					qDebug() << QDir::homePath() + "/.config/autostart" << " created";
				else
					qDebug() << "! error creating" <<
						QDir::homePath() + "/.config/autostart";
			} 
			for(int i = 0; i < confDirs.size(); i++)
			{
				/* copy in .kde/autostart */
				autodirname = QDir::homePath() + QString("/%1/").arg(
						confDirs[i]);
				QFile autoDir(autodirname);
				if(autoDir.exists())
				{
					if(QFile(autodirname + "iqfire_autostart.desktop").exists())
					{
						qDebug() << "File already installed";
						installedEntries++;
						Log::log()->appendOk(QString("Successfully programmed iqfirewall to startup automatically "
						"in the next session (in \"%1\").").
								arg(autodirname + "iqfire_autostart.desktop"));
					}
					else if(autofile.copy(autodirname + "iqfire_autostart.desktop"))
					{
						Log::log()->appendOk("Successfully programmed iqfirewall to startup automatically "
							"in the next session.");
						installedEntries++;
					}
					else
					{
						QMessageBox::critical(0, "iqFirewall error", 
						QString("Error installing "
						"\"%1\" in the autostart folder (\"%2\")\n"
						"(error: %3)").arg(
						autofilenam).arg(autodirname).arg(autofile.error()));
						ret = false; 
					}
				}
				else
					qDebug() << "W: the directory " << autodirname << 
					" for the autostart of iqfirewall does not exist.";
			}
		}
	}
	else /* uninstall */
	{
		for(int i = 0; i < confDirs.size(); i++)
		{
			/* copy in .kde/autostart */
			autostartfilenam = QDir::homePath() + QString("/%1/iqfire_autostart.desktop").arg(
					confDirs[i]);
			QFile autoStartFile(autostartfilenam);
			if(autoStartFile.exists())
			{
				if(autoStartFile.remove())
				{
					qDebug() << 
					"Successfully programmed iqfirewall NOT to startup automatically "
						"in the next session.";
					ret = false; /* not enabled */
				}
				else
				{
					QMessageBox::critical(0, "iqFirewall error", 
						QString("Error uninstalling "
						"\"%1\"").arg(autostartfilenam));
					/* autofile exists, but cannot remove */
					ret = true;
				}
			}
			else
				qDebug() << "The file \"" << autostartfilenam <<
						" is not installed, so not removed";
		}
	}
	return ret;
}

/** @return true if the tcp port is in state of listen */
bool IQFUtils::tcpPortListen(unsigned short port)
{
	int i;
	QList<unsigned short> listenPorts = listenServices("tcp");
	for(i = 0; i < listenPorts.size(); i++)
		if(listenPorts[i] == port)
			return true;
	if(ipv6_enabled)
	{
		listenPorts.clear();
		listenPorts = listenServices("tcp6");
		for(i = 0; i < listenPorts.size(); i++)
			if(listenPorts[i] == port)
				return true;
	}
	return false;
}

/** @return true if the udp port is in state of listen */
bool IQFUtils::udpPortListen(unsigned short port)
{
	int i;
	QList<unsigned short> listenPorts = listenServices("udp");
	for(i = 0; i < listenPorts.size(); i++)
		if(listenPorts[i] == port)
			return true;
	if(ipv6_enabled)
	{
		listenPorts.clear();
		listenPorts = listenServices("udp6");
		for(i = 0; i < listenPorts.size(); i++)
			if(listenPorts[i] == port)
				return true;
	}
	return false;
}


/* Provides the list of services (tcp or udp ports) in the state
 * of LISTEN, as read from the file /proc/net/tcp and /proc/net/udp
 */
QList<unsigned short> IQFUtils::listenServices(QString proto)
{
	QSettings s;
	QList<unsigned short> listenSvcs;
	QString procfilenam = s.value(QString("PROC_NET_%1").arg(proto),
		QString("/proc/net/%1").arg(proto)).toString();
	QStringList list, addr_n_port;
	unsigned short port;
	bool ok;
	int state;
	QString line, local_addr, port_s, state_s;
	
	QFile procfile(procfilenam);
	
	if(!procfile.open(QIODevice::ReadOnly | QIODevice::Text))
	{
		if(proto == "tcp6" || proto == "udp6")
		{
			Log::log()->appendMsg("ipv6 is probably not compiled on your kernel.\n"
				"This is not a problem, since there will not be active services\n"
				"for TCP or UDP v6");
			ipv6_enabled = false;
		}
		else
		{
			Log::log()->appendFailed(QString("Failed to open the proc file \"%1\".\n"
				"Check the settings and verify that the proc file name is correct\n"
				"and that you have the permission to read it.").arg(procfilenam));
		}
	}
	else
	{
		QTextStream in(&procfile);
		QString lineRead = in.readLine();
		/* example of /proc/net/tcp line:
		 * sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt
		 * 0: 00000000:008B 00000000:0000 0A 00000000:00000000 00:00000000 00000000     
		 * uid  timeout inode
		 * 0        0 10456 1 de57d4e0 3000 0 0 2 -1  
		 */
		while(!lineRead.isNull())
		{
			
			line = lineRead.trimmed(); /* remove white spaces at start and end */
			if(!line.contains("st"))
			{
				list = line.split(QRegExp("\\s+"));
				/* sockets in listen state are those which have a st(ate) equal to 0x0A and
				* a port in local_address, in the second part, after the ":"
				*/
				if(list.size() >= 4)
				{
					local_addr = list[1];
					state_s = list [3];
					addr_n_port = local_addr.split(':');
					if(addr_n_port.size() == 2)
					{
						port_s = addr_n_port[1];
						/* test the conversion */
						port = port_s.toInt(&ok, 16);
						if(!ok)
						{
							qDebug() << "Impossible to convert" <<
								port_s << " into a port!";
							return listenSvcs;
						}
						state = state_s.toInt(&ok, 16);
						if(ok)
						{
							if(proto == "tcp" && state == 0x0A)
							{
								listenSvcs.push_back(port_s.toInt(&ok, 16));
							}
							else if(proto == "udp" && state == 0x07)
							{
								listenSvcs.push_back(port_s.toInt(&ok, 16));
							}
						}
						else
							Log::log()->appendFailed(QString("could not convert the "
								"state %1 into an integer!").arg(port_s));
					}
					else
						Log::log()->appendFailed(QString("Strange local_address field "
							"in \"%1\"").arg(procfilenam));
				}
				else
					Log::log()->appendFailed(QString("invalid line "
							"in \"%1\"").arg(procfilenam));
			}
			
			lineRead = in.readLine();
		}
	}
	return listenSvcs;
}



