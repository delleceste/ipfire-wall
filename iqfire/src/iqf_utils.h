#ifndef IQF_UTILS_H
#define IQF_UTILS_H

#include <QStringList>
#include <QObject>

class IQFUtils : public QObject
{
	Q_OBJECT
	public:
	
		static IQFUtils* utils(QObject *parent = NULL);
		QStringList activeNetdevs();

		QString styleSheet(QString filename);
		
		void htmlDialog(QString message);
		
		/* used by the tree widgets */
		bool checkDir(QString s);
		bool checkProto(QString s);
		bool checkIP(QString s);
		bool checkGenericIP(QString s);
		bool checkPort(QString s);
		bool checkPortOrInterval(QString s);
		bool checkDev(QString s);
		bool checkState(QString s);
		bool checkNotify(QString s);
		bool checkMssOption(QString s);
		/** tries to install the autostart file.desktop.
		 * Returns true on success, false otherwise 
		*/
		bool enableAutostart(bool en);
		/** Returns true if it finds an install file iqfire.desktop in the
		 * search directories. 
		 * When it finds a file in one of the dirs, it returns true.
		 */
		bool autostartEnabled();
		
		/** @return true if the port is in a state of LISTEN,
		 *  as stated in /proc/net/udp.
		 * /proc/net/udp stores ports in hexadecimal, but host 
		 * byte order. 
		 @param port: port in host byte order, base 10
		 */
		bool udpPortListen(unsigned short port);
		
		/** @return true if the port is in a state of LISTEN,
		 *  as stated in /proc/net/tcp.
		 * /proc/net/tcp stores ports in hexadecimal, but host 
		 * byte order. 
		 @param port: port in host byte order, base 10
		 */
		bool tcpPortListen(unsigned short port);
		
		~IQFUtils();
		
	signals:
		void resolved(QStringList &rdata);
		void sipResolved(QString& s);
		void dipResolved(QString& s);
		void sportResolved(QString& s);
		void dportResolved(QString& s);
	
	private: /* Singleton: the constructor is private */
		
		IQFUtils(QObject *parent);
		
		static IQFUtils* _instance;
		/* Provides the list of services (tcp or udp ports) in the state
		 * of LISTEN, as read from the file /proc/net/tcp and /proc/net/udp
		 */
		QList<unsigned short> listenServices(QString proto);
		bool ipv6_enabled;
		
};

#endif


