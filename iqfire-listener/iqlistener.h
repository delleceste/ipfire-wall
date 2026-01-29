#include <QtCore>
#include <QThread>
#include <QApplication>
#include <ipfire_structs.h>

class ListenerThread;

/** The Listener listens to the netlink socket to receive 
 * the netlink data information from the kernel.
 */
class Listener : public QObject
{
	Q_OBJECT
	public:
		Listener();
		~Listener();
		
		void enablePortResolution(bool en);
		void applyFilter(QString &filter);
		void disableFilter();
			
	protected slots:
		void threadFinished();
		
	private:
		ListenerThread *thread;
		struct ipfire_servent *svent, *svent_pointer_save;
		struct netl_handle *nh_data;
		struct netlink_stats nlstats;
		
		ipfire_rule_filter *filter;
		
		void startListening();
};

/** Listens to standard input to receive some particular
 * commands which affect the behaviour of the parent 
 */
class ListenerThread : public QThread
{
	public:
		
		ListenerThread(QObject *parent);
		~ListenerThread();
		
		void run();
		
	private:
		Listener *listener_parent;
};



