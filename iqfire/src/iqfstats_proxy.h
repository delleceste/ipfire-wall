#ifndef IQFSTATS_PROXY_H
#define IQFSTATS_PROXY_H

#include <ipfire_structs.h>
#include <QObject>
#include <QVector>

class QTimer;

// struct kernel_stats
// {
// 	unsigned long long in_rcv;
// 	unsigned long long out_rcv;
// 	unsigned long long pre_rcv;
// 	unsigned long long post_rcv;
// 	unsigned long long fwd_rcv;
// 	unsigned long long sum;
// 	unsigned long long total_lost;
// 	unsigned long long sent_tou;
// 	unsigned long long last_failed;
// 	
// 	/* response-related */
// 	unsigned long long in_acc;
// 	unsigned long long in_drop;
// 	unsigned long long in_drop_impl;
// 	unsigned long long in_acc_impl;
// 	
// 	unsigned long long out_acc;
// 	unsigned long long out_drop;
// 	unsigned long long out_drop_impl;
// 	unsigned long long out_acc_impl;
// 	
// 	unsigned long long fwd_acc;
// 	unsigned long long fwd_drop;
// 	unsigned long long fwd_drop_impl;
// 	unsigned long long fwd_acc_impl;
// 	/* packets not sent because of loglevel */
// 	unsigned long long not_sent;
// 	
// 	/* for packets to be NATTED, we must control checksum:
// 	* if a packet arrives with bad checksum, we don't translate it */
// 	unsigned long long bad_checksum_in;
// 	unsigned long long bad_checksum_out;
// 	
// 	/* Time when module was loaded */
// 	time_t kmod_load_time;
// 	/* Default policy applied when packets do not meet any rule */
// 	short int policy;
// };

class IQFStatsProxy : public QObject
{
	Q_OBJECT
	public:
		enum element { IN, OUT, FWD };
		
		/** This is another singleton:
		 * The first time it creates a stats proxy with the 
		 * given parent (essentially to instantiate the timer).
		 * Then it returns the instance.
		*/
		static IQFStatsProxy *statsProxy(QObject *parent = NULL);
		
		QVector<double> statsData() { return _data; }	
		
		struct kernel_stats getStats();
		int getStatsLight(struct kstats_light *statsLight);
		
		unsigned long long in() { return mystats.in_rcv; }
		unsigned long long out() { return mystats.out_rcv; }
		unsigned long long pre() { return mystats.pre_rcv; }
		unsigned long long post() { return mystats.post_rcv; }
		unsigned long long fwd() { return mystats.fwd_rcv; }
		
		unsigned long long sum() { return mystats.sum; }
		unsigned long long totalLost() { return mystats.total_lost; }
		unsigned long long sentToUser() { return mystats.sent_tou; }
		unsigned long long lastFailed() { return mystats.last_failed;}
			
			/* response-related */
		unsigned long long inAcc() { return mystats.in_acc; }
		unsigned long long inDrop() { return mystats.in_drop;}
		unsigned long long inDropImpl() { return mystats.in_drop_impl;}
		unsigned long long inAccImpl() { return mystats.in_acc_impl;}
			
		unsigned long long outAcc() { return mystats.out_acc;}
		unsigned long long outDrop() { return mystats.out_drop;}
		unsigned long long outDropImpl() { return mystats.out_drop_impl;}
		unsigned long long outAccImpl() { return mystats.out_acc_impl;}
			
		unsigned long long fwdAcc() { return mystats.fwd_acc;}
		unsigned long long fwdDrop(){ return mystats.fwd_drop;}
		unsigned long long fwdDropImpl()  { return mystats.fwd_drop_impl;}
		unsigned long long fwdAccImpl() { return mystats.fwd_acc_impl;}
		/* packets not sent because of loglevel */
		unsigned long long notSent() { return mystats.not_sent;}
			
		/* for packets to be NATTED, we must control checksum:
		 * if a packet arrives with bad checksum, we don't translate it */
		unsigned long long badSumIn() { return mystats.bad_checksum_in;}
		unsigned long long badSumOut() { return mystats.bad_checksum_out;}

		time_t moduleLoadTime() { return mystats.kmod_load_time; }
		
	public slots:
		void changeTimerInterval(int secs);
		
	signals:
		void statsUpdated();
		
	private slots:
		void refresh();
		
	private:
		IQFStatsProxy(QObject *parent);
		
		static IQFStatsProxy *_instance;
		QTimer *timer;
		unsigned int timer_interval; /* in msec */
		
		QVector<double> _data;
		
		/* mystats will always contain the last stats read.
		 * It might be set in refresh(), where it is put equal to old_kstats, or in
		 * getStats().
		 */
		struct kernel_stats old_kstats, mystats;
};


#endif

