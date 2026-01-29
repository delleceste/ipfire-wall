#include "iqfstats_proxy.h"
#include "iqfnetlink.h"
#include "iqflog.h"
#include <QtDebug>
#include <QTimer>
#include <QSettings>

IQFStatsProxy *IQFStatsProxy::_instance = NULL;

/* This is another singleton:
 * The first time it creates a stats proxy with the 
 * given parent (essentially to instantiate the timer).
 * Then it returns the instance.
 */
IQFStatsProxy *IQFStatsProxy::statsProxy(QObject *parent)
{
	if(_instance == NULL)
	{
// 		qDebug() << "* stats proxy";
		_instance = new IQFStatsProxy(parent);
	}
	
	return _instance;
}

/* The constructor */
IQFStatsProxy::IQFStatsProxy(QObject *par)
{
	QSettings s; /* refresh time */
	timer = new QTimer(par);
	connect(timer, SIGNAL(timeout()), this, SLOT(refresh()));
	timer_interval = s.value("STATS_TIMER", 20).toUInt() * 1000;
	timer->setSingleShot(false);
	timer->setInterval(timer_interval);
	refresh();
	timer->start();
	/* initialize old_kstats to 0 the first time */
	memset(&old_kstats, 0, sizeof(struct kernel_stats));
	
	
}

/* get the kernel stats and emit the signal when done */
void IQFStatsProxy::refresh()
{
	struct kernel_stats stats;
	command stats_req; /* for asking the statistics */
	unsigned long long total = 0;
	
	double delta_in_acc, delta_out_acc, delta_fwd_acc, delta_in_drop,
  	delta_out_drop, delta_fwd_drop, 
  	delta_in_acc_impl,
  	delta_out_acc_impl, delta_fwd_acc_impl, delta_in_drop_impl,
  	delta_out_drop_impl, delta_fwd_drop_impl;
		
  	double delta_in, delta_out, delta_fwd;
	
 	memset(&stats_req, 0, sizeof(stats_req));
  	stats_req.cmd = KSTATS_REQUEST;
	
  	QVector<double> values;
	Log *iqflog = Log::log();
	IQFNetlinkControl *iqfctrl = IQFNetlinkControl::instance();
  	if(iqfctrl->SendCommand(&stats_req) < 0)
  	{
		iqflog->appendFailed("updateStats(): failed to request the statistics to the kernel!");
  	}	
  	else
  	{
		/* Read the response */
	  	if(iqfctrl->ReadStats(&stats) < 0)
	  	{
			  iqflog->appendFailed("updateStats(): failed to read the statistics from the kernel");
	 	 }
	 	 else
	 	 {
			  total = stats.in_rcv + stats.out_rcv + stats.fwd_rcv +
				  stats.pre_rcv + stats.post_rcv;
				
			  delta_in_acc = stats.in_acc - old_kstats.in_acc;
			  delta_out_acc = stats.out_acc - old_kstats.out_acc;
			  delta_fwd_acc = stats.fwd_acc - old_kstats.fwd_acc;
			  delta_in_drop = stats.in_drop - old_kstats.in_drop;
			  delta_out_drop = stats.out_drop - old_kstats.out_drop;
			  delta_fwd_drop =  stats.fwd_drop - old_kstats.fwd_drop;
			  delta_in_acc_impl = stats.in_acc_impl - old_kstats.in_acc_impl;
			  delta_out_acc_impl= stats.out_acc_impl - old_kstats.out_acc_impl;
			  delta_fwd_acc_impl = stats.fwd_acc_impl - old_kstats.fwd_acc_impl;
			  delta_in_drop_impl = stats.in_drop_impl - old_kstats.in_drop_impl;
			  delta_out_drop_impl = stats.out_drop_impl - old_kstats.out_drop_impl;
			  delta_fwd_drop_impl = stats.fwd_drop_impl - old_kstats.fwd_drop_impl;
			
			  delta_in = stats.in_rcv - old_kstats.in_rcv;
			  delta_out = stats.out_rcv - old_kstats.out_rcv;
			  delta_fwd = stats.fwd_rcv - old_kstats.fwd_rcv;
			
			  /* calculate ratios being careful if we divide by 0 */
			  if(delta_in != 0)
				values << delta_in_acc/delta_in << delta_in_drop/delta_in <<
					  delta_in_drop_impl/delta_in << delta_in_acc_impl / delta_in;
			  else
			 	 values << 0 << 0 << 0 << 0;
			
		  	if(delta_out != 0)
			 	 values << delta_out_acc/delta_out << delta_out_drop/delta_out <<
					  delta_out_drop_impl/delta_out << delta_out_acc_impl / delta_out;
		 	 else
			  	values << 0 << 0 << 0 << 0;
			
		  	if(delta_fwd != 0)
			 	 values << delta_fwd_acc/delta_fwd << delta_fwd_drop/delta_fwd <<
					  delta_fwd_drop_impl/delta_fwd << delta_fwd_acc_impl / delta_fwd;
		 	 else
			  	values << 0 << 0 << 0 << 0;

		  	/* save the current stats into the old_stats, for the next time */
			memcpy(&old_kstats, &stats, sizeof(struct kernel_stats));
			/* mystats will always contain the last read statistics */
			memcpy(&mystats, &stats, sizeof(mystats));
			if(_data.isEmpty()) /* first time */
				_data << 0 << 0 << 0 << 0 << 0 << 0 << 0 << 0 << 0 << 0 << 0 << 0;
			else
				_data = values; /* assign the values vector to the _data */
			emit statsUpdated();
			
	  	} /* else (success in getting stats) */
  	}
}

void IQFStatsProxy::changeTimerInterval(int secs)
{
	timer->stop();
	timer_interval = secs * 1000; /* msec */
	timer->setInterval(timer_interval);
	timer->start();
}

struct kernel_stats IQFStatsProxy::getStats()
{
	struct kernel_stats statistics;
	command stats_req; /* for asking the statistics */
	
 	memset(&stats_req, 0, sizeof(stats_req));
	memset(&statistics, 0, sizeof(statistics));
	
 	stats_req.cmd = KSTATS_REQUEST;
	
	Log *iqflog = Log::log();
	IQFNetlinkControl *iqfctrl = IQFNetlinkControl::instance();
	
	if(iqfctrl->SendCommand(&stats_req) < 0)
	{
		iqflog->appendFailed("updateStats(): failed to request the statistics to the kernel!");
	}	
	else
	{
		/* Read the response */
		if(iqfctrl->ReadStats(&statistics) < 0)
		{
			iqflog->appendFailed("updateStats(): failed to read the statistics from the kernel");
		}
		else
		{
			memcpy(&mystats, &statistics, sizeof(mystats));
		}	
	}
	return statistics;
}

int IQFStatsProxy::getStatsLight(struct kstats_light *statsLight)
{
	command statslight_req;
	Log *iqflog = Log::log();
	memset(statsLight, 0, sizeof(kstats_light));
	
	IQFNetlinkControl *nfcontrol = IQFNetlinkControl::instance();
	
	if(nfcontrol != NULL)
	{
		memset(&statslight_req, 0, sizeof(command));
		statslight_req.cmd = KSTATS_LIGHT_REQUEST;
	
		if(nfcontrol->SendCommand(&statslight_req) < 0)
		{
			iqflog->appendFailed("get_kernel_stats_light():"
					"failed to request the statistics (light) to the kernel!");

			return -1;
		}
		else
		{
			/* Read the response */
			if(nfcontrol->ReadStatsLight(statsLight) < 0)
			{
				iqflog->appendFailed("get_kernel_stats_light(): "
						"failed to read the statistics from the kernel");

				return -1;
			}
		}
	}
	else
		iqflog->appendFailed("get_kernel_stats_light(): IQFNetlinkControl::instance() returned NULL!");
	
	return 0;
}




