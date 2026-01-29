#include "iqfstats.h"
#include "iqfnetlink.h"
#include "iqfwidgets.h"
#include "iqflog.h"
#include "colors.h"
#include "iqfstats_proxy.h"

#include <ipfire_structs.h>

#include <QSettings>
#include <QGridLayout>
#include <QTimer>
#include <QLabel>
#include <QVector>
#include <QDateTime>
#include <qwt_legend_item.h>
#include "stats/kernel_stats_plot.h"
#include "stats/eplotcurve.h"

IQFStats::IQFStats(QWidget *parent, QWidget *legend_widget) : QWidget(parent)
{
	QSettings s;
	int i;
	double now = (double) QDateTime::currentDateTime().toTime_t();
	/*  to setup the xBottom scale, calculate as x higher bound the current time + the refresh interval length */
	double then = (double) QDateTime::currentDateTime().addSecs(s.value("STATS_TIMER", 20).toInt()).toTime_t();
	EPlotCurve *crv0, *crv1, *crv2, *crv3, *crv4, *crv5, *crv6, *crv7, *crv8, *crv9, *crv10, *crv11;
	
	QGridLayout *lo = new QGridLayout(parent);
	
	plot = new KernelStatsPlot(this);
	lo->addWidget(plot, 0, 0, 6, 6);

	iqflog = Log::log();

	/* setup axes
	 */
	QFont font("", 10);
	font.setBold(true);
	QwtText yLabel( "% over total packets processed");
	yLabel.setFont(font);
	plot->setAxisTitle(QwtPlot::yLeft, yLabel);
	QFont axisFont("", 8);
	plot->setAxisFont(QwtPlot::xBottom, axisFont);
	plot->setAxisScale(QwtPlot::yLeft, 0, 100);
	plot->setTimeScaleDrawEnabled(true);
	/* setting initial axis scale disables autoscale. The zoomer will not 
	 * autoscale on non-zoomed replots but will adjust x scale to the 
	 * effective lower and higher bounds.
	 */
	plot->setAxisScale(QwtPlot::xBottom, now, then);
  
	/* create the curves, each one with its title and color */
	QPen p;
	crv0 = new EPlotCurve(this, "IN allowed over\ntotal IN");
	plot->addCurve("crv0", crv0);
	/* input */
	p.setStyle(Qt::DashLine);
	p.setColor(KGREEN);
	p.setWidth(1);
	crv0->setPen(p);
	
	p.setColor(KRED);
	crv1 = new EPlotCurve(this, "IN blocked over\ntotal IN");
	plot->addCurve("crv1", crv1);
	crv1->setPen(p);
	crv1->setVisible(true);
	
	p.setColor(KMAGENTA);
	crv2 = new EPlotCurve(this, "IN implicitly blocked\nover total IN");
	crv2->setPen(p);
	plot->addCurve("crv2", crv2);
	
	p.setColor(KDARKGREEN);
	crv3 = new EPlotCurve(this, "IN implicitly allowed\nover total IN");
	crv3->setPen(p);
	plot->addCurve("crv3", crv3);

	p.setStyle(Qt::SolidLine);
	p.setColor(KGREEN);
	crv4 = new EPlotCurve(this, "OUT allowed over\ntotal OUT");
	crv4->setPen(p);
	plot->addCurve("crv4", crv4);

	p.setColor(KRED);
	crv5 = new EPlotCurve(this, "OUT blocked over\ntotal OUT");
	crv5->setPen(p);
	plot->addCurve("crv5", crv5);
	crv5->setVisible(true);
	
	p.setColor(KMAGENTA);
	crv6 = new EPlotCurve(this, "OUT implicitly blocked\nover total OUT");
	crv6->setPen(p);
	plot->addCurve("crv6", crv6);

	p.setColor(KDARKGREEN);
	crv7 = new EPlotCurve(this, "OUT implicitly allowed\nover total OUT");
	crv7->setPen(p);
	plot->addCurve("crv7", crv7);
	
	p.setStyle(Qt::DashDotLine);
	p.setColor(KGREEN);
	crv8 = new EPlotCurve(this, "FWD allowed over\ntotal FWD");
	crv8->setPen(p);
	plot->addCurve("crv8", crv8);

	p.setColor(KRED);
	crv9 = new EPlotCurve(this, "FWD blocked over\ntotal FWD");
	crv9->setPen(p);
	plot->addCurve("crv9", crv9);

	p.setColor(KMAGENTA);
	crv10 = new EPlotCurve(this, "FWD implicitly blocked over\ntotal FWD");
	crv10->setPen(p);
	plot->addCurve("crv10", crv10);
	
	p.setColor(KDARKGREEN);
	crv11 = new EPlotCurve(this, "FWD implicitly allowed over\ntotal FWD");
	crv11->setPen(p);
	plot->addCurve("crv11", crv11);
		

	if(legend_widget)	
	{
		buildLegend(legend_widget);
	}
	else
	{
		plot->enableAxis(QwtPlot::xBottom, false);
		plot->enableAxis(QwtPlot::yLeft, false);
	}

	QList<QwtPlotCurve*> curves = plot->curves();
	for(i = 0; i < curves.size(); i++)
	{
		curves[i]->setStyle(QwtPlotCurve::Steps);
		if(i == 1 /* in blocked */ || i == 5 /* out blocked */)
			curves[i]->setVisible(true);
		else
			curves[i]->setVisible(false);
	}
	
}

IQFStats::~IQFStats()
{
}

void IQFStats::showStatsIn()
{
	showCurve(1);
	plot->replot();
}
		
void IQFStats::showStatsOut()
{
	showCurve(5);
	plot->replot();
}
		
void IQFStats::showStatsFwd()
{
	showCurve(9);
	plot->replot();
}

void IQFStats::hideAllCurves()
{
	int i;
	QList<QwtPlotCurve*> curves = plot->curves();
	for(i = 0; i < curves.size(); i++)
		curves[i]->setVisible(false);
}

void IQFStats::showCurve(int index)
{
	int i;
	QList<QwtPlotCurve*> curves = plot->curves();
	for(i = 0; i < curves.size(); i++)
	{
		if(i == index)
		{
			curves[i]->setVisible(true);
// 			qDebug() << "abilito curva " << i;
		}
		else
		{
			curves[i]->setVisible(false);
// 			qDebug() << "disabilito curva " << i;
		}
	}
}

void IQFStats::buildLegend(QWidget *legend_w)
{
	if(legend_w == NULL)
		return;
	int i;
	QLabel *label = new QLabel(legend_w);
	label->setText("View/hide:");
	label->setToolTip("Press down a button to show a curve.\nPress again to hide it\n"
		"Click on \"?\" and/or \"i\" on the \n\"sidebar contents\" toolbar to get more\n"
		"help or information...");
	QList<QwtPlotCurve*> curves = plot->curves();
	QHBoxLayout *lo = new QHBoxLayout(legend_w);
 	legend_w->setSizePolicy(QSizePolicy(QSizePolicy::Preferred, QSizePolicy::Fixed));
// 	legend_w->setMaximumWidth(40);
	//QLabel *label = new QLabel(legend_w);
	//label->setText("Enabled\ncurves:");
	//lo->addWidget(label);
	lo->addWidget(label);
	for(i = 0; i < curves.size(); i++)
	{
		IQFLegendItem *it = new IQFLegendItem(legend_w, curves[i]);
		it->setItemMode(QwtLegend::CheckableItem);
		it->setToolTip(curves[i]->title().text());
		it->setInfo(curves[i]->title().text().remove(" ").remove("/").remove(".").remove('\n'));
		it->setHelp(curves[i]->title().text().remove(" ").remove("/").remove(".").remove('\n')
			.remove('\n'));
		it->setCurvePen(curves[i]->pen());
		it->setSizePolicy(QSizePolicy(QSizePolicy::Preferred, QSizePolicy::Fixed)); 
		it->setMaximumWidth(85);
		it->setMaximumHeight(20);
		lo->addWidget(it);
		connect(it, SIGNAL(checked(bool)), this, SLOT(showCurve(bool)));
		if(i == 1 /* in blocked */ || i == 5 /* out blocked */)
		{
			it->setChecked(true);
		}
		else
			it->setChecked(false);
	}
	
	if(curves.size() < 12)
		qDebug() << "The curves are not 12: cannot build legend correctly";
	
}

bool IQFStats::curveVisible(int index)
{
	QList<QwtPlotCurve*> curves = plot->curves();
	if(index < curves.size())
		return curves[index]->isVisible();
	else
		return false;

	
}

void IQFStats::showCurve(bool visible)
{
	QwtPlotCurve *item = ((IQFLegendItem *)sender())->associatedCurve();
	item->setVisible(visible);
	plot->replot();
}

void IQFStats::updateStats()
{
	int n = 0;
	time_t tt_now;
	QDateTime now = QDateTime::currentDateTime();
	tt_now = now.toTime_t();
	QList<QwtPlotCurve*> curves = plot->curves();
	IQFStatsProxy *statspro = IQFStatsProxy::statsProxy();
	QVector<double> data = statspro->statsData();
	if(data.size() == 12 && curves.size() == 12)
	{
	  while(n < 12)
	  {
	    QString crvName = QString("crv%1").arg(n);
	    plot->appendData(crvName, tt_now, data[n] * 100);
	    n++;
	  }
	}
	plot->refresh();
}

void IQFStats::showEvent(QShowEvent *e)
{
	updateStats();
	QWidget::showEvent(e);
}


