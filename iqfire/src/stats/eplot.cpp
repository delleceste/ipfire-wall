#include <QEvent>
#include <QApplication>
#include <QVector>
#include <QMenu>
#include <QAction>
#include <QMouseEvent>
#include <QPrinter>
#include <QPrintDialog>
#include <QPainter>
#include <QDateTime>
#include <QFileDialog>
#include <QDir>
#include <QFile>
#include <QTextStream>
#include <QMessageBox>
#include <QWidget>

#include <QDialog>
#include <QGridLayout>
#include <QLabel>
#include <QSpinBox>
#include <QPushButton>
#include <QMenu>

#include <QtDebug>
#include <qwt_plot_layout.h>
#include <qwt_scale_engine.h>

#include <sys/time.h>
#include <time.h>
#include <vector>
#include <iostream>
#include "eplot.h"


#define MAX_CURVES 64

using namespace std;
class EPlot;

QwtText TimeScaleDraw::label(double v) const
{
        QDateTime d;
        d.setTime_t((int) v );
	return d.toString("d/M\nhh:mm.ss");
}

void Zoomer::rescale()
{
        QwtScaleWidget *scaleWidget = plot()->axisWidget(yAxis());
        QwtScaleDraw *sd = scaleWidget->scaleDraw();
        int minExtent = 0;
        if ( zoomRectIndex() > 0 )
        {
         /* When scrolling in vertical direction
          * the plot is jumping in horizontal direction
          * because of the different widths of the labels
          * So we better use a fixed extent.
          */
         minExtent = sd->spacing() + sd->majTickLength() + 1;
         minExtent += sd->labelSize(scaleWidget->font(), 1000).width();
        }
        sd->setMinimumExtent(minExtent);
        ScrollZoomer::rescale();
}

/* The constructor of the class EPlot */
EPlot::EPlot(QWidget *p, bool show_legend) 
	: QwtPlot(p)
{
	state = RUNNING;
	scrolling = true;
	refresh_enabled = true;
	bufsiz = -1;
	yscalefact = 1;
	xscalefact = 1;
	setFrameStyle(QFrame::NoFrame);
	setLineWidth(0);
	setCanvasLineWidth(2);
//	plotLayout()->setAlignCanvasToScales(true);
	plotLayout()->setCanvasMargin(0, QwtPlot::yLeft);
	plotLayout()->setCanvasMargin(0, QwtPlot::yRight);
	/* Popup menu to set buffer size, print or save data. */
	popupmenu = new QMenu(this);
	view_mode = new QAction("View as lines", this);
	connect(view_mode, SIGNAL(triggered()), this, SLOT(switchViewMode()));
	popupmenu->addAction(view_mode);
	start_pause_act = popupmenu->addAction("Pause Acquisition", this, SLOT(startPauseAcq()));
	popupmenu->addSeparator();
	popupmenu->addAction("Set Buffer Size...", this, SLOT(bufSizeDialog() ) );
	popupmenu->addSeparator();
	popupmenu->addAction("Save Data", this, SLOT(save()));
	popupmenu->addAction("Print", this, SLOT(print()));
	/* the colours of the curve */
 	curve_colors << (Qt::darkBlue) << (Qt::red) << (Qt::gray) 
 		<< (Qt::darkYellow);
// 	curve_colors << EColor(Elettra::pinkPig) << EColor(Elettra::darkGreen) << QColor(Elettra::maroon) 
// 		<< EColor(Elettra::cyan);
// 	curve_colors << EColor(Elettra::darkWater) << EColor(Elettra::violet) << EColor(Elettra::almostBlack)
// 		<< EColor(Elettra::blueGray);
// 	curve_colors << EColor(Elettra::darkPink) << EColor(Elettra::blue) << QColor(Elettra::darkMaroon) 
// 		<< EColor(Elettra::darkCyan);

	manualmode = false;
	xasdate = false;
	xautogen = true;
	left_button_pressed = false;
	mpe = new MousePressEater(this);
	about_to_zoom = false;

	/* white background */
	setCanvasBackground(Qt::white);
	plotgrid = new QwtPlotGrid;
	plotgrid->setPen(QPen(Qt::DotLine));
	plotgrid->attach(this);
	EnableGridX(true);
	EnableGridY(true);
	replot();
	zoomer = new Zoomer(canvas());
	zoomer->setRubberBandPen(QPen(Qt::red, 2, Qt::DotLine));
	zoomer->setTrackerPen(Qt::NoPen);
	zoomer->setTrackerMode(QwtPicker::AlwaysOn);
	
	displayXAxisVectorAsDate(true);
		
	setEnabled(true);
	
	init();
	
	legenda = NULL;
	
	if(show_legend)
	{
		legenda = new QwtLegend();
		insertLegend(legenda, QwtPlot::RightLegend);
		legend_enabled = true;
	}
	else
		legend_enabled = false;

	ydata << QVector<double>();
	setMinimumWidth(0);
	connect(zoomer, SIGNAL(zoomed(const QwtDoubleRect&) ), this, SLOT(EPlotBeenZoomed(const QwtDoubleRect&) ) );

}

/** Inserts data into the plot, accepting a single value.
  *  If a QDateTime is not passed, time values are initialized
  *  to the current date and time.
  */
void  EPlot::insertData(double value, const struct timeval* tv )
{
// 	//qDebug("insertata: %f", value);
	insert_data(value, tv);
}


/** Inserts data into the plot, accepting a vector of values.
  * This function behaves differently depending on the scrolling
  * being enabled or not.
  */
void EPlot::insertData(QVector<double> & v, const struct timeval* tv )
{
	insert_data(v, tv);
}

/** This one is like the above function, but accepts a standard vector
 * instead of a QVector. It is provided for convenience.
 */
void EPlot::insertData(std::vector<double> &v, const struct timeval * tv)
{
	QVector<double> qvect = QVector<double>::fromStdVector(v);
	insert_data(qvect, tv);
}

/* PRIVATE FUNCTIONS */

void EPlot::init()
{
	if (scrolling)
	{
		setAxisScaleDraw(QwtPlot::xBottom, new TimeScaleDraw());
		setAxisLabelRotation(QwtPlot::xBottom, -50.0);
	}
	else
	{
		setAxisScaleDraw(QwtPlot::xBottom, new QwtScaleDraw());
		setAxisLabelRotation(QwtPlot::xBottom, 0.0);
	}
	setAxisLabelAlignment(QwtPlot::xBottom, Qt::AlignLeft | Qt::AlignBottom);
}


void EPlot::enableManualMode(bool en)
{
	manualmode = en;
	mpe->setManual(en);
	if(en)
	{
		canvas()->installEventFilter(mpe);
		setCursor(Qt::ArrowCursor);
	}
	else
	{
		canvas()->removeEventFilter(mpe);
		setCursor(Qt::CrossCursor);
	}
}

void EPlot::setXAxisVector(std::vector<double> v)
{
	unsigned int i;
	/* Prepare xdatamanual, which will be used in the 
	 * insert_data.
	 */
	xdatamanual.clear();
	for(i = 0; i < v.size(); i++)
		xdatamanual.push_back(v[i]);
	/* Setup the scale for xBottom axis */
	if(xdatamanual.size() > 0)
		setEPlotAxisScale(QwtPlot::xBottom, xdatamanual[0], 
				xdatamanual[xdatamanual.size() - 1]);
}
 
/* Slot to change x axis */
void EPlot::changeXAxisScale(double x1, double x2)
{
	double start, end;
	qApp->processEvents();
	start = axisScaleDiv(QwtPlot::xBottom)->lBound();
	end = axisScaleDiv(QwtPlot::xBottom)->hBound();
	if(x1 != start || x2 != end)
	{
		setEPlotAxisScale(QwtPlot::xBottom, x1, x2); /* calls emit() */
	}
}

/* Slot that propagates the zoomed() signal emitted by the zoomer */
void EPlot::EPlotBeenZoomed(const QwtDoubleRect &r)
{
	qApp->processEvents();
	emit EPlotZoomed(r, axisScaleDiv(QwtPlot::xBottom)->lBound(), axisScaleDiv(QwtPlot::xBottom)->hBound());
}

/* Slot to change y axis scale */
void EPlot::changeYAxisScale(double y1, double y2)
{
	setAxisScale(QwtPlot::yLeft, y1, y2);
	emit yAxisScaleChanged(y1, y2);
}

void EPlot::setXAxisVectorAutoGeneration(bool autog)
{
	xautogen = autog;
}

void EPlot::displayXAxisVectorAsDate(bool x_as_date)
{
	xasdate = x_as_date;
	if(xasdate)
	{
		setAxisScaleDraw(QwtPlot::xBottom, new TimeScaleDraw());
		setAxisLabelRotation(QwtPlot::xBottom, -50.0);
	}
	else
	{
		setAxisScaleDraw(QwtPlot::xBottom, new QwtScaleDraw());
		setAxisLabelRotation(QwtPlot::xBottom, 0.0);
	}
	setAxisLabelAlignment(QwtPlot::xBottom, Qt::AlignLeft | Qt::AlignBottom);
}

bool MousePressEater::eventFilter(QObject *o, QEvent *e)
{
	if( ( e->type() == QEvent::MouseButtonPress || e->type() == QEvent::MouseButtonRelease) && manualmode )
	{
		QMouseEvent* mev = (QMouseEvent *)e;
		if(mev->button() == Qt::LeftButton || mev->button() == Qt::MidButton)
			return true;
	}
	return QObject::eventFilter(o, e);

}

void EPlot::insert_data(double newdata, const struct timeval* tv)
{
	struct timeval tval;
	/* Avoid updating the plot when scrolling is enabled and the state is PAUSED.
         * The lack of this check causes the zoom to behave badly: while we are zooming
         * the plot is updated and the paused screenshot changes!
         * This issue doesn't appear when scrolling is enabled because the data is stored
         * continuously inside the plot.
         */
        if(!scrolling && state == EPlot::PAUSED)
                return;

	/* check if curves data are empty and eventually reattach them */
	if (curve.size() == 0)
	{
		QwtPlotCurve *c = new QwtPlotCurve(QString("%1").arg(curve.size() ) );
		QPen p(curve_colors[0]);
		p.setWidth(2);
		c->setPen(p);
		c->attach(this);
		curve << c;
	}

	ydata[0].push_back(newdata * yscalefact);
	
	if(tv == NULL)
		gettimeofday(&tval, NULL);
	else
		memcpy(&tval, tv, sizeof(struct timeval) );
	xdata.push_back( (double) (tval.tv_sec + tval.tv_usec * 0.000001) );

	while ((bufsiz != -1) && ((xdata.last() - xdata.front() ) > bufsiz) )
	{
		ydata[0].pop_front();
		xdata.pop_front();
	}
		
	curve[0]->setRawData(&xdata[0], &(ydata[0])[0], xdata.size());
	if (refresh_enabled)
		QApplication::postEvent(this, new QEvent(QEvent::User));
}

/* Inserts data into the plot, accepting a vector of values.
 * This function behaves differently depending on the scrolling
 * being enabled or not.
 */
void EPlot::insert_data(QVector<double> &newDataVector, const struct timeval* tv)
{
	int s, i, xdatasiz = 0;
	struct timeval tval;
	
	/* See the comment in the function above */
        if(!scrolling && state == EPlot::PAUSED)
                return;
	
	/* check if curves data are empty and eventually reattach them */
/*	if (curve.size() == 0)
	{
		QwtPlotCurve *c = new QwtPlotCurve("Plot.");
		c->setPen(QPen(curve_colors[0]));
		c->attach(this);
		curve << c;
	}
*/	
	s = MAX_CURVES;
	if (newDataVector.size() < MAX_CURVES)
		s = newDataVector.size();
	
	/* Apply y offset to the y data if required and the y offset vector is setup
	 * correctly.
	 */
	if(yoffset.size() != 0 && newDataVector.size() != yoffset.size() )
		qDebug() << "The yOffset vector(long " << yoffset.size() <<
			") must be as long as the y data vector (long " << newDataVector.size() << 
			")! The offset won't be applied!";
	else if(yoffset.size() == newDataVector.size() )
	{
		for(i = 0; i < newDataVector.size(); i++)
			newDataVector[i] += yoffset[i];
	}

	if (scrolling)
	{
		while (ydata.size() < s)
			ydata.push_back(QVector<double>());
		
		for (i = 0; i < ydata.size(); i++)
			ydata[i].push_back(newDataVector[i] * yscalefact);
		
		if(tv == NULL)
			gettimeofday(&tval, NULL);
		else
			memcpy(&tval, tv, sizeof(struct timeval) );
	
		xdata.push_back( (double) (tval.tv_sec + tval.tv_usec * 0.000001) );

		while ((bufsiz != -1) && (xdata.size() > bufsiz))
		{
			for (i = 0; i < ydata.size(); i++)
				ydata[i].pop_front();
			xdata.pop_front();
		}
	}
	else
	{
		if(yscalefact != 1)
		{
			QVector<double> datacopy;
			datacopy.resize(newDataVector.size() );
			for(i = 0; i < datacopy.size(); i++)
				datacopy[i] = newDataVector[i] * yscalefact;
			ydata[0] = datacopy;
		}
		else
			ydata[0] = newDataVector;

		if(xautogen || xdata.size() != ydata[0].size() )
		{
			xdata.clear();
			for (i = 0; i < ydata[0].size(); i++)
				xdata.push_back(i * xscalefact);
			
			if(!xautogen && xdata.size() != ydata[0].size() )
			{
				qDebug() << "X axis auto generation is disabled but the lenght of " ;
				qDebug() <<  " the x vector provided [" << xdata.size() << "] is different ";
				qDebug() <<  " from the y vector length [" << ydata[0].size() << "]";
				qDebug() << "If you call setXAxisVectorAutoGeneration() to false, you have";
				qDebug() << "to call setAxisVector() explicitly at least once to provide the x axis elements.";
			}
		}
		else
		{
			/* Leave xdata untouched: it should have been set manually. */
		}
	}
	
	while (curve.size() < ydata.size())
	{
		QwtPlotCurve *c = new QwtPlotCurve(QString("%1").arg(curve.size() ) );
		QPen p(curve_colors[curve.size() % curve_colors.size()]);
		p.setWidth(1.5);
		c->setPen(p);
		c->attach(this);
		curve.push_back(c);
	}

	
	for (i = 0; i < curve.size(); i++)
	{
		xdatasiz = ydata[i].size(); /* initialize xdatasiz to this, then we will correct it if
					     * xdatamanual.size() != ydata[i].size()
					     */
		if(!xautogen && (xdatamanual.size() != ydata[i].size() ) )
		{
			/* The number of elements to plot has to be the 
			 * minimum between the x and y vectors size
			 */
			qDebug() << "WARNING: the size of the x vector (" << xdatamanual.size()  <<
				") is not equal to the size of the y vector (" << 
				ydata[i].size() << ") at the " <<
				i + 1 << " position.";
			qDebug() << "The plot will not appear with all the elements expected";
			if(xdatamanual.size() >= ydata[i].size() )
				xdatasiz = ydata[i].size();
			else
				xdatasiz = xdatamanual.size();
			/* Finally, resize xdatamanual, so that the display() will receive
			 * consistent data.
			 */
			xdatamanual.resize(xdatasiz);
		}
		if(!xautogen && !scrolling) /* x manual is allowed only without scrolling enabled */
			curve[i]->setRawData(&xdatamanual[0], &(ydata[i])[0], xdatasiz);
		else
			curve[i]->setRawData(&xdata[0], &(ydata[i])[0], xdata.size());
	}
	if (refresh_enabled)
		QApplication::postEvent(this, new QEvent(QEvent::User));
}					
	
void EPlot::display()
{
	QwtDoubleRect r;
	double offset;
	int i;
	QVector <double> x_data;
	x_data.clear();

	/* x_data will contain the right vector, depending on
	 * scrolling and autogen enabled or not.
	 */
	if(!scrolling && !xautogen)
	{
		for(i = 0; i < xdatamanual.size(); i++)
			x_data.push_back(xdatamanual[i] );
		if(xasdate)
		{
			
		}
	}
	else
	{
		for(i = 0; i < xdata.size(); i++)
			x_data.push_back(xdata[i]);
	}

	if (!x_data.size())
		return;

	
	if (state == EPlot::RUNNING /*&& !manualmode*/)
	{
		if (! zoomer->zoomRectIndex()) /* we are not inside the zoom */
		{
	//		qDebug() << "! zoomer->zoomRectIndex()";
			/* Adjust the scale just when needed */
			if(!scrolling && !manualmode && ScaleChanged( x_data[x_data.size() - 1] -  x_data[0]  ) )
				setEPlotAxisScale(QwtPlot::xBottom, x_data[0], x_data[x_data.size() - 1]);
			else if(axisScaleDiv(QwtPlot::xBottom)->lBound() != x_data[0] 
				|| axisScaleDiv(QwtPlot::xBottom)->hBound() != x_data[x_data.size() - 1] )
			{
//				qDebug() << "Aggiorno la scala perche` risulta diversa";
				QwtPlot::setAxisScale(QwtPlot::xBottom, x_data[0], x_data[x_data.size() - 1]);
 				emit xAxisScaleChanged(x_data[0], x_data[x_data.size() - 1]);
			}
//			else
//				qDebug() << "Non aggiorno la scala perche` non serve!";
			/* Disable explicit setAxisAutoScale 
			 * in manualmodei: see enableManualMode() 
			 * comment in eplot.h. 
			 */
			if(!manualmode) 
				setAxisAutoScale(QwtPlot::yLeft);
			replot();

		}
		else if (scrolling) /* zoom with scrolling enabled */
		{
	//		qDebug() << "scrolling";
			r = zoomer->zoomBase();
			offset = x_data[x_data.size()-1] - x_data[x_data.size()-2];
			if ((bufsiz != -1) || ((x_data.last()-x_data.front()) < bufsiz))
				r.setRight(r.right()+offset);
			else
				r.moveRight(r.right()+offset);
			
			zoomer->setZoomBase(r);
			zoomer->moveBy(offset, 0);
			replot();
		}
		else /* zoom with scrolling disabled */
		{
	//		qDebug() << "else";
			/* Modifica del 19 aprile: questa istruzione causa l'autoscale della Y anche nello zoom,
        		 * annullando l'effetto dello zoom sull'asse stesso
	         	*/
	//		if(!manualmode) 
	//			setAxisAutoScale(QwtPlot::yLeft);

			replot();	
		}
			
	}
	canvas()->setMouseTracking(true);
	setMouseTracking(true);
	zoomer->setTrackerMode(QwtPicker::AlwaysOn);
	zoomer->setTrackerPen(QColor(Qt::black));
}

bool EPlot::ScaleChanged(double xinterval)
{
	QwtDoubleRect zrect = zoomer->zoomBase();
	double x1, x2;
	x1 = zrect.left();
	x2 = zrect.right();
//	if(xinterval != x2 - x1)
//		qDebug() << "effettivamente la scala e` cambiata: x1: " << x1 << ", x2: " << x2 <<
//			", xinterval: " << xinterval;
	return xinterval != x2 - x1;
	
}

void  EPlot::setEPlotAxisScale(int id, double start, double end)
{
	QwtDoubleRect zrect = zoomer->zoomBase();
	QwtDoubleRect newrect;
//	QwtPlot::setAxisScale(id, start, end);
	if(id == QwtPlot::xBottom) /* x axis */
		newrect.setRect(start, zrect.top(), end - start, zrect.bottom() - zrect.top() );
	else if(id == QwtPlot::yLeft)
		newrect.setRect(zrect.left(), start, zrect.right() - zrect.left(), end - start);
	zoomer->setZoomBase(newrect);
	zoomer->zoom(0);
	QwtPlot::setAxisScale(id, start, end);
	/* signal that scales have changed */
	if(id == QwtPlot::yLeft)
		emit yAxisScaleChanged(start, end);
	else
		emit xAxisScaleChanged(start, end);
}

bool EPlot::event(QEvent *e)
{
	if (e->type() == QEvent::User)
	{
		display();
		return true;
	}
// 	else if(e->type() == QEvent::MouseMove)
// 	{
// 		QMouseEvent* ev = (QMouseEvent *) e;
// 		QString info;
// 		info.sprintf("Freq=%g, Ampl=%g",
// 			     invTransform(QwtPlot::xBottom, ev->pos().x()),
// 					  invTransform(QwtPlot::yLeft, ev->pos().y())
// 			    );
// 		qDebug() << info;
// 		setStatusTip(info);
// 	}
	else
		return QwtPlot::event(e);
}

void EPlot::refresh()
{
	QApplication::postEvent(this, new QEvent(QEvent::User));
}

void EPlot::mouseMoveEvent(QMouseEvent *e)
{
	Q_UNUSED(e);
}

void EPlot::mousePressEvent(QMouseEvent *ev)
{
	/* Pause refreshing if state is running and put the
	 * state to CLICK_PAUSE, so that at mouse release
	 * we can restore the state to RUNNING
	 */
	if(ev->button() == Qt::LeftButton && !manualmode)
	{
		QRect r;
		if (state == EPlot::RUNNING)
			state = EPlot::CLICK_PAUSE;
		about_to_zoom = false;
		left_button_pressed = true;
		/* zoomer->setZoomBase() is now called inside the mouse move event.
		 */
		if (! zoomer->zoomRectIndex())
			zoomer->setZoomBase( );

	}
	else if (ev->button() == Qt::RightButton)
		popupmenu->popup(ev->globalPos());
	
//		QwtPlotPicker::mousePressEvent(ev);
}


void EPlot::mouseReleaseEvent(QMouseEvent *ev)
{
	if(ev->button() == Qt::LeftButton)
	{
		if(state == EPlot::CLICK_PAUSE)
			state = EPlot::RUNNING;

	}
}

void EPlot::startPauseAcq()
{
	if (state == EPlot::PAUSED)
	{
		state = EPlot::RUNNING;
		start_pause_act->setText("Pause Acquisition");
	}

	else if (state == EPlot::RUNNING)
	{
		state = EPlot::PAUSED;
		start_pause_act->setText("Resume Acquisition");
	}
}


void EPlot::save()
{
	int size, i, j;
	QDateTime d;
	QString s = QFileDialog::getSaveFileName(this, "Choose a filename to save under", QDir::homePath(), "Text file (*.txt)");
	if (!s.isEmpty())
	{
		QFile f(s);
		if (!f.open(QIODevice::WriteOnly | QIODevice::Text))
		{
			QMessageBox::warning(this, "Error", "Can't create file", QMessageBox::Ok, 0, 0); 
			return;
		}
		QTextStream out(&f);
		out << fixed;
		out.setRealNumberPrecision(10);
		out << QDateTime::currentDateTime().toString() << '\n';
		size = xdata.size();
		for (i = 0; i < size; i++)
		{
			d.setTime_t((int)xdata[i]);
			out << d.toString() << '\t' << xdata[i] << '\t';
			for (j = 0; j < ydata.size(); j++)
				out << ydata[j][i] << '\t';
			out << '\n';
		}
		f.close();
	}		
}

void EPlot::print()
{
/*	QPrinter printer;

	QPrintDialog *dialog = new QPrintDialog(&printer, this);
	dialog->setWindowTitle(tr("Print Document"));
	if (dialog->exec() != QDialog::Accepted)
		return;

	QPainter painter(&printer);
	painter.drawText(20, 20, QDateTime::currentDateTime().toString());
	QwtPlot::print(&painter, QRect(20, 40, printer.pageRect().width()-40, (int)(printer.pageRect().height()*.3)));*/

	QPrinter printer;
	//printer.setOutputFileName("/tmp/ciccio.ps");
	QString docName = title().text();
	if ( docName.isEmpty() )
	{
		docName.replace (QRegExp (QString::fromLatin1 ("\n")), tr (" -- "));
		printer.setDocName (docName);
	}
	printer.setCreator("QTango");
	QPrintDialog dialog(&printer);
	if ( dialog.exec() )
	{
		QwtPlotPrintFilter filter;
		if ( printer.colorMode() == QPrinter::GrayScale )
		{
// 			filter.setOptions(QwtPlotPrintFilter::PrintAll & ~QwtPlotPrintFilter::PrintCanvasBackground);
		}
		QwtPlot::print(printer, filter);
	}
}

void EPlot::bufSizeDialog()
{
	QDialog *dlg = new QDialog(this);
	dlg->setWindowTitle("Buffer Size");
	
	QLabel *l = new QLabel("Buffer Size [s]:", dlg);
	QSpinBox *s = new QSpinBox(dlg);
	s->setToolTip("-1 means no size limit");
	s->setMinimum(-1);
	s->setMaximum(60*60*24);
	s->setValue(bufSize());
	
	QPushButton *close = new QPushButton("OK", dlg);
	QPushButton *cancel = new QPushButton("Cancel", dlg);
	connect(close, SIGNAL(clicked()), dlg, SLOT(accept()));
	connect(cancel, SIGNAL(clicked()), dlg, SLOT(reject()));

	QGridLayout *grid = new QGridLayout(dlg);
	grid->addWidget(l, 0, 0);
	grid->addWidget(s, 0, 1);
	grid->addWidget(close, 1, 0);
	grid->addWidget(cancel, 1, 1);
	
	if (dlg->exec() == QDialog::Accepted)
		setBufSize(s->value());

	delete dlg;
}

void EPlot::switchViewMode()
{
	QVector<QwtPlotCurve*> curves = GetCurves();
	int i;
	for(i = 0; i < curves.size(); i++)
	{
		if(curves[i]->style() == QwtPlotCurve::Steps)
			curves[i]->setStyle(QwtPlotCurve::QwtPlotCurve::Lines);
		else 
			curves[i]->setStyle(QwtPlotCurve::Steps);
	}
	if(curves.size() > 0)
	{
		if(curves[0]->style() == QwtPlotCurve::Steps)
			view_mode->setText("View as lines");
		else
			view_mode->setText("View as steps");
	}
	refresh();
}



