#include "eplotlight_base.h"
#include "ezoomer.h"
#include "eplotcurve.h"

#include <macros.h>
#include <colors.h>
#include <qwt_plot_grid.h>
#include <qwt_legend.h>
#include <qwt_legend_item.h>
#include <sys/time.h>
#include <QDateTime>
#include <QtDebug>

QwtText ETimeScaleDraw::label(double v) const
{
  QDateTime d;
  d.setTime_t((int) v );
  return d.toString("dd:/MM\nhh:mm.ss");
}

EPlotLightBase::EPlotLightBase(QWidget *parent) : QwtPlot(parent)
{
 init();
}

EPlotLightBase::EPlotLightBase(const QwtText &title, QWidget *parent) : QwtPlot(title, parent)
{
  init();
}

/* QwtPlot xAxis autoscale is disabled and axis autoscale is managed internally 
 * through the refresh() method.
 */
void EPlotLightBase::init()
{
  d_timeScaleDraw = NULL;
  d_curvesStyle = QwtPlotCurve::Lines;
  setFrameStyle(QFrame::NoFrame);
  plotLayout()->setAlignCanvasToScales(true);
  plotLayout()->setCanvasMargin(0, QwtPlot::yLeft);
  plotLayout()->setCanvasMargin(0, QwtPlot::yRight);
  /* white background */
  setCanvasBackground(Qt::white);
  /* grid */
  QwtPlotGrid* plotgrid = new QwtPlotGrid;
  plotgrid->setPen(QPen(Qt::DotLine));
  plotgrid->attach(this);
  plotgrid->enableX(true);
  plotgrid->enableY(true);
  
  setAxisLabelAlignment(QwtPlot::xBottom, Qt::AlignLeft | Qt::AlignBottom);

  zoomer = new Zoomer(canvas());
  zoomer->setRubberBandPen(QPen(KDARKGRAY, 1, Qt::DotLine));
  zoomer->setTrackerPen(QPen(KGRAY));
  d_scheduleAdjustScales = false;

  /* axis autoscaling */
  setAxisAutoScale(QwtPlot::yLeft);
  /* NOTE: disable QwtPlot x axis autoscale */
  d_xAutoscale = true; /* enabled by default */
  d_yAutoscale = true;
  setAxisScale(QwtPlot::xBottom, 0, 1000);
  
  d_xAutoscaleAdjustment = d_yAutoscaleAdjustment = 2.0;
  d_xAutoscaleAdjustEnabled = d_yAutoscaleAdjustEnabled = true;
  
  QwtPlot::replot(); /* do not need EPlotLightBase::replot() here */
  
//   connect(zoomer, SIGNAL(zoomed(const QwtDoubleRect &)), this, SLOT(plotZoomed(const QwtDoubleRect &)));
}

bool EPlotLightBase::timeScaleDrawEnabled()
{
   if(zoomer)
      return zoomer->xAsDate();
   return false;
}

void EPlotLightBase::setTimeScaleDrawEnabled(bool enable)
{
  /* if xAutoscale is enabled, scales are automatically adjusted at first refresh */
  if(!enable) 
  {
  	setAxisScaleDraw(QwtPlot::xBottom, new QwtScaleDraw());
	/* next time replot() is invoked, adjust scales */
// 	d_scheduleAdjustScales = true;
  }
  else
  {
    d_timeScaleDraw = new ETimeScaleDraw();
    d_timeScaleDraw->setLabelAlignment(Qt::AlignLeft | Qt::AlignVCenter);
    setAxisScaleDraw(QwtPlot::xBottom, d_timeScaleDraw);
    setAxisLabelRotation(QwtPlot::xBottom, -50.0);
  }
  /* deleting d_timeScaleDraw produces a crash */
  replot();
  zoomer->setXAsDate(enable);
}

void EPlotLightBase::refresh()
{
  int size, offset, bufsiz = -1;
  double x1 = 0.0, x2 = 0.0, xstart = 0.0;
  EPlotCurve *epc = NULL;
  
  /* user might call replot after adding curves but before setting data on them:
   * it is not possible  to adjust scales if the curves haven't data yet.
   */
  if(d_scheduleAdjustScales && adjustScales())
    d_scheduleAdjustScales = false;

  foreach(QwtPlotItem* i, itemList())
  {
    if(dynamic_cast<QwtPlotCurve* >(i))
    {
      QwtPlotCurve *c = dynamic_cast<QwtPlotCurve* >(i);
      epc = dynamic_cast<EPlotCurve *>(i);
      /* need to calculate x start and x1 when not in vectorUpdateMode (to scroll the zoom)
       * or when in optimizeXAutoscale mode (to rescale the plot)
       */
      if((epc && !epc->vectorUpdateMode()) || d_xAutoscale)
      {
	size = c->dataSize();
	if(size > 2)
	{
	  x1 = c->x(size - 1);
	  x2 = c->x(size - 2);
	  xstart = c->x(0);
	}
	else
	  return;
      }
      break;
    }
  }
  
  if(!zoomer->zoomRectIndex())
  {
    if(d_xAutoscale) /* put the scales manually */
    {
      setAxisScale(QwtPlot::xBottom, xstart, x1);
      
      if(d_xAutoscaleAdjustEnabled)
      {
	adjustXScale(d_xAutoscaleAdjustment);
      }
    }
    if(d_yAutoscale && d_yAutoscaleAdjustEnabled)
    {
      adjustYScale(d_yAutoscaleAdjustment);
    }
    zoomer->setZoomBase(); /* at the end of scale manipulation! */
  }
  else if(zoomer->zoomRectIndex())
   {
     QwtDoubleRect r = zoomer->zoomBase();
     /* obtain x data vector to establish an offset */
      /* look for a curve, if present */
      if(epc != NULL && !epc->vectorUpdateMode() && d_xAutoscale)
      {
	offset = x1 - x2;
	if ((bufsiz != -1) || (x1 - x2) < bufsiz)
	  r.setRight(r.right()+offset); /* make it bigger */
	else
	{
	  r.moveRight(r.right()+offset); /* just move */
	}
	r.setLeft(r.left() - offset);
// 	zoomer->moveBy(offset, 0);
	zoomer->setZoomBase(r);
	r.setRight(r.right() + offset);
      }
      else
	zoomer->setZoomBase(r);
    }
  replot();
}

void EPlotLightBase::enableTrackerText(bool en)
{
  zoomer->enableTrackerText(en);
  if(en)
    zoomer->setTrackerMode(QwtPicker::AlwaysOn);
  else
    zoomer->setTrackerMode(QwtPicker::AlwaysOff);
}
  
bool EPlotLightBase::trackerTextEnabled()
{
  return zoomer->trackerTextEnabled();
}

QList<QwtPlotCurve *> EPlotLightBase::curves()
{
  QList<QwtPlotCurve *> curves;
  foreach(QwtPlotItem* i, itemList())
  {
    if(dynamic_cast<QwtPlotCurve* >(i))
    {
      QwtPlotCurve * c = dynamic_cast<QwtPlotCurve* >(i);
      curves.push_back(c);
    }
  }
  return curves;
}

void EPlotLightBase::setCurvesStyle(QwtPlotCurve::CurveStyle style)
{
  QList<QwtPlotCurve *> crvs = curves();
  foreach(QwtPlotCurve *c, crvs)
    c->setStyle(style);
  d_curvesStyle = style;
}

bool EPlotLightBase::adjustXScale(double percent)
{
  double xMin = 0, xMax = 0, extend;
   QList<QwtPlotCurve *> crvs = curves();
   foreach(QwtPlotCurve *c, crvs)
   {
     if(c->dataSize() < 2) /* it is not possible  to adjust scales if the curves haven't enough data yet. */
       return false;

      if(c->minXValue() < xMin || xMin == xMax)
	 xMin = c->minXValue();
      if(c->maxXValue() > xMax || xMin == xMax)
	 xMax = c->maxXValue();
   }
   if(xMin < xMax) /* values must be well ordered */
   {
     extend = ((xMax - xMin) * percent/100.0);
     setAxisScale(QwtPlot::xBottom, xMin - extend/2, xMax + extend/2);
     replot();
     zoomer->setZoomBase();
     return true;
   }
   perr("error adjusting the X scale: xMin %f xMax %f leaving unset", xMin, xMax); 
   return false;
}

bool EPlotLightBase::adjustYScale(double percent)
{
  double yMin = 0, yMax = 0, extend;
    
   QList<QwtPlotCurve *> crvs = curves();
   foreach(QwtPlotCurve *c, crvs)
   {
     if(c->dataSize() < 2) /* it is not possible  to adjust scales if the curves haven't enough data yet. */
       return false;
      /* y */
      if(c->minYValue() < yMin || yMin == yMax)
	 yMin = c->minYValue();
      if(c->maxYValue() > yMax || yMin == yMax)
	 yMax = c->maxYValue();
   }
   
   if(yMin < yMax) /* values must be well ordered */
   {
     extend = (yMax - yMin) * percent/100.0;
     setAxisScale(QwtPlot::yLeft, yMin - extend/2, yMax + extend/2);
     replot();
     zoomer->setZoomBase();
     return true;
   }
   perr("error adjusting the Y scale: xMin %f xMax %f: leaving unset",  yMin, yMax); 
   return false;
}

bool EPlotLightBase::adjustScales(double percent)
{
   return adjustXScale(percent) && adjustYScale(percent);
}

void EPlotLightBase::setAlignCanvasToScalesEnabled(bool en)
{
    if(plotLayout())
      plotLayout()->setAlignCanvasToScales(en);
}
    
bool EPlotLightBase::alignCanvasToScalesEnabled()
{
  if(plotLayout())
      return plotLayout()->alignCanvasToScales();
  return false;
}

void EPlotLightBase::setXAxisAutoscaleEnabled(bool autoscale)
{
   d_xAutoscale = autoscale;
   /* if !d_autoscale make clear to QwtPlot that we do not want any x axis autoscale, although if we use
    * EPlotLightBase api, x axis autoscale shouldn't be enabled.
    */
   if(!d_xAutoscale)
   {
#if QWT_VERSION >= 0x050200
	setAxisScale(QwtPlot::xBottom, axisScaleDiv(QwtPlot::xBottom)->lowerBound(), axisScaleDiv(QwtPlot::xBottom)->upperBound());
#else
	setAxisScale(QwtPlot::xBottom, axisScaleDiv(QwtPlot::xBottom)->lBound(), axisScaleDiv(QwtPlot::xBottom)->hBound());
#endif
    }
    /* else if autoscale is enabled the x scale will be adjusted on the next refresh() method */
    QwtPlot::replot();
    zoomer->setZoomBase();
}
	

void EPlotLightBase::setYAxisAutoscaleEnabled(bool autoscale)
{
  d_yAutoscale = autoscale;
	if(autoscale)
		setAxisAutoScale(QwtPlot::yLeft); /* enable auto scale */
	else /* disable autoscale by setting axis scale */
	{
#if QWT_VERSION >= 0x050200
		setAxisScale(QwtPlot::yLeft, axisScaleDiv(QwtPlot::yLeft)->lowerBound(), axisScaleDiv(QwtPlot::yLeft)->upperBound());
#else
		setAxisScale(QwtPlot::yLeft, axisScaleDiv(QwtPlot::yLeft)->lBound(), axisScaleDiv(QwtPlot::yLeft)->hBound());
#endif
	}
	QwtPlot::replot();
	zoomer->setZoomBase();
}

double EPlotLightBase::yUpperBound()
{
#if QWT_VERSION >= 0x050200
		return axisScaleDiv(QwtPlot::yLeft)->upperBound();
#else
		return axisScaleDiv(QwtPlot::yLeft)->hBound();
#endif	
}
		
double EPlotLightBase::yLowerBound()
{
#if QWT_VERSION >= 0x050200
		return axisScaleDiv(QwtPlot::yLeft)->lowerBound();
#else
		return axisScaleDiv(QwtPlot::yLeft)->lBound();
#endif		
}

/* implicitly disables y axis autoscale (via the QwtPlot::setAxisScale() ) */
void EPlotLightBase::setYLowerBound(double l)
{
  d_yAutoscale = false;
#if QWT_VERSION >= 0x050200
		setAxisScale(QwtPlot::yLeft, l, axisScaleDiv(QwtPlot::yLeft)->upperBound());
#else
		setAxisScale(QwtPlot::yLeft, l, axisScaleDiv(QwtPlot::yLeft)->hBound());
#endif
	QwtPlot::replot();
	zoomer->setZoomBase();
}

/* implicitly disables y axis autoscale (via the QwtPlot::setAxisScale() ) */
void EPlotLightBase::setYUpperBound(double u)
{
  d_yAutoscale = false;
	#if QWT_VERSION >= 0x050200
	setAxisScale(QwtPlot::yLeft, axisScaleDiv(QwtPlot::yLeft)->lowerBound(), u);
#else
	setAxisScale(QwtPlot::yLeft, axisScaleDiv(QwtPlot::yLeft)->lBound(), u);
#endif	
	QwtPlot::replot();
	zoomer->setZoomBase();
}
		
double EPlotLightBase::xUpperBound()
{
#if QWT_VERSION >= 0x050200
		return axisScaleDiv(QwtPlot::xBottom)->upperBound();
#else
		return axisScaleDiv(QwtPlot::xBottom)->hBound();
#endif	
}
		
double EPlotLightBase::xLowerBound()
{
#if QWT_VERSION >= 0x050200
	return axisScaleDiv(QwtPlot::xBottom)->lowerBound();
#else
	return axisScaleDiv(QwtPlot::xBottom)->lBound();
#endif		
}

/* implicitly disables x autoscale in QwtPlot via setAxisScale() and explicitly disables it
 * here in EPlotLightBase by d_xAutoscale set to false.
 * d_xAutoscale set to false also prevents the refresh() method from scrolling.
 */
void EPlotLightBase::setXLowerBound(double l)
{
	d_xAutoscale = false;  /* disables autoscale */
#if QWT_VERSION >= 0x050200
	setAxisScale(QwtPlot::xBottom, l, axisScaleDiv(QwtPlot::xBottom)->upperBound());
#else
	setAxisScale(QwtPlot::xBottom, l, axisScaleDiv(QwtPlot::xBottom)->hBound());
#endif
	QwtPlot::replot();
	zoomer->setZoomBase();
}

/* implicitly disables x autoscale in QwtPlot via setAxisScale() and explicitly disables it
 * here in EPlotLightBase by d_xAutoscale set to false.
 * d_xAutoscale set to false also prevents the refresh() method from scrolling.
 */
void EPlotLightBase::setXUpperBound(double u)
{
	d_xAutoscale = false;  /* disables autoscale */
#if QWT_VERSION >= 0x050200
	setAxisScale(QwtPlot::xBottom, axisScaleDiv(QwtPlot::xBottom)->lowerBound(), u);
#else
	setAxisScale(QwtPlot::xBottom, axisScaleDiv(QwtPlot::xBottom)->lBound(), u);
#endif	
	QwtPlot::replot();
	zoomer->setZoomBase();
}

/* implicitly disables y axis autoscale (via the QwtPlot::setAxisScale() ) */
void  EPlotLightBase::extendYLowerBound(double l)
{
  d_yAutoscale = false;
  double lBound, uBound;
#if QWT_VERSION >= 0x050200
  lBound = axisScaleDiv(QwtPlot::yLeft)->lowerBound();
  uBound = axisScaleDiv(QwtPlot::yLeft)->upperBound();
#else
  lBound = axisScaleDiv(QwtPlot::yLeft)->lBound();
  uBound = axisScaleDiv(QwtPlot::yLeft)->hBound();
#endif
  lBound = qMin(lBound, l);
  setAxisScale(QwtPlot::yLeft, lBound, uBound);
  QwtPlot::replot();
  zoomer->setZoomBase();
}
     
/* implicitly disables y axis autoscale (via the QwtPlot::setAxisScale() ) */
void  EPlotLightBase::extendYUpperBound(double u)
{
  d_yAutoscale = false;
  double lBound, uBound;
#if QWT_VERSION >= 0x050200
  lBound = axisScaleDiv(QwtPlot::yLeft)->lowerBound();
  uBound = axisScaleDiv(QwtPlot::yLeft)->upperBound();
#else
  lBound = axisScaleDiv(QwtPlot::yLeft)->lBound();
  uBound = axisScaleDiv(QwtPlot::yLeft)->hBound();
#endif
  uBound = qMax(uBound, u);
  setAxisScale(QwtPlot::yLeft, lBound, uBound); /* disables autoscale */
  QwtPlot::replot();
  zoomer->setZoomBase();
}

void EPlotLightBase::setXAutoscaleAdjustment(double d)
{
  if(d >= 0)
    d_xAutoscaleAdjustment = d;
}

void EPlotLightBase::setYAutoscaleAdjustment(double d)
{
  if(d >= 0)
    d_yAutoscaleAdjustment = d;
}


