#include "eplotlight_marker.h"
#include "ezoomer.h"
#include <colors.h>
#include <macros.h>
#include <QtDebug>
#include <QMouseEvent>
#include <qwt_plot_marker.h>
#include <qwt_plot_picker.h>

#define ALPHAVAL 220

void Arrow::draw(QPainter *painter, const QwtScaleMap &xMap, const QwtScaleMap &yMap, const QRect &) const
{
//	qDebug() << begin << end;
	double x1, x2, y1, y2;
	QColor penColor(KLIGHTGRAY);
	x1 = xMap.transform(begin.x());
	x2 = xMap.transform(end.x());
	y1 = yMap.transform(begin.y());
	y2 = yMap.transform(end.y());
	penColor.setAlpha(ALPHAVAL - 100);
	painter->setPen(KDARKGRAY);
	painter->drawLine(QPointF(x1, y1), QPointF(x2, y2));
}

EPlotLightMarker::EPlotLightMarker(QWidget *parent) : EPlotLight(parent)
{
  init();
}

EPlotLightMarker::EPlotLightMarker(const QwtText &title, QWidget *parent) : EPlotLight(title, parent)
{
  init();
}

void EPlotLightMarker::init()
{
    QColor bgColor(QColor(245,245,245));
    QColor txtColor(Qt::black);
    QColor bgPen(KDARKGRAY);
    _marker = new QwtPlotMarker();
    _picker = new QwtPlotPicker(QwtPlot::xBottom, QwtPlot::yLeft, QwtPicker::PointSelection, QwtPlotPicker::NoRubberBand, QwtPicker::AlwaysOff, canvas());
    connect(_picker, SIGNAL(selected(const QwtPolygon &)), this, SLOT(showLabel(const QwtPolygon &)));
    QwtText text("", QwtText::PlainText);
    text.setRenderFlags(Qt::AlignCenter | Qt::TextIncludeTrailingSpaces);
    text.setFont(QFont(fontInfo().family(), 10, QFont::Bold));
    bgColor.setAlpha(ALPHAVAL);
    txtColor.setAlpha(ALPHAVAL);
    bgPen.setAlpha(ALPHAVAL);
    text.setColor(txtColor);
    text.setBackgroundBrush(QBrush(bgColor));
    text.setBackgroundPen(QPen(bgPen, 1));
    _marker->setLabel(text);
    _marker->setLabelAlignment(Qt::AlignHCenter | Qt::AlignVCenter);
    _marker->setLineStyle(QwtPlotMarker::NoLine);
    //_marker->setLineStyle(QwtPlotMarker::Cross);
    _marker->setValue(0.0, 0.0);
    _marker->attach(this);
    _marker->hide();
    _arrow = new Arrow();
    _arrow->attach(this);
    _arrow->hide();
    connect(zoomer, SIGNAL(zoomed(const QwtDoubleRect&) ), this, SLOT(plotZoomed(const QwtDoubleRect&) ) );
}

QString EPlotLightMarker::markerText(const QwtPlotCurve *relatedCurve, const int index)
{
  QString s;
  if(relatedCurve != NULL)
  {
    if(relatedCurve->title() != QwtText(QString()))
      s = QString("%1:\n").arg(relatedCurve->title().text());
    s += QString("x: %1\ny: %2").arg(relatedCurve->x(index)).arg(relatedCurve->y(index));
  }
  return s;
}

void EPlotLightMarker::showLabel(const QwtPolygon &p)
{
    int closestPoint;
    QwtPlotCurve *closestCurve;
    closestPoint = findClosestPoint(p.point(0), &closestCurve);

    if (closestPoint != -1)
    {
      _marker->show();
      _arrow->show();
      updateLabel(closestCurve, closestPoint);
    }
    else
    {
      _marker->hide();
      _arrow->hide();
    }
    replot();
}

void EPlotLightMarker::updateLabel(QwtPlotCurve *closestCurve, int closestPoint)
{
  double xLowerBound, xUpperBound, yLowerBound, yUpperBound;
  
  if(closestCurve == NULL)
  {
    pwarn("EPlotLightMarker::updateLabel: closestCurve is null");
  }
  else if((closestPoint != -1) && _marker->isVisible())
  {
      double hoff, range;
#if QWT_VERSION >= 0x050200
      xLowerBound = axisScaleDiv(QwtPlot::xBottom)->lowerBound();
      xUpperBound = axisScaleDiv(QwtPlot::xBottom)->upperBound();
      yLowerBound = axisScaleDiv(QwtPlot::yLeft)->lowerBound();
      yUpperBound = axisScaleDiv(QwtPlot::yLeft)->upperBound();
#else
      xLowerBound = axisScaleDiv(QwtPlot::xBottom)->lBound();
      xUpperBound = axisScaleDiv(QwtPlot::xBottom)->hBound();
      yLowerBound = axisScaleDiv(QwtPlot::yLeft)->lBound();
      yUpperBound = axisScaleDiv(QwtPlot::yLeft)->hBound();
#endif
      /* axisScaleDiv(axisId)->lBound(), axisScaleDiv(axisId)->hBound() are the current limits of the axis scale */
      range = xUpperBound - xLowerBound;
      QwtText l = _marker->label(); 
      l.setText(markerText(closestCurve, closestPoint));
      _marker->setLabel(l);
      
      double markerWidth = l.textSize(l.font()).width();
      double markerHeight = l.textSize(l.font()).height();
      
      /* align label and set different x offsets depending on the area of the 
       * canvas the click takes place in.
       */
      if(closestCurve->x(closestPoint) <= xLowerBound + range/3)
      {
	hoff = 0.1*range; // + .2*closestCurve->x(closestPoint);
	_marker->setLabelAlignment(Qt::AlignRight|Qt::AlignBottom);
      }
      else if(closestCurve->x(closestPoint) >= xLowerBound + 2 * range/3)
      {
	hoff = -0.1*range;
	_marker->setLabelAlignment(Qt::AlignLeft|Qt::AlignBottom);
      }
      else 
      {
	hoff = -0.1*range;
	_marker->setLabelAlignment(Qt::AlignHCenter|Qt::AlignBottom);
      }
      
      QwtDoublePoint begin, end, arrowEnd;
      double up = yLowerBound + 0.93 * (yUpperBound - yLowerBound);
      begin = QwtDoublePoint(closestCurve->x(closestPoint), closestCurve->y(closestPoint));
      end = QwtDoublePoint(closestCurve->x(closestPoint)+hoff, up);
      
      _marker->setYAxis(QwtPlot::yLeft);
      _marker->setValue(end);
      
      qDebug() << "marker bounding rect: " << _marker->boundingRect() << 
	_marker->yAxis() << " y" << _marker->yValue() << " value " << _marker->value();
	
      /* 1. to obtain the position of the end point of the arrow, transform first the end point into
       * pixel coordinates.
       */
      int arrowXEndPix = transform(QwtPlot::xBottom, closestCurve->x(closestPoint) + hoff);
      int arrowYEndPix = transform(QwtPlot::yLeft, up);
      
      /* 2. position end point for the arrow, depending on the area the user clicks.
       * No need to change arrowXEndPix for central area clicks. We are in pixel coordinates
       * and markerWidth and markerHeight are in pixel coordinates: we can sum each other
       */
      if(closestCurve->x(closestPoint) <= xLowerBound + range/3)
	arrowXEndPix += markerWidth/2;
      else if(closestCurve->x(closestPoint) >= xLowerBound + 2 * range/3)
	arrowXEndPix -= markerWidth/2; /* last portion */
      
      arrowYEndPix += markerHeight; /* we are summing pixel coords */
      
      /* 3. Finally set arrow end point, transforming back into plot coordinates */
      arrowEnd = QwtDoublePoint(invTransform(QwtPlot::xBottom, arrowXEndPix), invTransform(QwtPlot::yLeft, arrowYEndPix));
      _arrow->setYAxis(QwtPlot::yLeft);
      _arrow->begin = begin;
      _arrow->end = arrowEnd;
  }
  replot();
}

int EPlotLightMarker::findClosestPoint(QPoint p, QwtPlotCurve **closestCrv)
{
    QList<double> distances;
    QMap<QwtPlotCurve*, double> curveDistancesMap;
    QMap<QwtPlotCurve*, int> curveClosestPointMap;
    int closestPoint = -1;
    double dist = -1, minDist = -1;
    *closestCrv = NULL;
    
    foreach(QwtPlotItem* i, itemList())
    {
      if(dynamic_cast<QwtPlotCurve* >(i))
	{
	  QwtPlotCurve *c = dynamic_cast<QwtPlotCurve* >(i);
	  if(c->isVisible())
	  {
	  	closestPoint = c->closestPoint(p, &dist);
	  	curveDistancesMap.insert(c, dist);
	  	curveClosestPointMap.insert(c, closestPoint);
// 		qprintf("curve %s, dist %.2f closestPoint %d\n", qstoc(c->title().text()), dist, closestPoint);
	 }
	}
    }
    
    
    distances = curveDistancesMap.values();
    if(distances.size() > 0)
    {
      qSort(distances.begin(), distances.end());
      qDebug() << "distances sorted: " << distances;
      minDist = distances.first();
      closestPoint = curveClosestPointMap.value(curveDistancesMap.key(minDist));
      qDebug() << "valori di curveClosestPointMap: " << curveClosestPointMap.values() << "closestPoint " << closestPoint;
      if(curveClosestPointMap.values().contains(closestPoint))
      {
	*closestCrv = curveDistancesMap.key(minDist);
	qDebug() << "closestCurve: " << *closestCrv << (*closestCrv)->title().text(); 
      }
      else
	qDebug() << "dont contains curve";
    }
    return closestPoint;
}

void EPlotLightMarker::setMarkerLabel(const QwtText &text)
{
  _marker->setLabel(text);
}

void EPlotLightMarker::hideMarker()
{
  _marker->hide();
  _arrow->hide();
  replot();
}

void EPlotLightMarker::mouseReleaseEvent(QMouseEvent *ev)
{
  if(ev->button() == Qt::RightButton && _marker->isVisible())
    hideMarker();
  QWidget::mouseReleaseEvent(ev);
}

void EPlotLightMarker::plotZoomed(const QwtDoubleRect&)
{
  if(_marker->isVisible())
    hideMarker();
//   refresh();
}



