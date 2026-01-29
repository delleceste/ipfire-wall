#include "eplotlight.h"
#include <QPaintEngine>
#include <macros.h>
#include <qwt_plot_grid.h>
#include <qwt_legend.h>
#include <qwt_legend_item.h>
#include <QtDebug>
#include <macros.h>
#include "ezoomer.h"

EPlotLight::EPlotLight(QWidget *parent) : EPlotLightBase(parent)
{
 init();
}

EPlotLight::EPlotLight(const QwtText &title, QWidget *parent) : EPlotLightBase(title, parent)
{
  init();
}

void EPlotLight::init()
{
  /* scales are initialized to auto scale, both for x and for y. 
   * X scale is managed internally by EPlotLightBase, through the refresh() method.
   */
  d_bufSiz = -1;
}

void EPlotLight::appendData(const QString& curveTitle, double x, double y)
{
    appendData(curveTitle, &x, &y, 1);
}
    
void EPlotLight::appendData(const QString& curveTitle, double *x, double *y, int size)
{
  if(d_curvesMap.contains(curveTitle))
  {
   EPlotCurve* curve = d_curvesMap.value(curveTitle);
   curve->appendData(x, y, size);
   curve->updateRawData();
   /* save attributes */
   const bool cacheMode =  canvas()->testPaintAttribute(QwtPlotCanvas::PaintCached);
   const bool oldDirectPaint = canvas()->testAttribute(Qt::WA_PaintOutsidePaintEvent);
   const QPaintEngine *pe = canvas()->paintEngine();
   bool directPaint = pe->hasFeature(QPaintEngine::PaintOutsidePaintEvent);
   /* set directPaint to true only when widget is visible. - INFO: canvas inherits QFrame - 
    * Actually, setting this attribute when the widget is hidden, produces X drawing errors.
    */
   if ( pe->type() == QPaintEngine::X11 && this->isVisible())
   {
        // Even if not recommended by TrollTech, Qt::WA_PaintOutsidePaintEvent 
        // works on X11. This has an tremendous effect on the performance..
        directPaint = true;
   }
   /* change attributes temporarily before drawing */
   canvas()->setAttribute(Qt::WA_PaintOutsidePaintEvent, directPaint);
   canvas()->setPaintAttribute(QwtPlotCanvas::PaintCached, false);
   
//    printf("-- drawing %f %f data size: %d on %s\n", *x, *y, curve->dataSize(), curveTitle.toStdString().c_str());
   curve->draw(curve->dataSize() - size, curve->dataSize() - 1);
   /* restore attributes after painting */
   canvas()->setPaintAttribute(QwtPlotCanvas::PaintCached, cacheMode);
   canvas()->setAttribute(Qt::WA_PaintOutsidePaintEvent, oldDirectPaint);
  }
  else
    perr("EPLotLight: appendData: curve \"%s\" does not exist", qstoc(curveTitle));
}
    
void EPlotLight::setData(const QString& curveName, const QVector< double > &xData, const QVector< double > &yData)
{
  if(d_curvesMap.contains(curveName))
  {
    EPlotCurve* curve = d_curvesMap.value(curveName);
    curve->setData(xData, yData);
  }
  else
    perr("EPlotLight \"%s\" no curve with the name \"%s\"", qstoc(objectName()), qstoc(curveName));
}

void EPlotLight::addCurve(const QString& title, EPlotCurve *curve)
{
  d_curvesMap.insert(title, curve);
  curve->attach(this);
}

void EPlotLight::removeCurve(const QString &curveName)
{
	EPlotCurve* curve = d_curvesMap.value(curveName);
	d_curvesMap.remove(curveName);
	curve->detach();
	delete curve;
}
    
void EPlotLight::removeData()
{

}
  
void EPlotLight::setDataBufferSize(int s)
{
  QList<EPlotCurve *> curves = d_curvesMap.values();
  foreach(EPlotCurve *c, curves)
    c->setDataBufferSize(s);
}

void EPlotLight::setCurveStyle(const QString &curveName, QwtPlotCurve::CurveStyle style)
{
  if(d_curvesMap.contains(curveName))
  {
    EPlotCurve *pCurve = d_curvesMap.value(curveName);
    pCurve->setStyle(style);
    replot();
  }
}

		


