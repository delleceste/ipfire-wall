#include "eplotcurve.h"
#include <QtDebug>


EPlotCurve::EPlotCurve(QObject *parent) : QObject(parent), QwtPlotCurve()
{
  init();
}

EPlotCurve:: EPlotCurve(QObject *parent, const QwtText &title) : QObject(parent), QwtPlotCurve(title)
{
  init();
}

EPlotCurve:: EPlotCurve(QObject *parent, const QString &title) : QObject(parent), QwtPlotCurve(title)
{
  init();
}

void EPlotCurve::init()
{
  d_data = NULL;
  d_data = new CurveData();
  d_bufSize = -1;
  d_vectorUpdateMode = false;
}

EPlotCurve::~EPlotCurve()
{
  if(d_data)
    delete d_data;
}

void EPlotCurve::setData(const QwtArray< double > &xData, const QwtArray< double > &yData)
{
  d_vectorUpdateMode = true;
  QwtPlotCurve::setData(xData, yData);
}

void EPlotCurve::appendData(double *x, double *y, int count)
{
  /* add count elements */
  d_data->append(x, y, count);
  if(d_bufSize > 0 && d_data->count() > d_bufSize)
  {
    qDebug() << "xxx resize needed data size / bufsize" << d_data->count() <<  d_bufSize;
    d_data->removeFirstElements(d_data->count() - d_bufSize);
  }
  if(count == 1)
    d_vectorUpdateMode = false;
  else
    d_vectorUpdateMode = true;
//   else
//     printf("resize not needed: data size %d bufSize %d\n", d_data->size(), d_bufSize);
}

void EPlotCurve::updateRawData()
{
  setRawData(d_data->x(), d_data->y(), d_data->count());
}




