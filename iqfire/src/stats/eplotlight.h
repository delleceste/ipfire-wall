#ifndef EPLOTLIGHT_H
#define EPLOTLIGHT_H

#include <QMap>

#include "eplotlight_base.h"
#include "eplotcurve.h"


/***************************************************************************
*   Copyright (C) 2008 by Giacomo Strangolino	   			  *
*   delleceste@gmail.com		   				  *
*                                                                         *
*   This program is free software; you can redistribute it and/or modify  *
*   it under the terms of the GNU General Public License as published by  *
*   the Free Software Foundation; either version 2 of the License, or     *
*   (at your option) any later version.                                   *
*                                                                         *
*   This program is distributed in the hope that it will be useful,       *
*   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
*   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
*   GNU General Public License for more details.                          *
*                                                                         *
*   You should have received a copy of the GNU General Public License     *
*   along with this program; if not, write to the                         *
*   Free Software Foundation, Inc.,                                       *
*   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.             *
***************************************************************************/
/**
 * \brief a plot derived from EPlotLightBase that provides easy curve management.
 *
 * @see EPlotLightBase base class
 * @see EPlotLightBase::refresh() method
 * 
 * 
 */
class EPlotLight : public EPlotLightBase
{
  Q_OBJECT
    
  Q_PROPERTY(bool timeScaleEnabled READ timeScaleDrawEnabled() WRITE setTimeScaleDrawEnabled)
  Q_PROPERTY(int curvesStyle READ curvesStyle WRITE setCurvesStyleAsInt);
  
  public:
    /** 
     * \brief The constructor of a simple plot with zooming and scrolling capabilities
     * @param parent the parent widget
     */
    EPlotLight(QWidget *parent);
    
    /** 
     * \brief The constructor of a simple plot with zooming and scrolling capabilities
     * @param parent the parent widget
     * @param title the title of the plot
     */
    EPlotLight(const QwtText &title, QWidget *parent);

    /** \brief Registers a new curve with the provided curveName 
     * @param curveName the name associated to the EPlotCurve curve.
     * @param curve the pointer to the EPlotCurve to add to the plot with the given curveName.
     *
     * Use addCurve() to add the curve to the plot, with the provided curveName. The curveName
     * has to be used to appendData to the EPlotCurve when new points need to be added.
     */
    void addCurve(const QString& curveName, EPlotCurve *curve);
    
    /** \brief Removes the specified curve from the plot, deleting it.
     * @param curveName the name of the curve you want to remove.
     */
    void removeCurve(const QString &curveName);
    
    /** \brief sets a particular curve style for the specified curveName
     * @param curveName the name of the curve you want to change the style to
     * @param style the CurveStyle (NoCurve, Lines, Sticks, Steps, Dots, UserCurve) you want to apply to the curve curveName.
     * Should you want to change the style of all the curves in the plot in one shot, consider using
     * EPlotLightBase::setCurvesStyle().
     */
    void setCurveStyle(const QString &curveName, QwtPlotCurve::CurveStyle);
    
    void removeData();
    
    /** \brief sets the data buffer size to b elements. When b is reached, data is removed from the front.
     * @param b the maximum size of the underlying data .
     *
     * For each curve of the plot, sets the buffer size of the data linked to the curve. This puts a limit
     * on the memory used by the plot.
     */
    void setDataBufferSize(int b);
    
    /** \brief returns the data buffer size.
     * @return the number of elements of the underlying data size.
     */
    int dataBufferSize() { return d_bufSiz; }
    
    bool yAutoscale() { return axisAutoScale(QwtPlot::yLeft); }
    
    public slots:
    
     /**
     *  \brief Initialize data with x- and y-arrays (explicitly shared)
     * @param curveName the name of the curve you want to set data on
     * @param xData x array of data to set on the curve
     * @param yData y array of data to set on the curve
     *
     * Calls QwtPlotCurve's setData() on the curve having the specified name.
     */
     virtual void setData(const QString& curveName, const QVector< double > &xData, const QVector< double > &yData);
    
    /** \brief Appends data to the curve with the given curveName, using the efficient draw() method
     *
     * @param curveName the curve name that identifies the curve you want to append data to. The curveName
     * must be the string you assigned when you called addCurve(). It is not necessary that the curveName is
     * the same name as the curve title provided when the curve was created.
     * @param x the x value to append to the x axis.
     * @param y the y value to append to the y axis.
     * This method adds one x and y point to the curve with curveName, using the low level draw() method of
     * the QwtPlotCurve, providing an efficient update of the plot.
     */
    virtual void appendData(const QString& curveName, double x, double y); 
    
    /** \brief Appends size data to the curve with the given curveName, using the efficient draw() method
     *
     * @param curveName the curve name that identifies the curve you want to append data to. The curveName
     * must be the string you assigned when you called addCurve(). It is not necessary that the curveName is
     * the same name as the curve title provided when the curve was created.
     * @param x pointer to the x value(s) to append to the x axis.
     * @param y pointer to the y value(s) to append to the y axis.
     * @param size number of elements contained in the data pointed by x and y.
     *
     * This method adds size x and y points to the curve with curveName, using the low level draw() method of
     * the QwtPlotCurve, providing an efficient update of the plot.
     */
    virtual void appendData(const QString& curveName, double *x, double *y, int size);
     
    /** \brief the same as setXAxisAutoscaleEnabled, provided for convenience and for backwards compatibility
     */
    void setXAutoscale(bool a) { EPlotLightBase::setXAxisAutoscaleEnabled(a); }
    
    /** \brief the same as setYAxisAutoscaleEnabled, provided for convenience and for backwards compatibility
     */
    void setYAutoscale(bool a) { EPlotLightBase::setYAxisAutoscaleEnabled(a); }
    
  protected slots:
    virtual void dataUpdated() {};
    
  private:
    void init();
    int d_bufSiz;
    QMap<QString, EPlotCurve*> d_curvesMap;
    
};



#endif
