#ifndef EPLOT_CURVE_H
#define EPLOT_CURVE_H

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

#include <qwt_plot_curve.h>
#include "ecurvedata.h"

class EPlotCurve : public QObject, public QwtPlotCurve
{
  Q_OBJECT
  public:
    /*! Constructor */
    EPlotCurve(QObject *parent);
    
    /** 
     * \brief Constructor of EPlotCurve.
     * @param title the title of the curve.
     */
    EPlotCurve(QObject *parent, const QwtText &title);
    
     /** 
     * \brief Constructor of EPlotCurve.
     * @param title the title of the curve.
     */
    EPlotCurve(QObject *parent, const QString &title);
    
    ~EPlotCurve();
    
    /** \brief appends x axis data and y axis data of a given size to the curve data.
     * @param x pointer to a double array of x axis data of size count
     * @param y pointer to a double array of y axis data of size count
     * @param count number of elements of the x and y arrays
     *
     * One may consider calling updateRawData() before drawing the curve
     */
    void appendData(double *x, double *y, int count);
    
    void setData(const QwtArray< double > &xData, const QwtArray< double > &yData);
    
    /** \brief takes its data and sets it as raw data on the curve for subsequent drawing
     *
     */
    void updateRawData();
    
    void setDataBufferSize(int size) { d_bufSize = size; }
    int dataBufferSize() { return d_bufSize; }
    
    bool vectorUpdateMode() { return d_vectorUpdateMode; }
    
  protected:
    
  private:
    void init();
    int d_bufSize;
    CurveData *d_data;
    bool d_vectorUpdateMode;
};



#endif


