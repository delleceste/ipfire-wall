#include "kernel_stats_plot.h"
#include <QDateTime>


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

KernelStatsPlot::KernelStatsPlot(const QwtText &title, QWidget *parent) : EPlotLightMarker(title, parent)
{
  
}

KernelStatsPlot::KernelStatsPlot(QWidget *parent) : EPlotLightMarker(parent)
{
  
}

QString KernelStatsPlot::markerText(const QwtPlotCurve *relatedCurve, const int index)
{
  if(!relatedCurve)
    return QString("invalid curve!");
  QDateTime d;
  d.setTime_t((time_t) relatedCurve->x(index) );
  QString txt;
  txt = QString("%1\n").arg(relatedCurve->title().text());
  txt += d.toString("dd MMM\nhh:mm:ss");
  txt += QString("\n%1kB").arg(relatedCurve->y(index));
  return txt;
}



