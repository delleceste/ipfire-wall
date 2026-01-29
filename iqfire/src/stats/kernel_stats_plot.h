#ifndef KERNEL_STATS_PLOT_H
#define KERNEL_STATS_PLOT_H


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

#include "eplotlight_marker.h"

class KernelStatsPlot : public EPlotLightMarker
{
    Q_OBJECT
  public:
    KernelStatsPlot(const QwtText &title, QWidget *parent);
    KernelStatsPlot(QWidget *parent);
    
  protected:
    QString markerText(const QwtPlotCurve *relatedCurve, const int index);
};

#endif
