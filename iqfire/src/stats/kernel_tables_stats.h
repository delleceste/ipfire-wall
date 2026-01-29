#ifndef KERNEL_TABLES_STATS
#define KERNEL_TABLES_STATS


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

#include <QWidget>
#include <QList>
#include "kernel_stats_plot.h"
#include "eplotcurve.h"
#include <ipfire_structs.h>

class IQFCheckBox;
class IQFSpinBox;
class QTimer;
class IQFRadioButton;

class KernelTablesStats : public QWidget
{
  Q_OBJECT
  public:
    KernelTablesStats(QWidget *parent);
    
  protected:
    void showEvent(QShowEvent *e);
    
  protected slots:
    void pollRefresh();
    void plotRefresh();
    void plotDataBufferChanged(int);
    void plotRefreshIntervalChanged(int);
    void enableRefresh(bool);
    void peakRBToggled(bool);
    void pollChanged(int);
    
  private:
    IQFCheckBox *d_cbEnable;
    IQFSpinBox *d_sbPlotRefreshInterval, *d_sbBuffer, *d_sbPoll;
    IQFRadioButton *d_rbMean, *d_rbPeak;
    KernelStatsPlot *d_plot;
    int d_refreshTimeout, d_pollTimeout, d_bufsiz;
    QTimer *d_refreshTimer, *d_pollTimer;
    bool d_refreshEnabled;
    EPlotCurve *d_stateCrv, *d_snatCrv, *d_dnatCrv, *d_loginfoCrv, *d_totCrv;
    
    struct firesizes tables_sizes;
    
    int getStructSizes();
    QList<uint> d_stPollBuf, d_sntPollBuf, d_dntPollBuf, d_infoPollBuf;
};







#endif




