/*************************************************************************
 *  Copyright (C) 2010 by Volker Lanz <vl@fidra.de>                      *
 *                                                                       *
 *  This program is free software; you can redistribute it and/or        *
 *  modify it under the terms of the GNU General Public License as       *
 *  published by the Free Software Foundation; either version 3 of       *
 *  the License, or (at your option) any later version.                  *
 *                                                                       *
 *  This program is distributed in the hope that it will be useful,      *
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of       *
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the        *
 *  GNU General Public License for more details.                         *
 *                                                                       *
 *  You should have received a copy of the GNU General Public License    *
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.*
 *************************************************************************/

#if !defined(SCANPROGRESSDIALOG_H)

#define SCANPROGRESSDIALOG_H

#include <QProgressDialog>

class QShowEvent;

class ScanProgressDialog : public QProgressDialog
{
public:
    ScanProgressDialog(QWidget* parent);

    void setProgress(int p) {
        setValue(p);
    }
    void setDeviceName(const QString& d);

protected:
    void showEvent(QShowEvent* e) override;

};

#endif

