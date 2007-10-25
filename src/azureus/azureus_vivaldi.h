/***************************************************************************
 *   Copyright (C) 2007 by Saritha Kalyanam                                *
 *   kalyanamsaritha@gmail.com                                             *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 3 of the License, or     *
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
 *   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA            *
 ***************************************************************************/

#ifndef __AZUREUS_VIVALDI_H__
#define __AZUREUS_VIVALDI_H__

#include "pkt.h"

enum azureus_vivaldi_type {
    POSITION_TYPE_NONE = 0,
    POSITION_TYPE_VIVALDI_V1 = 1,
    POSITION_TYPE_VIVALDI_V2 = 5
};

struct azureus_vivaldi_v1_pos {
    float                       c[4];
#define X       0
#define Y       1
#define Z       2
#define E       3
};

struct azureus_vivaldi_pos {
    enum azureus_vivaldi_type           type;
    union {
        struct azureus_vivaldi_v1_pos   v1;
    } v;
};

int azureus_vivaldi_decode(struct pkt *pkt, int type, 
                            struct azureus_vivaldi_pos *pos);
int azureus_vivaldi_encode(struct pkt *pkt, int type, 
                            struct azureus_vivaldi_pos *pos);

#endif /* __AZUREUS_VIVALDI_H__ */

