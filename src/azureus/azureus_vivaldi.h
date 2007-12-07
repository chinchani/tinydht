/***************************************************************************
 *  Copyright (C) 2007 by Saritha Kalyanam                                 *
 *  kalyanamsaritha@gmail.com                                              *
 *                                                                         *
 *  This program is free software: you can redistribute it and/or modify   *
 *  it under the terms of the GNU Affero General Public License as         *
 *  published by the Free Software Foundation, either version 3 of the     *
 *  License, or (at your option) any later version.                        *
 *                                                                         *
 *  This program is distributed in the hope that it will be useful,        *
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of         *
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the          *
 *  GNU Affero General Public License for more details.                    *
 *                                                                         *
 *  You should have received a copy of the GNU Affero General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.  *
 ***************************************************************************/

#ifndef __AZUREUS_VIVALDI_H__
#define __AZUREUS_VIVALDI_H__

#include "pkt.h"

struct azureus_rpc_msg;

#define MAX_RPC_VIVALDI_POS     2

#define VIVALDI_V1              0
#define VIVALDI_V2              1

enum azureus_vivaldi_type {
    POSITION_TYPE_NONE = 0,
    POSITION_TYPE_VIVALDI_V1 = 1,
    POSITION_TYPE_VIVALDI_V2 = 5
};

struct azureus_vivaldi_v1_pos {
    float       x, y, h, err;
#define X       0
#define Y       1
#define H       2
#define E       3
};

struct azureus_vivaldi_v2_pos {
    u8          n_coords;
    double      x, y, h, err;
};

struct azureus_vivaldi_pos {
    enum azureus_vivaldi_type           type;
    union {
        struct azureus_vivaldi_v1_pos   v1;
        struct azureus_vivaldi_v2_pos   v2;
    } v;
};

int azureus_vivaldi_pos_new(struct azureus_vivaldi_pos *pos, u8 type, 
                            float x, float y, float h);
int azureus_vivaldi_v1_update(struct azureus_vivaldi_pos *pos, float rtt, 
                            struct azureus_vivaldi_pos *cj, float ej);
float azureus_vivaldi_v1_estimate_rtt(struct azureus_vivaldi_pos *p1, 
                                struct azureus_vivaldi_pos *p2);

int azureus_vivaldi_decode(struct pkt *pkt, int type, 
                            struct azureus_vivaldi_pos *pos);
int azureus_vivaldi_encode(struct pkt *pkt, int type, 
                            struct azureus_vivaldi_pos *pos);

void azureus_vivaldi_pos_dump(struct azureus_vivaldi_pos *pos);

#endif /* __AZUREUS_VIVALDI_H__ */

