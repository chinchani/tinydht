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

#include <string.h>

#include "azureus_vivaldi.h"

static int azureus_vivaldi_v1_encode(struct pkt *pkt, 
                                        struct azureus_vivaldi_pos *pos);
static int azureus_vivaldi_v1_decode(struct pkt *pkt, 
                                        struct azureus_vivaldi_pos *pos);

int
azureus_vivaldi_encode(struct pkt *pkt, int type, 
                                        struct azureus_vivaldi_pos *pos)
{
    int ret;

    ASSERT(pkt && pos);

    ret = pkt_mark(pkt, 512);
    if (ret != SUCCESS) {
        return ret;
    }

    switch (type) {
        case POSITION_TYPE_VIVALDI_V1:
            ret = azureus_vivaldi_v1_encode(pkt, pos);
            if (ret != SUCCESS) {
                return ret;
            }
            break;

        case POSITION_TYPE_VIVALDI_V2:
            break;
            
        default:
            pkt_reset(pkt);
            return FAILURE;
    }

    return SUCCESS;
}

static int
azureus_vivaldi_v1_encode(struct pkt *pkt, struct azureus_vivaldi_pos *pos)
{
    int i;
    int ret;

    ASSERT(pkt && pos);
    ASSERT(pos->type == POSITION_TYPE_VIVALDI_V1);

    for (i = 0; i < 4; i++) {
        ret = pkt_write_float(pkt, pos->v.v1.c[i]);
        if (ret != SUCCESS) {
            return ret;
        }
    }

    return SUCCESS;
}

int
azureus_vivaldi_decode(struct pkt *pkt, int type, 
                            struct azureus_vivaldi_pos *pos)
{
    int ret;

    ASSERT(pkt && pos);

    bzero(pos, sizeof(struct azureus_vivaldi_pos));

    ret = pkt_mark(pkt, 512);
    if (ret != SUCCESS) {
        return ret;
    }

    switch (type) {
        case POSITION_TYPE_VIVALDI_V1:
            ret = azureus_vivaldi_v1_decode(pkt, pos);
            if (ret != SUCCESS) {
                return ret;
            }
            break;

        case POSITION_TYPE_VIVALDI_V2:
            break;

        default:
            pkt_reset(pkt);
            return FAILURE;
    }

    return SUCCESS;
}

static int
azureus_vivaldi_v1_decode(struct pkt *pkt, struct azureus_vivaldi_pos *pos)
{
    int i;
    int ret;

    ASSERT(pkt && pos);

    pos->type = POSITION_TYPE_VIVALDI_V1;

    for (i = 0; i < 4; i++) {
        ret = pkt_read_float(pkt, &pos->v.v1.c[i]);
        if (ret != SUCCESS) {
            return ret;
        }
    }

    return SUCCESS;
}
