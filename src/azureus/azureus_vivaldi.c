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
#include "float.h"

static const float initial_err = 10.0;
static float error = 10.0; // initial_err
static const float cc = 0.25;
static const float ce = 0.5;
static int nb_updates = 0;
static const int AZ_CONVERGE_EVERY = 5;
static const float AZ_CONVERGE_FACTOR = 50.0;
static const float AZ_ERROR_MIN = 0.1;

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
    float f[4];

    ASSERT(pkt && pos);
    ASSERT(pos->type == POSITION_TYPE_VIVALDI_V1);

    f[X] = pos->v.v1.x;
    f[Y] = pos->v.v1.y;
    f[H] = pos->v.v1.h;
    f[E] = pos->v.v1.err;

    for (i = 0; i < 4; i++) {
        ret = pkt_write_float(pkt, f[i]);
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
    float f[4];

    ASSERT(pkt && pos);

    pos->type = POSITION_TYPE_VIVALDI_V1;

    for (i = 0; i < 4; i++) {
        ret = pkt_read_float(pkt, &f[i]);
        if (ret != SUCCESS) {
            return ret;
        }
    }

    pos->v.v1.x = f[X];
    pos->v.v1.y = f[Y];
    pos->v.v1.h = f[H];
    pos->v.v1.err = f[E];

    return SUCCESS;
}

struct azureus_vivaldi_pos *
azureus_vivaldi_v1_pos_new(float x, float y, float h, float err)
{
    struct azureus_vivaldi_pos *pos = NULL;

    pos = (struct azureus_vivaldi_pos *) malloc(sizeof(struct azureus_vivaldi_pos));
    if (!pos) {
        return NULL;
    }

    bzero(pos, sizeof(struct azureus_vivaldi_pos));

    pos->type = POSITION_TYPE_VIVALDI_V1;
    pos->v.v1.x = x;
    pos->v.v1.y = y;
    pos->v.v1.h = h;
    pos->v.v1.err = err;

    return pos;
}

void
azureus_vivaldi_v1_pos_delete(struct azureus_vivaldi_pos *pos)
{
    ASSERT(pos);

    free(pos);
}

bool
azureus_vivaldi_v1_at_origin(struct azureus_vivaldi_pos *pos)
{
    ASSERT(pos);

    return ((pos->v.v1.x == 0) && (pos->v.v1.y == 0));
}

bool
azureus_vivaldi_v1_is_valid(struct azureus_vivaldi_pos *pos)
{
    ASSERT(pos);

    return float_is_valid(pos->v.v1.x) && 
            float_is_valid(pos->v.v1.y) && 
            float_is_valid(pos->v.v1.h);
}

int
azureus_vivaldi_v1_add(struct azureus_vivaldi_pos *p1,
                    struct azureus_vivaldi_pos *p2,
                    struct azureus_vivaldi_pos *res)
{
    ASSERT(p1 && p2 && res);

    res->v.v1.x = p1->v.v1.x - p2->v.v1.x;
    res->v.v1.y = p1->v.v1.y - p2->v.v1.y;
    res->v.v1.h = fabs(p1->v.v1.h + p2->v.v1.h);

    return SUCCESS;
}

int
azureus_vivaldi_v1_sub(struct azureus_vivaldi_pos *p1,
                    struct azureus_vivaldi_pos *p2,
                    struct azureus_vivaldi_pos *res)
{
    ASSERT(p1 && p2 && res);

    res->type = POSITION_TYPE_VIVALDI_V1;
    res->v.v1.x = p1->v.v1.x - p2->v.v1.x;
    res->v.v1.y = p1->v.v1.y - p2->v.v1.y;
    res->v.v1.h = fabs(p1->v.v1.h - p2->v.v1.h);

    return SUCCESS;
}

float
azureus_vivaldi_v1_measure(struct azureus_vivaldi_pos *pos) 
{
    ASSERT(pos);

    return (sqrt((pos->v.v1.x * pos->v.v1.x) + 
                    (pos->v.v1.y * pos->v.v1.y)) + pos->v.v1.h);
}

float 
azureus_vivaldi_v1_distance(struct azureus_vivaldi_pos *p1,
                            struct azureus_vivaldi_pos *p2)
{
    struct azureus_vivaldi_pos sub;

    azureus_vivaldi_v1_sub(p1, p2, &sub);

    return azureus_vivaldi_v1_measure(&sub);
}

float
azureus_vivaldi_v1_estimate_rtt(struct azureus_vivaldi_pos *p1, 
                                struct azureus_vivaldi_pos *p2)
{
    ASSERT(p1 && p2);

    if (azureus_vivaldi_v1_at_origin(p1) || azureus_vivaldi_v1_at_origin(p2)) {
        return ieee754_to_float(NAN_PLUS);
    }

    return azureus_vivaldi_v1_distance(p1, p2);
}

int
azureus_vivaldi_v1_update(float rtt, struct azureus_vivaldi_pos *pos, float ej)
{
    return SUCCESS;
}

