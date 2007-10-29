/***************************************************************************
 *   Copyright (C) 2007 by Saritha Kalyanam   				   *
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

#include "float.h"
#include "debug.h"

u32
float_to_ieee754(float f)
{
    u8 sign;
    u8 exp = 127;
    float nf;
    float mant;
    u32 signf;
    u32 ret;
    int i;

    if (f == 0.0) {
        return 0;
    }

    if (-f > f) {
        sign = 1;
        f = -f;
    } else {
        sign = 0;
        f = f;
    }

    exp = 127;

    if (f < 1.0) {
        for (nf = f; nf < 1.0; nf *= 2, exp--);
    } else if (f > 1.0) {
        for (nf = f; nf >= 2.0; nf /= 2, exp++);
    } else {
        nf = 1.0;
    }

    /* we are normalized at this point */
    ASSERT((nf >= 1.0) && (nf < 2.0));

    signf = nf;
    mant = nf - 1.0*signf;
    ret = 0;

    for (i = 0; i < 23; i++) {
        mant = mant*2;
    }
    
    ret = mant;

    return (sign << 31) | (exp << 23) | ret;
}

float
ieee754_to_float(u32 ie)
{
    u8 sign;
    char exp;
    u32 intmant;
    float mant;
    int i;
    float ret;

    if (ie == 0) {
        return 0.0;
    }

    sign = (ie & 0xffffffff) >> 31;
    exp = ((ie & 0x7f800000) >> 23) - 127;
    intmant = ie & 0x007fffff;

    mant = 1.0*intmant;
    for (i = 0; i < 23; i++) {
        mant = mant/2;
    }

    ASSERT(mant < 1.0);

    ret = 1.0 + mant;

    if (exp < 0) {
        for (; exp != 0; exp++) {
            ret = ret/2;
        }
    } else if (exp > 0) {
        for (; exp != 0; exp--) {
            ret = ret*2;
        }
    }

    if (sign) {
        ret = -ret;
    }

    return ret;
}

bool
ieee754_is_nan(u32 ie)
{
    if ((((ie & INF_PLUS) == INF_PLUS) || ((ie & INF_MINUS) == INF_MINUS)) && (ie & 0x7fffff)) {
        return TRUE;
    }

    return FALSE;
}

bool
ieee754_is_inf(u32 ie)
{
    if ((ie == INF_PLUS) || (ie == INF_MINUS))
        return TRUE;
    
    return FALSE;
}

bool 
float_is_nan(float f)
{
    return ieee754_is_nan(float_to_ieee754(f));
}

bool
float_is_inf(float f)
{
    return ieee754_is_inf(float_to_ieee754(f));
}

bool
float_is_valid(float f)
{
    return (!float_is_nan(f) && !float_is_inf(f));
}
