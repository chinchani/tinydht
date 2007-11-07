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

#ifndef __CRYPTO_H__
#define __CRYPTO_H__

#include <sys/types.h>
#include <assert.h>

#include "types.h"

#define CRYPTO_ASSERT   assert

#define CRYPTO_MAX_SEED_BYTES   16

struct dht_crypto_rnd_seed {
    u_int8_t    bytes[CRYPTO_MAX_SEED_BYTES];
} __attribute__ ((__packed__));

int crypto_init(void);
void crypto_exit(void);
int crypto_get_rnd_bytes(void *buf, int num);
int crypto_get_rnd_short(u16 *s);
int crypto_get_rnd_int(u32 *s);
int crypto_get_rnd_long(u64 *l);
int crypto_get_sha1_digest(void *data, int len, void *digest);

#endif /* __CRYPTO_H__ */
