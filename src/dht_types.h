/***************************************************************************
 *   Copyright (C) 2007 by Saritha Kalyanam   				   *
 *   sk.tinydht@gmail.com   						   *
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

#ifndef __DHT_TYPES_H__
#define __DHT_TYPES_H__

#include "dht.h"
#include "task.h"
#include "tinydht.h"

enum dht_type {
    DHT_TYPE_UNKNOWN = 0,
    DHT_TYPE_AZUREUS,
    DHT_TYPE_MAX
};

struct dht_prototype {
    enum dht_type       type;
    struct dht * (*constructor)(struct dht_net_if *nif, int port);
    void (*destructor)(struct dht *dht);
    int (*get)(struct dht *dht, struct tinydht_msg *msg);
    int (*put)(struct dht *dht, struct tinydht_msg *msg);
    int (*decode_rpc)(struct dht *dht, struct sockaddr_storage *from, 
                        size_t fromlen, u8 *data, int len);
    int (*task_schedule)(struct task *task);
};

#define MAX_DHT_TYPE    4
extern struct dht_prototype *dht_table[MAX_DHT_TYPE];

#endif /* __DHT_TYPES_H__ */
