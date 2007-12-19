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
    int (*rpc_rx)(struct dht *dht, struct sockaddr_storage *from, 
                    size_t fromlen, u8 *data, int len, u64 timestamp);
    int (*task_schedule)(struct dht *dht);
    void (*exit)(struct dht *dht);
};

#define MAX_DHT_TYPE    4
extern struct dht_prototype *dht_table[MAX_DHT_TYPE];

#endif /* __DHT_TYPES_H__ */
