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

#ifndef __AZUREUS_DHT_H__
#define __AZUREUS_DHT_H__

#include "types.h"
#include "dht.h"
#include "task.h"
#include "kbucket.h"
#include "queue.h"
#include "azureus_node.h"
#include "azureus_db.h"

struct azureus_dht {
    struct dht                  dht;
    u32                         trans_id;
    u8                          proto_ver;
    u32                         network;
    u32                         instance_id;
    u32                         est_dht_size;
    struct azureus_node         *this_node;
    TAILQ_HEAD(azureus_db_list_head, azureus_db_item)   db_list;
    TAILQ_HEAD(azureus_task_list_head, task)            task_list;
    TAILQ_HEAD(azureus_node_list_head, azureus_node)    new_node_list;
    struct kbucket              kbucket[160];
};

static inline struct azureus_dht *
azureus_dht_get_ref(struct dht *dht)
{
    return container_of(dht, struct azureus_dht, dht);
}

#define DHT_BOOTSTRAP_HOST      "dht.aelitis.com"
#define DHT_BOOTSTRAP_PORT      6881

#define AZUREUS_K               20      /* minimum no. of nodes in a kbucket */
#define AZUREUS_W               4

#define MAX_RPC_RETRIES         1

#define MAX_PING_TIMEOUT        60*1000*1000
#define MAX_FIND_NODE_TIMEOUT   60*1000*1000

struct dht * azureus_dht_new(struct dht_net_if *nif, int port);
void azureus_dht_delete(struct dht *dht);
int azureus_dht_put(struct dht *dht, struct tinydht_msg *msg);
int azureus_dht_get(struct dht *dht, struct tinydht_msg *msg);
int azureus_task_schedule(struct dht *dht);
int azureus_rpc_rx(struct dht *dht, struct sockaddr_storage *from, 
                    size_t fromlen, u8 *data, int len, u64 timestamp);

#endif /* __AZUREUS_DHT_H__ */
