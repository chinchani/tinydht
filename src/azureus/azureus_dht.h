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
    struct azureus_node         *bootstrap;
    struct kbucket              kbucket[160];
    u64                         cr_time;
    TAILQ_HEAD(azureus_new_node_list_head, azureus_node)        new_node_list;
    TAILQ_HEAD(azureus_task_list_head, task)                    task_list;
    TAILQ_HEAD(azureus_db_list_head, azureus_db_item)           db_list;
};

struct azureus_dht_mem_stats {
    int                         node;
    int                         msg;
    int                         task;
};

#define DHT_BOOTSTRAP_HOST      "dht.aelitis.com"
#define DHT_BOOTSTRAP_PORT      6881

#define AZUREUS_K               20      /* minimum no. of nodes in a kbucket */
#define AZUREUS_W               4

#define AZUREUS_RPC_TIMEOUT     ((u64)20*1000*1000)
/* 20 seconds */

#define MAX_RPC_RETRIES         0
#define MAX_RPC_FAILURES        3

#define PING_TIMEOUT            ((u64)15*60*1000*1000)          
/* 15 minutes */
#define FIND_NODE_TIMEOUT       PING_TIMEOUT
#define KBUCKET_REFRESH_TIMEOUT PING_TIMEOUT

/* Rate limiting */
#define DHT_STABLE_TEST_WINDOW  AZUREUS_RPC_TIMEOUT
#define RATE_LIMIT_BITS_PER_SEC (5*1024)

/*-------------------------------------------------------------
 *
 *      Static functions
 *
 *------------------------------------------------------------*/

static inline struct azureus_dht *
azureus_dht_get_ref(struct dht *dht)
{
    return container_of(dht, struct azureus_dht, dht);
}

/*-------------------------------------------------------------
 *
 *      Function declarations
 *
 *------------------------------------------------------------*/

struct dht * azureus_dht_new(struct dht_net_if *nif, int port);
void azureus_dht_delete(struct dht *dht);
int azureus_dht_put(struct dht *dht, struct tinydht_msg *msg);
int azureus_dht_get(struct dht *dht, struct tinydht_msg *msg);
int azureus_dht_task_schedule(struct dht *dht);
int azureus_dht_rpc_rx(struct dht *dht, struct sockaddr_storage *from, 
                    size_t fromlen, u8 *data, int len, u64 timestamp);
void azureus_dht_exit(struct dht *dht);

#endif /* __AZUREUS_DHT_H__ */
