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

#ifndef __TINYDHT_H__
#define __TINYDHT_H__

#include "types.h"
#include "task.h"

struct task;
struct task_list_head;

#define TINYDHT_SERVICE         ((u16)65521)

#define MAX_SERVICE_FD          2

#define MAX_DHT_INSTANCE        4
#define MAX_POLL_FD             16
#define MAX_DHT_NET_IF          MAX_DHT_INSTANCE

#define MAX_POLL_TIMEOUT        100     /* millisecs */

#define MAX_KEY_LEN             32
#define MAX_VAL_LEN             1024

/* Rate limiting */
#define RATE_LIMIT_BITS_PER_SEC (8*1024)

enum tinydht_action_type {
    TINYDHT_ACTION_UNKNOWN = 0,
    TINYDHT_ACTION_PUT,
    TINYDHT_ACTION_GET
};

enum tinydht_response_type {
    TINYDHT_RESPONSE_UNKNOWN = 0,
    TINYDHT_RESPONSE_SUCCESS,
    TINYDHT_RESPONSE_FAILURE
};

struct tinydht_msg_req {
    u8                          action;
    u32                         key_len;
    u8                          key[MAX_KEY_LEN];
    u32                         val_len;
    u8                          val[MAX_VAL_LEN];
} __attribute__ ((__packed__));

struct tinydht_msg_rsp {
    u8                          status;
    u32                         val_len;
    u8                          val[MAX_VAL_LEN];
} __attribute__ ((__packed__));

struct tinydht_msg {
    int                         sock;
    struct sockaddr_storage     from;
    size_t                      fromlen;
    struct tinydht_msg_req      req;
    struct tinydht_msg_rsp      rsp;
};

int tinydht_add_poll_fd(int fd);
int tinydht_add_task(struct task *task);
void tinydht_net_usage_update(size_t size);
bool tinydht_rate_limit_allow(void);

u64 tinydht_alloc_oid(void);
#endif /* __TINYDHT_H__ */
