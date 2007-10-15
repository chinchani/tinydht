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

#include <stdio.h>
#include <string.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/time.h>

#include "dht.h"
#include "dht_types.h"
#include "tinydht.h"
#include "crypto.h"

int
dht_net_if_new(struct dht_net_if *net_if, 
                const char *ifname, struct sockaddr *addr, size_t addrlen)
{
    bzero(net_if, sizeof(struct dht_net_if));
    memcpy(net_if->ifname, ifname, IFNAMSIZ);
    memcpy(&net_if->local_addr, addr, addrlen);
    return SUCCESS;
}

int
dht_new(struct dht *dht, unsigned int type, 
                    struct dht_net_if *net_if, short port)
{
    struct sockaddr_in addr4;
    struct sockaddr_in6 addr6;
    int sock;
    int sa_family;
    int i;
    int ret = SUCCESS;

    bzero(dht, sizeof(struct dht));
    dht->type = type;
    memcpy(&dht->net_if, net_if, sizeof(struct dht_net_if));
    dht->port = port;

    sa_family = ((struct sockaddr *)&net_if->local_addr)->sa_family;

    switch (sa_family) {
        case AF_INET:
            bzero(&addr4, sizeof(struct sockaddr_in));
            memcpy(&addr4, &net_if->local_addr, sizeof(struct sockaddr_in));
            addr4.sin_port = port;

            sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
            if (sock < 0) {
                goto err;
            }

            ret = bind(sock, (struct sockaddr *)&addr4, 
                                    sizeof(struct sockaddr_in));
            if (ret < 0) {
                goto err;
            }

            ret = tinydht_add_poll_fd(sock);
            if (ret != SUCCESS) {
                goto err;
            }

            dht->net_if.sock = sock;

            break;

        case AF_INET6:
            bzero(&addr6, sizeof(struct sockaddr_in6));
            memcpy(&addr6, &net_if->local_addr, sizeof(struct sockaddr_in6));
            addr6.sin6_port = port;

            sock = socket(PF_INET6, SOCK_DGRAM, IPPROTO_UDP);
            if (sock < 0) {
                goto err;
            }

            ret = bind(sock, (struct sockaddr *)&addr6, 
                                    sizeof(struct sockaddr_in6));
            if (ret < 0) {
                goto err;
            }

            ret = tinydht_add_poll_fd(sock);
            if (ret != SUCCESS) {
                goto err;
            }

            dht->net_if.sock = sock;

            break;

        default:
            goto err;
    }

#if 0
    sa_family = ((struct sockaddr *)&net_if->ext_addr)->sa_family;

    switch (sa_family) {
        case AF_INET:
            ((struct sockaddr_in *)&net_if->ext_addr)->sin_port = port;
            ((struct sockaddr_in *)&net_if->local_addr)->sin_port = port;
            break;

        case AF_INET6:
            ((struct sockaddr_in6 *)&net_if->ext_addr)->sin6_port = port;
            ((struct sockaddr_in6 *)&net_if->local_addr)->sin6_port = port;
            break;

        default:
            goto err;
    }
#endif

    for (i = 0; (i < MAX_DHT_TYPE) && dht_table[i]; i++) {
        if (dht_table[i]->type == type) {
            dht->get = dht_table[i]->get;
            dht->put = dht_table[i]->put;
            dht->decode_rpc = dht_table[i]->decode_rpc;
            dht->task_schedule = dht_table[i]->task_schedule;
            break;
        }
    }

    return SUCCESS;

err:
    return FAILURE;
}

u64
dht_get_current_time(void)
{
    struct timeval tv;
    int ret;

    bzero(&tv, sizeof(struct timeval));
    ret = gettimeofday(&tv, NULL);
    if (ret < 0) {
        return 0;
    }

    return ((u64)1*tv.tv_sec*1000*1000 + tv.tv_usec);
}

