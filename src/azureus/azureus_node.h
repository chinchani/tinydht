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

#ifndef __AZUREUS_NODE_H__
#define __AZUREUS_NODE_H__

#include <netinet/in.h>
#include <arpa/inet.h>

#include "types.h"
#include "key.h"
#include "node.h"

enum azureus_node_status {
    AZUREUS_NODE_STATUS_UNKNOWN = 0xffffffff,
    AZUREUS_NODE_STATUS_ROUTABLE = 0x00000001
};

struct azureus_vivaldi_coords {
    float x, y, h;
};

struct azureus_node {
    struct node                     node;
    struct sockaddr_storage         ext_addr;
    enum azureus_node_status        node_status;
    u8                              proto_ver;
    u64                             skew;
    u32                             rnd_id;         /* anti-spoof */
    struct azureus_vivaldi_coords   viv;
};

struct azureus_node_serialized {
    struct sockaddr_storage         ext_addr;
    u32                             rnd_id;
} __attribute__ ((__packed__));

static inline struct azureus_node *
azureus_get_node_ref(struct node *node)
{
    return container_of(node, struct azureus_node, node);
}

struct azureus_node * azureus_node_new(u8 proto_ver, struct sockaddr_storage *ss);
void azureus_node_delete(struct azureus_node *n);

int azureus_node_get_id(struct key *k, struct sockaddr_storage *ss, u8 proto_ver);
int azureus_node_get_spoof_id(struct azureus_node *an, u32 *id);

#endif /* AZUREUS_NODE_H__ */
