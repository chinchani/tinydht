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

#ifndef __KBUCKET_H__
#define __KBUCKET_H__

#include "types.h"
#include "queue.h"
#include "node.h"
#include "key.h"
#include "debug.h"

struct kbucket {
    int         depth;
    int         n_nodes;     /* no. of nodes in this kbucket */
    LIST_HEAD(kbucket_node_list_head, node)     node_list;
    int         n_ext_nodes;
    LIST_HEAD(kbucket_ext_node_list_head, node) ext_node_list;
};

TAILQ_HEAD(kbucket_node_search_list_head, node);

int kbucket_new(struct kbucket *k);

int kbucket_insert_node(struct kbucket *k, struct node *n, int max_nodes);
struct node * kbucket_delete_node(struct kbucket *k, struct node *n);
int kbucket_index(struct key *self, struct key *k);
int kbucket_contains_node(struct kbucket *k, struct node *n);
struct node * kbucket_get_node(struct kbucket *k, struct key *key);

#endif /* __KBUCKET_H__ */
