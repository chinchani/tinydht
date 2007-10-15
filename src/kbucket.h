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

#ifndef __KBUCKET_H__
#define __KBUCKET_H__

#include "types.h"
#include "queue.h"
#include "node.h"
#include "key.h"
#include "debug.h"

#define KBUCKET_MAX_NODES       8   /* max. no. of nodes in a kbucket */

struct kbucket {
    int                             depth;
    int                             node_count;     /* no. of nodes in this kbucket */
    LIST_HEAD(node_list_head, node) node_list;
};

struct kbucket * kbucket_new(void);
void kbucket_delete(struct kbucket *k);

int kbucket_insert_node(struct kbucket *k, struct node *n);
int kbucket_index(struct key *self, struct key *k);
int kbucket_contains_node(struct kbucket *k, struct node *n);

#endif /* __KBUCKET_H__ */
