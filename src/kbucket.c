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

#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "kbucket.h"

struct kbucket *
kbucket_new(void)
{
    struct kbucket *k = NULL;

    k = (struct kbucket *) malloc(sizeof(struct kbucket));
    if (!k) {
        return NULL;
    }

    bzero(k, sizeof(struct kbucket));
    k->node_count = 0;
    LIST_INIT(&k->node_list);

    return k;
}

void
kbucket_delete(struct kbucket *k)
{
    free(k);
}

int
kbucket_insert_node(struct kbucket *k, struct node *n)
{
    ASSERT(k && n);

    if (kbucket_contains_node(k, n)) {
        return SUCCESS;
    }
    
    if (k->node_count < KBUCKET_MAX_NODES) {
        LIST_INSERT_HEAD(&k->node_list, n, next);
        return SUCCESS;
    }

    LIST_INSERT_HEAD(&k->node_list, n, next);

#if 0
    /* FIXME: let each dht_instance handle this is its own way! */
    LIST_FOREACH(tn, &k->node_list, next) {
        switch (tn->state) {
            case NODE_STATE_GOOD:
                continue;
            case NODE_STATE_BAD:
                // list_delete(&tn->list, &k->node_list);
                LIST_INSERT_HEAD(&k->node_list, n, next);
                // list_add_tail(&n->list, &k->node_list);
                break;
            case NODE_STATE_QUESTIONABLE:
                /* FIXME: create a new ping task, and return */
                break;
            default:
                ASSERT(0);
                break;
        }
    }
#endif
    
    return SUCCESS;
}

int
kbucket_contains_node(struct kbucket *k, struct node *n)
{
    struct node *tn = NULL;

    LIST_FOREACH(tn, &k->node_list, next) {
        if (key_cmp(&tn->id, &n->id) == 0) {
            return TRUE;
        }
    }

    return FALSE;
}

int
kbucket_index(struct key *self, struct key *k)
{
    struct key xor;
    int index;
    int ret;

    ASSERT(self && k);
    
    ret = key_xor(self, k, &xor);

    for (index = 0; index < k->len; index++) {
        if (key_nth_bit(&xor, (k->len - 1) - index) != 0)
            break;
    }

    key_delete(&xor);

    return index;
}
