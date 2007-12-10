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

#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "kbucket.h"

int 
kbucket_new(struct kbucket *k)
{
    ASSERT(k);

    bzero(k, sizeof(struct kbucket));
    k->node_count = 0;
    LIST_INIT(&k->node_list);

    return SUCCESS;
}

int
kbucket_insert_node(struct kbucket *k, struct node *n)
{
    ASSERT(k && n);

    if (kbucket_contains_node(k, n)) {
        return SUCCESS;
    }
    
    LIST_INSERT_HEAD(&k->node_list, n, kb_next);
    k->node_count++;

    return SUCCESS;
}

struct node *
kbucket_delete_node(struct kbucket *k, struct node *n)
{
    struct node *tn = NULL, *tnn = NULL;

    LIST_FOREACH_SAFE(tn, &k->node_list, kb_next, tnn) {
        if (key_cmp(&tn->id, &n->id) == 0) {
            LIST_REMOVE(tn, kb_next);
            return tn;
        }
    }

    return NULL;
}

int
kbucket_contains_node(struct kbucket *k, struct node *n)
{
    struct node *tn = NULL, *tnn = NULL;

    LIST_FOREACH_SAFE(tn, &k->node_list, kb_next, tnn) {
        if (key_cmp(&tn->id, &n->id) == 0) {
            return TRUE;
        }
    }

    return FALSE;
}

int
kbucket_index(struct key *self, struct key *k)
{
    struct key  xor;
    int         index;
    int         max_index;
    int         ret;

    ASSERT(self && k);
    
    ret = key_distance(self, k, &xor);

    max_index = k->len*8*sizeof(k->data[0]);
    ASSERT(max_index == 160);

    for (index = (max_index - 1); index >= 0; index--) {
        if (key_nth_bit(&xor, index) != 0) {
            break;
        }
    }

    if (index < 0) {
        index = 0;
    }

    return (max_index - 1) - index;
}
