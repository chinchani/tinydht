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

#include "task.h"
#include "tinydht.h"

int
task_new(struct task *task, struct dht *dht, struct node *node, struct pkt *pkt)
{
    ASSERT(task && dht && node && pkt);

    bzero(task, sizeof(struct task));
    task->node = node;
    task->creation_time = dht_get_current_time();
    task->pkt = pkt;

    return SUCCESS;
}

size_t 
task_get_pkt_data_len(struct task *task)
{
    struct pkt *pkt = NULL;
    size_t len = 0;

    ASSERT(task);

    len += pkt->len;

#if 0
    TAILQ_FOREACH(pkt, &task->pkt_list, next) {
        len += pkt->len;
    }
#endif

    return len;
}

int
task_add_child_task(struct task *parent, struct task *child)
{
    ASSERT(parent && child);

    /* FIXME: do we need to check if this task already exists */
    TAILQ_INSERT_TAIL(&parent->child_list, child, child_next);
    parent->n_child++;

    child->parent = parent;

    return SUCCESS;
}

int
task_remove_child_task(struct task *child)
{
    struct task *parent = NULL;
    struct task *tn = NULL, *tnn = NULL;

    ASSERT(child);

    parent = child->parent;
    ASSERT(parent);

    TAILQ_FOREACH_SAFE(tn, &parent->child_list, child_next, tnn) {
        if (tn == child) {
            TAILQ_REMOVE(&parent->child_list, tn, child_next);
            break;
        }
    }

    return SUCCESS;
}
