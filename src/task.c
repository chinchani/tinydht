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
    ASSERT(task && dht && node);

    bzero(task, sizeof(struct task));
    task->node = node;
    task->creation_time = dht_get_current_time();
    task->type = TASK_TYPE_CHILD;
    if (pkt) {
        task->pkt = pkt;
    }

    TAILQ_INIT(&task->child_list);

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

bool
task_contains_child_task(struct task *parent, struct task *child)
{
    struct task *t = NULL;

    ASSERT(parent && child);

    TAILQ_FOREACH(t, &parent->child_list, next_child) {
        if (t == child) {
            return TRUE;
        }
    }

    return FALSE;
}

int
task_add_child_task(struct task *parent, struct task *child)
{
    ASSERT(parent && child);

    DEBUG("%p %p\n", parent, child);

    if (task_contains_child_task(parent, child)) {
        ASSERT(0);
    }

    /* FIXME: do we need to check if this task already exists */
    TAILQ_INSERT_TAIL(&parent->child_list, child, next_child);
    if (!task_contains_child_task(parent, child)) {
        ASSERT(0);
    }
    parent->n_child++;

    child->parent = parent;
    parent->type = TASK_TYPE_PARENT;

    return SUCCESS;
}

int
task_delete_child_task(struct task *child)
{
    struct task *parent = NULL;

    ASSERT(child);

    parent = child->parent;
    ASSERT(parent);

    if (!task_contains_child_task(parent, child)) {
        ASSERT(0);
    }

    TAILQ_REMOVE(&parent->child_list, child, next_child);
    if (task_contains_child_task(parent, child)) {
        ASSERT(0);
    }
    parent->n_child--;
    child->parent = NULL;

    DEBUG("parent %p child %p child->parent %p parent->n_child %d\n", 
            parent, child, child->parent, parent->n_child);

    return SUCCESS;
}
