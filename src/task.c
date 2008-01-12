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
    ASSERT(task && dht && pkt);

    bzero(task, sizeof(struct task));
    task->dht = dht;
    task->node = node;
    task->creation_time = dht_get_current_time();
    TAILQ_INIT(&task->pkt_list);
    TAILQ_INSERT_TAIL(&task->pkt_list, pkt, next);

    return SUCCESS;
}

size_t 
task_get_pkt_data_len(struct task *task)
{
    struct pkt *pkt = NULL;
    size_t len = 0;

    TAILQ_FOREACH(pkt, &task->pkt_list, next) {
        len += pkt->len;
    }

    return len;
}

