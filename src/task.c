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

#include "task.h"
#include "tinydht.h"

struct task *
task_new(struct dht *dht, struct pkt *pkt)
{
    struct task *task = NULL;
    
    ASSERT(dht && pkt);

    task = (struct task *) malloc(sizeof(struct task));
    if (!task) {
        return NULL;
    }

    bzero(task, sizeof(struct task));
    task->dht = dht;
    task->creation_time = dht_get_current_time();
    TAILQ_INIT(&task->pkt_list);
    TAILQ_INSERT_TAIL(&task->pkt_list, pkt, next);
    
    return task;
}

void
task_delete(struct task *task)
{
    free(task);
}
