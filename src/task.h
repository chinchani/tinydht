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

#ifndef __TASK_H__
#define __TASK_H__

#include "dht.h"
#include "pkt.h"
#include "queue.h"

enum task_state {
    TASK_STATE_UNKNOWN = 0,
    TASK_STATE_RUNNABLE,
    TASK_STATE_WAIT,
    TASK_STATE_MAX
};

struct task {
    enum task_state                     state;
    u64                                 creation_time;
    u64                                 access_time;
    struct dht                          *dht;
    TAILQ_HEAD(pkt_list_head, pkt)      pkt_list;
    TAILQ_ENTRY(task)                   next;
};

struct task *task_new(struct dht *dht, struct pkt *pkt);
void task_delete(struct task *task);

#endif /* __TASK_H__ */
