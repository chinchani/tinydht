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

#ifndef __AZUREUS_TASK_H__
#define __AZUREUS_TASK_H__

struct azureus_rpc_msg;

#include "task.h"
#include "azureus_dht.h"
#include "azureus_node.h"
#include "azureus_db.h"

struct azureus_task {
    struct task                 task;
    int                         retries;
    struct azureus_dht          *dht;
    struct azureus_db_item      *db_item;
    TAILQ_ENTRY(azureus_task)   next;
    TAILQ_HEAD(azureus_db_node_list_head, azureus_node)    db_node_list;
};

struct azureus_task * azureus_task_new(struct azureus_dht *ad, 
                                        struct azureus_node *an,
                                        struct azureus_rpc_msg *msg);
void azureus_task_delete(struct azureus_task *at);

#endif /* __AZUREUS_TASK_H__ */
