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

#include <string.h>

#include "azureus_task.h"
#include "azureus_dht.h"
#include "azureus_rpc.h"

struct azureus_task *
azureus_task_new(struct azureus_dht *ad, struct azureus_node *an, 
                    struct azureus_rpc_msg *msg)
{
    struct azureus_task *at = NULL;

    ASSERT(ad && an && msg);

    at = (struct azureus_task *) malloc(sizeof(struct azureus_task));
    if (!at) {
        return NULL;
    }

    ad->stats.mem.task++;

    bzero(at, sizeof(struct azureus_task));

    task_new(&at->task, &ad->dht, &an->node, &msg->pkt);
    at->retries = MAX_RPC_RETRIES;
    at->dht = ad;
    an->task_pending = TRUE;

    return at;
}

void
azureus_task_delete(struct azureus_task *at)
{
    struct task *task = NULL;
    struct pkt *pkt = NULL, *pktn = NULL;
    struct azureus_node *an = NULL;
    struct azureus_rpc_msg *msg = NULL;
    struct azureus_dht *ad = NULL;

    ASSERT(at);

    ad = at->dht;

    task = &at->task;
    pkt = task->pkt;
    msg = azureus_rpc_msg_get_ref(pkt);
    azureus_rpc_msg_delete(msg);

    an = azureus_node_get_ref(task->node);
    an->task_pending = FALSE;

    free(at);
    ad->stats.mem.task--;
}
