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

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <netdb.h>
extern int h_errno;

#include <errno.h>
extern int errno;

#include "azureus_dht.h"
#include "azureus_node.h"
#include "dht_types.h"
#include "types.h"
#include "crypto.h"
#include "azureus_rpc.h"
#include "azureus_db.h"
#include "task.h"
#include "tinydht.h"
#include "queue.h"
#include "kbucket.h"

static int azureus_rpc_tx(struct dht *dht, struct task *task, 
                            struct azureus_rpc_msg *msg);
static int azureus_dht_add_ping_task(struct azureus_dht *ad, 
                            struct azureus_node *an);
static int azureus_dht_add_find_node_task(struct azureus_dht *ad, 
                            struct azureus_node *an, struct key *node_id);
static int azureus_dht_add_node(struct azureus_dht *ad, 
                            struct azureus_node *an);

struct dht *
azureus_dht_new(struct dht_net_if *nif, int port)
{
    struct azureus_dht *ad = NULL;
    struct sockaddr_storage ss;
    struct hostent *he = NULL;
    struct azureus_node *bootstrap = NULL;
    int ret;

    ad = (struct azureus_dht *) malloc(sizeof(struct azureus_dht));
    if (!ad) {
        return NULL;
    }

    /* initialize parent base class */
    ret = dht_new(&ad->dht, DHT_TYPE_AZUREUS, nif, port);
    if (ret != SUCCESS) {
        azureus_dht_delete(&ad->dht);
        return NULL;
    }

    /* initialize the task list */
    TAILQ_INIT(&ad->task_list);

    /* initialize the database */
    TAILQ_INIT(&ad->db_list);

    /* initialize the new node list */
    TAILQ_INIT(&ad->new_node_list);

    /* initialize Azureus specific stuff */
    ad->proto_ver = PROTOCOL_VERSION_MAIN;
    ret = crypto_get_rnd_int(&ad->trans_id);
    if (ret != SUCCESS) {
        azureus_dht_delete(&ad->dht);
        return NULL;
    }
    
    ret = crypto_get_rnd_int(&ad->instance_id);
    if (ret != SUCCESS) {
        azureus_dht_delete(&ad->dht);
        return NULL;
    }

    bzero(&ss, sizeof(ss));
    memcpy(&ss, &ad->dht.net_if.ext_addr, sizeof(struct sockaddr_storage));
    switch (ss.ss_family) {
        case AF_INET:
            ((struct sockaddr_in *)&ss)->sin_port = port;
            break;
        case AF_INET6:
            ((struct sockaddr_in6 *)&ss)->sin6_port = port;
            break;
        default:
            azureus_dht_delete(&ad->dht);
            return NULL;
    }

    ad->this_node = azureus_node_new(ad->proto_ver, &ss);
    if (!ad->this_node) {
        azureus_dht_delete(&ad->dht);
        return NULL;
    }

    /* initialize the network position of this node */
    azureus_vivaldi_pos_new(&ad->this_node->netpos, 
                            POSITION_TYPE_VIVALDI_V1, 0.0f, 0.0f, 0.0f);


    /* bootstrap from "dht.aelitis.com:6881" */
    he = gethostbyname(DHT_BOOTSTRAP_HOST);
    if (!he) {
        ERROR("%s\n", hstrerror(h_errno));
        azureus_dht_delete(&ad->dht);
        return NULL;
    }

    bzero(&ss, sizeof(ss));
    ss.ss_family = AF_INET;
    memcpy(&(((struct sockaddr_in *)&ss)->sin_addr), he->h_addr, 
                sizeof(struct in_addr));
    ((struct sockaddr_in *)&ss)->sin_port = htons(DHT_BOOTSTRAP_PORT);

    bootstrap = azureus_node_new(PROTOCOL_VERSION_MAIN, &ss);
    if (!bootstrap) {
        return NULL;
    }

    azureus_dht_add_node(ad, bootstrap);

    /* send a PING, but don't expect any response */
    azureus_dht_add_ping_task(ad, bootstrap);

    /* send a FIND_NODE on my own node-id */
    azureus_dht_add_find_node_task(ad, bootstrap, &ad->this_node->node.id);

    INFO("Azureus DHT listening on port %hu\n", ntohs(ad->dht.port));

    return &ad->dht;
}

void
azureus_dht_delete(struct dht *dht)
{
    struct azureus_dht *ad = NULL;

    ad = azureus_dht_get_ref(dht);
    free(ad);

    return;
}

void
azureus_task_delete(struct task *task)
{
    struct azureus_dht *ad = NULL;
    struct pkt *pkt = NULL;
    struct azureus_rpc_msg *msg = NULL;

    ASSERT(task);

    ad = azureus_dht_get_ref(task->dht);

    TAILQ_REMOVE(&ad->task_list, task, next);
    DEBUG("Deleted task %p\n", task);

    TAILQ_FOREACH(pkt, &task->pkt_list, next) {
        msg = azureus_rpc_msg_get_ref(pkt);
        azureus_rpc_msg_delete(msg);
    }

    task_delete(task);

    return;
}

int 
azureus_task_schedule(struct dht *dht)
{
    struct azureus_dht *ad = NULL;
    struct azureus_rpc_msg *msg = NULL;
    struct pkt *pkt = NULL;
    struct task *task = NULL;
    struct azureus_node *an = NULL;
    int ret;

    ASSERT(dht);

    ad = azureus_dht_get_ref(dht);

    /* process the new node list */
    TAILQ_FOREACH(an, &ad->new_node_list, next) {
        TAILQ_REMOVE(&ad->new_node_list, an, next);
        azureus_dht_add_ping_task(ad, an);
        /* FIXME: Should we adding this to the kbucket right away? */
    }

    TAILQ_FOREACH(task, &ad->task_list, next) {
        if (task->state == TASK_STATE_WAIT) {
            /* was there a timeout? */
            if ((dht_get_current_time() - task->access_time) 
                                            < AZUREUS_RPC_TIMEOUT) {
                /* this task hasn't timed out yet, so wait some more! */
                continue;
            }

            if (task->retries == 0) {
                DEBUG("task timed out\n");
                /* FIXME: this deletion here is not correct! */
                azureus_task_delete(task);      
                continue;
            } else {
                DEBUG("retrying task\n");
                task->retries--;
            }
        }

        pkt = TAILQ_FIRST(&task->pkt_list);
        msg = azureus_rpc_msg_get_ref(pkt);

        DEBUG("pkt->dir %d\n", pkt->dir);
        DEBUG("msg->action %d\n", msg->action);

        switch (pkt->dir) {
            case PKT_DIR_RX:
                DEBUG("RX\n");
                break;

            case PKT_DIR_TX:
                DEBUG("TX\n");
                pkt_reset_data(&msg->pkt);
                ret = azureus_rpc_encode(msg);
                if (ret != SUCCESS) {
                    return FAILURE;
                }

                azureus_rpc_tx(dht, task, msg);

                break;

            default:
                return FAILURE;
        }
    }

    return SUCCESS;
}

static int
azureus_rpc_tx(struct dht *dht, struct task *task, struct azureus_rpc_msg *msg)
{
    int ret;

    ASSERT(dht && msg);

    ret = sendto(dht->net_if.sock, msg->pkt.data, msg->pkt.len, 0, 
                (struct sockaddr *)&msg->pkt.ss, sizeof(struct sockaddr_in));
    if (ret < 0) {
        ERROR("sendto() - %s\n", strerror(errno));
        return FAILURE;
    }

    DEBUG("sending %d bytes to %s/%hu\n", 
            ret,
            inet_ntoa(((struct sockaddr_in *)&msg->pkt.ss)->sin_addr),
            ntohs(((struct sockaddr_in *)&msg->pkt.ss)->sin_port));

    task->state = TASK_STATE_WAIT;
    task->access_time = dht_get_current_time();

    return SUCCESS;
}

int
azureus_rpc_rx(struct dht *dht, struct sockaddr_storage *from, size_t fromlen,
                    u8 *data, int len, u64 timestamp)
{
    struct azureus_dht *ad = NULL;
    struct azureus_rpc_msg *msg = NULL, *msg1 = NULL;
    struct pkt *pkt = NULL;
    struct task *task = NULL;
    struct azureus_node *an = NULL;
    bool found = FALSE;
    float rtt = 0.0;
    int i;
    int ret;

    ASSERT(dht && from && data);

    ad = azureus_dht_get_ref(dht);

    /* decode the reply */
    ret = azureus_rpc_decode(dht, from, fromlen, data, len, &msg);
    if (ret != SUCCESS) {
        return ret;
    }

    if (msg->is_req) {  /* REQUEST */
        /* create a response and send */

    } else {            /* REPLY   */
        /* look for a matching request */
        TAILQ_FOREACH(task, &ad->task_list, next) {
            pkt = TAILQ_FIRST(&task->pkt_list);
            msg1 = azureus_rpc_msg_get_ref(pkt);
            if (azureus_rpc_match_req_rsp(msg1, msg)) {
                found = TRUE;
                break;
            }
        }

        if (!found) {
            /* drop this response! */
            ERROR("dropped response\n");
            azureus_rpc_msg_delete(msg);
            return SUCCESS;
        }

        switch (msg->action) {

            case ACT_REPLY_PING:
                an = azureus_node_get_ref(task->node);

                memcpy(&an->netpos, &msg->viv_pos[0], 
                            sizeof(struct azureus_vivaldi_pos));

                rtt = 1.0*(timestamp - task->access_time)/1000000;
                DEBUG("RTT %f\n", rtt);

                for (i = 0; i < msg->n_viv_pos; i++) {
                    if (msg->viv_pos[i].type != POSITION_TYPE_VIVALDI_V1) {
                        continue;
                    }
                    azureus_vivaldi_v1_update(&ad->this_node->netpos, rtt, 
                                                &msg->viv_pos[i], 
                                                msg->viv_pos[i].v.v1.err); 
                    break;
                }

                TAILQ_REMOVE(&ad->new_node_list, an, next);
                DEBUG("delete from new node list %p\n", an);

                azureus_dht_add_node(ad, an);

                azureus_dht_add_find_node_task(ad, an, &ad->this_node->node.id);

                break;

            case ACT_REPLY_FIND_NODE:
                /* if the reply contained new nodes, 
                 * add them to the new node list */
                while (msg->m.find_node_rsp.node_list.tqh_first != NULL) {
                    an = TAILQ_FIRST(&msg->m.find_node_rsp.node_list);
                    TAILQ_REMOVE(&msg->m.find_node_rsp.node_list, 
                            msg->m.find_node_rsp.node_list.tqh_first, next);
                    TAILQ_INSERT_TAIL(&ad->new_node_list, an, next);
                    DEBUG("new node %p\n", an);
                }
                break;

            case ACT_REPLY_FIND_VALUE:
                TAILQ_FOREACH(an, &msg->m.find_value_rsp.node_list, next) {
                    TAILQ_INSERT_TAIL(&ad->new_node_list, an, next);
                }
                break;

            default:
                break;
        }

        azureus_task_delete(task);
    }

    return SUCCESS;
}

int
azureus_dht_put(struct dht *dht, struct tinydht_msg *msg)
{
    struct azureus_db_item *item = NULL;
    struct azureus_dht *ad = NULL;
    int ret;
    size_t off, len;

    INFO("PUT received\n");

    if (!dht || (msg->req.key_len <= 0) || (msg->req.val_len <= 0)) {
        return FAILURE;
    }

    if (msg->req.key_len > AZUREUS_MAX_KEY_LEN) {
        return FAILURE;
    }

    if ((msg->req.val_len/AZUREUS_MAX_VAL_LEN) > AZUREUS_MAX_VALS_PER_KEY) {
        return FAILURE;
    }

    ad = azureus_dht_get_ref(dht);

    /* delete a duplicate! */
    TAILQ_FOREACH(item, &ad->db_list, next) {
        if (azureus_db_item_match_key(item, msg->req.key, msg->req.key_len)) {
            DEBUG("key already exists - deleting item\n");
            azureus_db_item_delete(item);
            break;
        }
    }

    item = azureus_db_item_new(ad);
    if (!item) {
        return FAILURE;
    }

    ret = azureus_db_item_set_key(item, msg->req.key, msg->req.key_len);
    if (ret != SUCCESS) {
        free(item);
        return ret;
    }

    off = 0;
    while (off < msg->req.val_len) {
        len = (msg->req.val_len - off) >= AZUREUS_MAX_VAL_LEN ? 
                    AZUREUS_MAX_VAL_LEN : (msg->req.val_len - off);
        ret = azureus_db_item_add_val(item, &msg->req.val[off], len);
        if (ret != SUCCESS) {
            azureus_db_item_delete(item);
            return ret;
        }

        off += len;
    }

    ASSERT(off == msg->req.val_len);

    TAILQ_INSERT_TAIL(&ad->db_list, item, next);

    DEBUG("PUT successful\n");

    return SUCCESS;
}

int
azureus_dht_get(struct dht *dht, struct tinydht_msg *msg)
{
    struct azureus_db_item *item = NULL;
    struct azureus_dht *ad = NULL;
    struct azureus_db_val *v = NULL;
    size_t off;

    INFO("GET received\n");

    if (!dht || (msg->req.key_len <= 0) || (msg->req.key_len > 32)) {
        return FAILURE;
    }

    if (msg->req.key_len > AZUREUS_MAX_KEY_LEN) {
        return FAILURE;
    }

    ad = azureus_dht_get_ref(dht);

    TAILQ_FOREACH(item, &ad->db_list, next) {
        if (azureus_db_item_match_key(item, msg->req.key, msg->req.key_len)) {
            off = 0;
            TAILQ_FOREACH(v, &item->valset.val_list, next) {
                memcpy(&msg->rsp.val[off], v->data, v->len);
                off += v->len;
            }
            msg->rsp.val_len = off;
            DEBUG("GET successful\n");
            return SUCCESS;
        }
    }

    return FAILURE;
}

static int
azureus_dht_add_ping_task(struct azureus_dht *ad, struct azureus_node *an)
{
    struct azureus_rpc_msg *msg = NULL;
    struct task *task = NULL;

    ASSERT(ad && an);

    msg = azureus_rpc_msg_new(&ad->dht, &an->ext_addr, 
                                sizeof(struct sockaddr_storage), NULL, 0);
    if (!msg) {
        return FAILURE;
    }

    msg->action = ACT_REQUEST_PING;
    msg->pkt.dir = PKT_DIR_TX;

    task = task_new(&ad->dht, &msg->pkt);
    if (!task) {
        azureus_rpc_msg_delete(msg);
        return FAILURE;
    }
    task->node = &an->node;
    task->retries = MAX_RPC_RETRIES;

    TAILQ_INSERT_TAIL(&ad->task_list, task, next);
    DEBUG("Added new task %p\n", task);

    return SUCCESS;
}

static int
azureus_dht_add_find_node_task(struct azureus_dht *ad, struct azureus_node *an,
                                    struct key *node_id)
{
    struct azureus_rpc_msg *msg = NULL;
    struct task *task = NULL;

    ASSERT(ad && an && node_id);

    msg = azureus_rpc_msg_new(&ad->dht, &an->ext_addr, 
                                sizeof(struct sockaddr_storage), NULL, 0);
    if (!msg) {
        return FAILURE;
    }

    msg->action = ACT_REQUEST_FIND_NODE;
    msg->pkt.dir = PKT_DIR_TX;
    msg->m.find_node_req.id_len = node_id->len;
    memcpy(msg->m.find_node_req.id, node_id->data, node_id->len);

    task = task_new(&ad->dht, &msg->pkt);
    if (!task) {
        azureus_rpc_msg_delete(msg);
        return FAILURE;
    }

    task->node = &an->node;
    task->retries = MAX_RPC_RETRIES;

    TAILQ_INSERT_TAIL(&ad->task_list, task, next);

    return SUCCESS;
}

static int
azureus_dht_add_node(struct azureus_dht *ad, struct azureus_node *an)
{
    int index = 0;
    int ret;

    index = kbucket_index(&ad->this_node->node.id, &an->node.id);

    key_dump(&ad->this_node->node.id);
    key_dump(&an->node.id);
    DEBUG("index %d\n", index);

    ret = kbucket_insert_node(&ad->kbucket[index], &an->node);

    return SUCCESS;
}

