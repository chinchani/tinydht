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
#include "node.h"
#include "azureus_vivaldi.h"
#include "azureus_task.h"

/*********************** Function Prototypes ***********************/

static int azureus_dht_rpc_tx(struct azureus_dht *ad, struct task *task, 
                            struct azureus_rpc_msg *msg);

static int azureus_dht_add_task(struct azureus_dht *ad, 
                            struct azureus_task *at);
static int azureus_dht_delete_task(struct azureus_dht *ad, 
                            struct azureus_task *at);
static int azureus_dht_add_ping_task(struct azureus_dht *ad, 
                            struct azureus_node *an);
static int azureus_dht_add_find_node_task(struct azureus_dht *ad, 
                            struct azureus_node *an, struct key *node_id);

static int azureus_dht_add_node(struct azureus_dht *ad, 
                            struct azureus_node *an);
static int azureus_dht_delete_node(struct azureus_dht *ad, 
                            struct azureus_node *an);
static struct azureus_node * azureus_dht_get_node(struct azureus_dht *ad, 
                                                struct sockaddr_storage *ss, 
                                                u8 proto_ver);
static bool azureus_dht_contains_node(struct azureus_dht *ad, 
                                struct azureus_node *an);

static int azureus_dht_get_k_closest_nodes(struct azureus_dht *ad, 
                                struct key *key, int k,
                                struct kbucket_node_search_list_head *list, 
                                int *n_list);
static int azureus_dht_get_node_count(struct azureus_dht *ad);

static int azureus_dht_kbucket_refresh(struct azureus_dht *ad);
static int azureus_dht_db_refresh(struct azureus_dht *ad);

static bool azureus_dht_is_stable(struct azureus_dht *ad);
static int azureus_dht_add_db_item(struct azureus_dht *ad, 
                                    struct azureus_db_key *db_key, 
                                    struct azureus_db_valset *db_valset);
static int azureus_dht_delete_db_item(struct azureus_dht *ad, 
                                        struct azureus_db_key *db_key);
static struct azureus_db_item * azureus_dht_find_db_item(
                                            struct azureus_dht *ad, 
                                            struct azureus_db_key *db_key);

static void azureus_dht_summary(struct azureus_dht *ad);
static void azureus_dht_kbucket_stats(struct azureus_dht *ad);
static void azureus_dht_db_stats(struct azureus_dht *ad);
static int azureus_dht_task_count(struct azureus_dht *ad);
static void azureus_dht_update_rpc_stats(struct azureus_dht *ad, u32 action, 
                                enum pkt_dir dir);
/*********************** Function Definitions ***********************/

struct dht *
azureus_dht_new(struct dht_net_if *nif, int port)
{
    struct azureus_dht *ad = NULL;
    struct sockaddr_storage ss;
    struct hostent *he = NULL;
    struct azureus_node *bootstrap = NULL;
    int i;
    int ret;

    ad = (struct azureus_dht *) malloc(sizeof(struct azureus_dht));
    if (!ad) {
        return NULL;
    }

    bzero(ad, sizeof(struct azureus_dht));

    /* initialize parent base class */
    ret = dht_new(&ad->dht, DHT_TYPE_AZUREUS, nif, port);
    if (ret != SUCCESS) {
        azureus_dht_delete(&ad->dht);
        return NULL;
    }

    /* initialize the kbuckets */
    for (i = 0; i < 160; i++) {
        LIST_INIT(&ad->kbucket[i].node_list);
    }

    /* initialize the task list */
    TAILQ_INIT(&ad->task_list);

    /* initialize the database */
    TAILQ_INIT(&ad->db_list);

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

    ad->this_node = azureus_node_new(ad, ad->proto_ver, &ss);
    if (!ad->this_node) {
        azureus_dht_delete(&ad->dht);
        return NULL;
    }

    DEBUG("this_node\n");
    key_dump(&ad->this_node->node.id);

    /* initialize the network position of this node */
    azureus_vivaldi_pos_new(&ad->this_node->viv_pos[VIVALDI_V1], 
                            POSITION_TYPE_VIVALDI_V1, 0.0f, 0.0f, 0.0f);
    azureus_vivaldi_pos_new(&ad->this_node->viv_pos[VIVALDI_V2],
                            POSITION_TYPE_VIVALDI_V2, 100.0f, 100.0f, 100.0f);

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

    bootstrap = azureus_node_new(ad, PROTOCOL_VERSION_MAIN, &ss);
    if (!bootstrap) {
        azureus_dht_delete(&ad->dht);
        return NULL;
    }

    bootstrap->node_status = AZUREUS_NODE_STATUS_BOOTSTRAP;
    ad->bootstrap = bootstrap;

    azureus_dht_add_node(ad, bootstrap);
    DEBUG("Added bootstrap node\n");

    ad->cr_time = dht_get_current_time();

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

int 
azureus_dht_task_schedule(struct dht *dht)
{
    struct azureus_dht *ad = NULL;
    struct azureus_rpc_msg *msg = NULL;
    struct pkt *pkt = NULL;
    struct azureus_task *at = NULL, *atn = NULL;
    struct task *task = NULL;
    struct azureus_node *an = NULL;
    u64 curr_time = 0;
    bool rate_limit_allow = TRUE;
    int ret;

    ASSERT(dht);

    curr_time = dht_get_current_time();

    ad = azureus_dht_get_ref(dht);

    /* kbucket refresh */
    azureus_dht_kbucket_refresh(ad);

    /* database refresh */
    azureus_dht_db_refresh(ad);

    /* the main task processing loop */
    TAILQ_FOREACH_SAFE(at, &ad->task_list, next, atn) {
        task = &at->task;
        if (task->state == TASK_STATE_WAIT) {
            /* was there a timeout? */
            if ((curr_time - task->access_time) < AZUREUS_RPC_TIMEOUT) {
                /* this task hasn't timed out yet, so wait some more! */
                continue;
            }

            if (at->retries == 0) {
                DEBUG("task timed out\n");
                an = azureus_node_get_ref(task->node);
                ASSERT(an);
                azureus_dht_delete_task(ad, at);      
                an->alive = FALSE;
                an->failures++;
                if (an->failures == MAX_RPC_FAILURES) {
                    azureus_dht_delete_node(ad, an);
                }
                continue;
            } else {
                DEBUG("retrying task\n");
                at->retries--;
            }
        }

        if (!rate_limit_allow) {
            /* don't process any more outgoing pkts! */
            continue;
        }

        pkt = task->pkt;
//        pkt = TAILQ_FIRST(&task->pkt_list);
        msg = azureus_rpc_msg_get_ref(pkt);

//        DEBUG("pkt->dir %d\n", pkt->dir);
//        DEBUG("msg->action %d\n", msg->action);

        switch (pkt->dir) {
            case PKT_DIR_RX:
                DEBUG("RX\n");
                break;

            case PKT_DIR_TX:

                if (!tinydht_rate_limit_allow()) {
                    rate_limit_allow = FALSE;
                    break;
                }

                DEBUG("TX\n");
                pkt_reset_data(&msg->pkt);
                /* FIXME: encode everytime? */
                ret = azureus_rpc_msg_encode(msg);  
                if (ret != SUCCESS) {
                    return FAILURE;
                }

                azureus_dht_rpc_tx(ad, task, msg);

                break;

            default:
                return FAILURE;
        }
    }

    return SUCCESS;
}

static int
azureus_dht_rpc_tx(struct azureus_dht *ad, struct task *task, 
                struct azureus_rpc_msg *msg)
{
    struct azureus_node *an = NULL;
    u64 curr_time = 0;
    int ret;

    ASSERT(ad && msg);

    ret = sendto(ad->dht.net_if.sock, msg->pkt.data, msg->pkt.len, 0, 
            (struct sockaddr *)&msg->pkt.ss, sizeof(struct sockaddr_in));
    if (ret < 0) {
        ERROR("sendto() - %s\n", strerror(errno));
        ERROR("error sending %d bytes to %s/%hu\n", 
            ret,
            inet_ntoa(((struct sockaddr_in *)&msg->pkt.ss)->sin_addr),
            ntohs(((struct sockaddr_in *)&msg->pkt.ss)->sin_port));
        return FAILURE;
    }

    curr_time = dht_get_current_time();

    DEBUG("sent %d bytes to %s/%hu\n", 
            ret,
            inet_ntoa(((struct sockaddr_in *)&msg->pkt.ss)->sin_addr),
            ntohs(((struct sockaddr_in *)&msg->pkt.ss)->sin_port));

    pkt_dump(&msg->pkt);

    ad->stats.net.tx += ret;

    tinydht_rate_limit_update(ret);

    azureus_dht_update_rpc_stats(ad, msg->action, msg->pkt.dir);

    if (!task) {
        return SUCCESS;
    }

    task->state = TASK_STATE_WAIT;
    task->access_time = curr_time;

    an = azureus_node_get_ref(task->node);
    ASSERT(an);

    switch (msg->action) {
        case ACT_REQUEST_PING:
            an->last_ping = curr_time;
            break;
        case ACT_REQUEST_FIND_NODE:
            an->last_find_node = curr_time;
            break;
        default:
            break;
    }

    return SUCCESS;
}

int
azureus_dht_rpc_rx(struct dht *dht, struct sockaddr_storage *from, 
                    size_t fromlen, u8 *data, int len, u64 timestamp)
{
    struct azureus_dht *ad = NULL;
    struct azureus_rpc_msg *msg = NULL, *msg1 = NULL;
    struct azureus_rpc_msg *rsp = NULL;
    struct pkt *pkt = NULL;
    struct azureus_task *at = NULL;
    struct task *task = NULL;
    struct azureus_node *an = NULL, *ann = NULL;
    bool found = FALSE;
    float rtt = 0.0;
    int i;
    struct kbucket_node_search_list_head list;
    int n_list = 0;
    struct node *tn = NULL, *tnn = NULL;
    struct key key;
    struct azureus_db_item *db_item = NULL;
    struct azureus_db_key *db_key = NULL, *db_keyn = NULL;
    struct azureus_db_valset *db_valset = NULL, *db_valsetn = NULL;
    int ret;

    ASSERT(dht && from && data);

    ad = azureus_dht_get_ref(dht);

    ad->stats.net.rx += len;

    tinydht_rate_limit_update(len);

    /* decode the rpc msg */
    ret = azureus_rpc_msg_decode(ad, from, fromlen, data, len, &msg);
    if (ret != SUCCESS) {
        ERROR("dropped msg - cannot decode!\n");
        return ret;
    }

    msg->pkt.dir = PKT_DIR_RX;

    azureus_dht_update_rpc_stats(ad, msg->action, msg->pkt.dir);

    if (msg->is_req) {  /* REQUEST */

        an = azureus_dht_get_node(ad, &msg->pkt.ss, msg->u.udp_req.proto_ver);
        if (!an) {
            an = azureus_node_new(ad, msg->u.udp_req.proto_ver, &msg->pkt.ss);
            if (!an) {
                azureus_rpc_msg_delete(msg);
                return FAILURE;
            }

            azureus_dht_add_node(ad, an);
            DEBUG("Added new node %p\n", an);
        }

        /* prepare a response for the request */
        rsp = azureus_rpc_msg_new(ad, from, fromlen, NULL, 0);
        rsp->pkt.dir = PKT_DIR_TX;
        rsp->r.req = msg;

        rsp->n_viv_pos = MAX_RPC_VIVALDI_POS;
        memcpy(&rsp->viv_pos[VIVALDI_V1], &ad->this_node->viv_pos[VIVALDI_V1], 
                        sizeof(struct azureus_vivaldi_pos));
        memcpy(&rsp->viv_pos[VIVALDI_V2], &ad->this_node->viv_pos[VIVALDI_V2], 
                        sizeof(struct azureus_vivaldi_pos));

        switch (msg->action) {

            case ACT_REQUEST_PING:
                rsp->action = ACT_REPLY_PING;
                break;

            case ACT_REQUEST_FIND_NODE:
                rsp->action = ACT_REPLY_FIND_NODE;
                rsp->m.find_node_rsp.rnd_id = an->rnd_id;
                ret = key_new(&key, KEY_TYPE_SHA1, msg->m.find_node_req.id, 
                        msg->m.find_node_req.id_len);

                azureus_dht_get_k_closest_nodes(ad, &key, AZUREUS_K, 
                        &list, &n_list);
                TAILQ_INIT(&rsp->m.find_node_rsp.node_list);
                TAILQ_FOREACH_SAFE(tn, &list, next, tnn) {
                    an = azureus_node_get_ref(tn);
                    TAILQ_INSERT_TAIL(&rsp->m.find_node_rsp.node_list, 
                            an, next);
                }
                rsp->m.find_node_rsp.n_nodes = n_list;
                break;

            case ACT_REQUEST_FIND_VALUE:
                rsp->action = ACT_REPLY_FIND_VALUE;
                /* do we already have this value? */
                db_item = azureus_dht_find_db_item(ad, 
                                                    &msg->m.find_value_req.key);
                DEBUG("db_item %p\n", db_item);
                if (db_item) {
                    /* we have this key-value pair */
                    rsp->m.find_value_rsp.has_vals = TRUE;
                    rsp->m.find_value_rsp.valset = db_item->valset;
                    rsp->m.find_value_rsp.div_type = DT_NONE;

                    DEBUG("valset n_vals %d\n", db_item->valset->n_vals);

                } else {
                    /* we don't, so send the k-closest nodes */
                    rsp->m.find_value_rsp.has_vals = FALSE;

                    ret = key_new(&key, KEY_TYPE_SHA1, 
                                    msg->m.find_value_req.key.data, 
                                    msg->m.find_value_req.key.len);
                    azureus_dht_get_k_closest_nodes(ad, &key, AZUREUS_K, 
                            &list, &n_list);

                    DEBUG("n_list %d\n", n_list);

                    TAILQ_INIT(&rsp->m.find_value_rsp.node_list);
                    TAILQ_FOREACH_SAFE(tn, &list, next, tnn) {
                        an = azureus_node_get_ref(tn);
                        TAILQ_INSERT_TAIL(&rsp->m.find_value_rsp.node_list, 
                                an, next);
                    }
                    rsp->m.find_value_rsp.n_nodes = n_list;
                }
                break;

            case ACT_REQUEST_STORE:
                if (an->rnd_id != msg->m.store_value_req.rnd_id) {
                    ERROR("spoof id mismatch - %#x %#x!\n", 
                            an->rnd_id, msg->m.store_value_req.rnd_id);
                    azureus_rpc_msg_delete(rsp);
                    azureus_rpc_msg_delete(msg);
                    return FAILURE;
                }

                azureus_dht_db_stats(ad);

                /* store the values */
                TAILQ_FOREACH_SAFE(db_key, &msg->m.store_value_req.key_list, 
                                    next, db_keyn) {

                    TAILQ_REMOVE(&msg->m.store_value_req.key_list, 
                                    db_key, next);

                    db_valset = db_valsetn = NULL;

                    TAILQ_FOREACH_SAFE(db_valset, 
                                        &msg->m.store_value_req.valset_list, 
                                        next, db_valsetn) {
                        TAILQ_REMOVE(&msg->m.store_value_req.valset_list, 
                                        db_valset, next);
                        break;
                    }

                    ret = azureus_dht_add_db_item(ad, db_key, db_valset);
                    if (ret != SUCCESS) {
                        break;
                    }
                }

                rsp->action = ACT_REPLY_STORE;
                rsp->m.store_value_rsp.n_divs = 0;
                break;

            default:
                azureus_rpc_msg_delete(rsp);
                azureus_rpc_msg_delete(msg);
                return FAILURE;
        }

        ret = azureus_rpc_msg_encode(rsp);
        if (ret != SUCCESS) {
            azureus_rpc_msg_delete(msg);
            return FAILURE;
        }

        azureus_dht_rpc_tx(ad, NULL, rsp);

        azureus_rpc_msg_delete(rsp);

    } else {            /* REPLY   */

        /* look for a matching request */
        TAILQ_FOREACH(at, &ad->task_list, next) {
            
            task = &at->task;

            if (task->state != TASK_STATE_WAIT) {
                continue;
            }

            pkt = task->pkt;
            msg1 = azureus_rpc_msg_get_ref(pkt);
            if (azureus_rpc_match_req_rsp(msg1, msg)) {
                found = TRUE;
                break;
            }
        }

        if (!found) {
            /* drop this response! */
            ERROR("dropped response - no matching request\n");
            azureus_rpc_msg_delete(msg);
            return SUCCESS;
        }

        an = azureus_node_get_ref(task->node);
        ASSERT(an);
        an->alive = TRUE;
        an->failures = 0;
        azureus_dht_add_node(ad, an);

        switch (msg->action) {

            case ACT_REPLY_PING:
                break;

            case ACT_REPLY_FIND_NODE:
                /* if the reply contained new nodes, 
                 * add them to the new node list */

                an->my_rnd_id = msg->m.find_node_rsp.rnd_id;

                DEBUG("number of nodes %d\n", msg->m.find_node_rsp.n_nodes);
                TAILQ_FOREACH_SAFE(an, &msg->m.find_node_rsp.node_list, 
                                                                    next, ann) {
                    TAILQ_REMOVE(&msg->m.find_node_rsp.node_list, an, next);
                    if (azureus_dht_contains_node(ad, an)) {
                        azureus_node_delete(an);
                        continue;
                    }
                    azureus_dht_add_node(ad, an);
                }

                /* FIXME: fix this later! */
                if (ad->est_dht_size < msg->m.find_node_rsp.est_dht_size) {
                    ad->est_dht_size = msg->m.find_node_rsp.est_dht_size + 1;
                }
                break;

            case ACT_REPLY_FIND_VALUE:
                /* if the reply contained new nodes, 
                 * add them to the new node list */
                TAILQ_FOREACH_SAFE(an, &msg->m.find_value_rsp.node_list, 
                                                                    next, ann) {
                    TAILQ_REMOVE(&msg->m.find_value_rsp.node_list, an, next);
                    if (azureus_dht_contains_node(ad, an)) {
                        azureus_node_delete(an);
                        continue;
                    }
                    azureus_dht_add_node(ad, an);
                }
                break;

            case ACT_REPLY_STORE:
                break;

            default:
                ERROR("dropped msg - unknown action!\n");
                azureus_rpc_msg_delete(msg);
                return SUCCESS;
        }


        /* update vivaldi position if relevant */
        rtt = 1.0*(timestamp - task->access_time)/1000;
        DEBUG("RTT %f\n", rtt);

        for (i = 0; i < msg->n_viv_pos; i++) {
            if (msg->viv_pos[i].type != POSITION_TYPE_VIVALDI_V1) {
                continue;
            }
            DEBUG("MY NETPOS (before)\n");
            azureus_vivaldi_pos_dump(&ad->this_node->viv_pos[VIVALDI_V1]);
            azureus_vivaldi_v1_update(&ad->this_node->viv_pos[VIVALDI_V1], rtt, 
                    &msg->viv_pos[i], 
                    msg->viv_pos[i].v.v1.err); 
            DEBUG("MY NETPOS (after)\n");
            azureus_vivaldi_pos_dump(&ad->this_node->viv_pos[VIVALDI_V1]);
            break;
        }

        azureus_dht_delete_task(ad, at);      
    }

    azureus_rpc_msg_delete(msg);

    return SUCCESS;
}

int
azureus_dht_put(struct dht *dht, struct tinydht_msg *msg)
{
    struct azureus_db_item *item = NULL, *itemn = NULL;
    struct azureus_dht *ad = NULL;
    struct azureus_db_key *k = NULL;
    struct azureus_db_valset *vs = NULL;
    struct azureus_db_val *v = NULL;
    int ret;
    size_t off, len;

    DEBUG("PUT received\n");

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
#if 0
    /* delete a duplicate! */
    TAILQ_FOREACH_SAFE(item, &ad->db_list, db_next, itemn) {
        if (azureus_db_item_match_key(item, msg->req.key, msg->req.key_len)) {
            DEBUG("key already exists - deleting item\n");
            azureus_db_item_delete(item);
            break;
        }
    }
#endif

    k = azureus_db_key_new();
    if (!k) {
        return FAILURE;
    }

    k->len = msg->req.key_len;
    memcpy(k->data, msg->req.key, msg->req.key_len);

    vs = azureus_db_valset_new();
    if (!vs) {
        azureus_db_key_delete(k);
        return FAILURE;
    }

    v = azureus_db_val_new();
    if (!v) {
        azureus_db_key_delete(k);
        azureus_db_valset_delete(vs);
    }
    v->len = msg->req.val_len;
    memcpy(v->data, msg->req.val, msg->req.val_len);
    TAILQ_INSERT_TAIL(&vs->val_list, v, next);

    item = azureus_db_item_new(ad, k, vs);
    if (!item) {
        azureus_db_item_delete(item);
    }

    TAILQ_INSERT_TAIL(&ad->db_list, item, db_next);

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

    DEBUG("GET received\n");

    if (!dht) {
        return FAILURE;
    }

    if (msg->req.key_len > AZUREUS_MAX_KEY_LEN) {
        return FAILURE;
    }

    ad = azureus_dht_get_ref(dht);
#if 0
    TAILQ_FOREACH(item, &ad->db_list, db_next) {
        if (azureus_db_item_match_key(item, msg->req.key, msg->req.key_len)) {
            off = 0;
            TAILQ_FOREACH(v, &item->valset->val_list, next) {
                memcpy(&msg->rsp.val[off], v->data, v->len);
                off += v->len;
            }
            msg->rsp.val_len = off;
            DEBUG("GET successful\n");
            return SUCCESS;
        }
    }
#endif

    DEBUG("GET successful\n");

    return SUCCESS;
}

static int 
azureus_dht_add_task(struct azureus_dht *ad, struct azureus_task *at)
{
    ASSERT(ad && at);

    TAILQ_INSERT_TAIL(&ad->task_list, at, next);
    ad->n_tasks++;
    return SUCCESS;
}

static int 
azureus_dht_delete_task(struct azureus_dht *ad, struct azureus_task *at)
{
    ASSERT(ad && at);

    TAILQ_REMOVE(&ad->task_list, at, next);
    ad->n_tasks--;

    azureus_task_delete(at);

    return SUCCESS;
}

static int
azureus_dht_add_ping_task(struct azureus_dht *ad, struct azureus_node *an)
{
    struct azureus_rpc_msg *msg = NULL;
    struct azureus_task *at = NULL;

    ASSERT(ad && an);

    if ((ad->bootstrap != an) && an->task_pending) {
        return FAILURE;
    }

    msg = azureus_rpc_msg_new(ad, &an->ext_addr, 
                                sizeof(struct sockaddr_storage), NULL, 0);
    if (!msg) {
        return FAILURE;
    }

    msg->action = ACT_REQUEST_PING;
    msg->pkt.dir = PKT_DIR_TX;

    at = azureus_task_new(ad, an, msg);
    if (!at) {
        azureus_rpc_msg_delete(msg);
        return FAILURE;
    }

    azureus_dht_add_task(ad, at);

    DEBUG("Added new PING task %p\n", an);

    return SUCCESS;
}

static int
azureus_dht_add_find_node_task(struct azureus_dht *ad, struct azureus_node *an,
                                    struct key *node_id)
{
    struct azureus_rpc_msg *msg = NULL;
    struct azureus_task *at = NULL;

    ASSERT(ad && an && node_id);

    if ((ad->bootstrap != an) && an->task_pending) {
        return FAILURE;
    }

    msg = azureus_rpc_msg_new(ad, &an->ext_addr, 
                                sizeof(struct sockaddr_storage), NULL, 0);
    if (!msg) {
        return FAILURE;
    }

    msg->action = ACT_REQUEST_FIND_NODE;
    msg->pkt.dir = PKT_DIR_TX;

    msg->m.find_node_req.id_len = node_id->len;
    memcpy(msg->m.find_node_req.id, node_id->data, node_id->len);

    at = azureus_task_new(ad, an, msg);
    if (!at) {
        azureus_rpc_msg_delete(msg);
        return FAILURE;
    }

    azureus_dht_add_task(ad, at);

    DEBUG("Added new FIND_NODE task %p\n", an);

    return SUCCESS;
}

static int
azureus_dht_add_node(struct azureus_dht *ad, struct azureus_node *an)
{
    int index = 0;
    struct node *n = NULL;
    int ret;

    ASSERT(ad && an);

    /* ignore, if the added node is me! */
    if (key_cmp(&ad->this_node->node.id, &an->node.id) == 0) {
        return SUCCESS;
    }

    index = kbucket_index(&ad->this_node->node.id, &an->node.id);
    ASSERT(index < 160);

    key_dump(&ad->this_node->node.id);
    key_dump(&an->node.id);
    DEBUG("index %d\n", index);

    n = kbucket_delete_node(&ad->kbucket[index], &an->node);
    if (n && (an != azureus_node_get_ref(n))) {
        azureus_node_delete(an);
        an = azureus_node_get_ref(n);
    }

    ret = kbucket_insert_node(&ad->kbucket[index], &an->node, AZUREUS_K);

    DEBUG("azureus_node_count %d\n", ad->stats.mem.node);
    DEBUG("azureues_dht_node_count %d\n", azureus_dht_get_node_count(ad));

    return SUCCESS;
}

static int
azureus_dht_delete_node(struct azureus_dht *ad, struct azureus_node *an)
{
    int index = 0;
    struct node *n = NULL;

    ASSERT(ad && an);

    index = kbucket_index(&ad->this_node->node.id, &an->node.id);
    ASSERT(index < 160);

    /* don't delete the bootstrap node, ever!! */
    if (an->node_status == AZUREUS_NODE_STATUS_BOOTSTRAP) {
        return SUCCESS;
    }

    key_dump(&ad->this_node->node.id);
    key_dump(&an->node.id);
    DEBUG("index %d\n", index);

    n = kbucket_delete_node(&ad->kbucket[index], &an->node);
    if (n && (an != azureus_node_get_ref(n))) {
        azureus_node_delete(azureus_node_get_ref(n));
    }

    azureus_node_delete(an);

    DEBUG("azureus_node_count %d\n", ad->stats.mem.node);
    DEBUG("azureues_dht_node_count %d\n", azureus_dht_get_node_count(ad));

    return SUCCESS;
}

static struct azureus_node *
azureus_dht_get_node(struct azureus_dht *ad, struct sockaddr_storage *ss, 
                        u8 proto_ver)
{
    struct key k;
    int index;
    struct node *n = NULL;
    int ret;

    ret = azureus_node_get_id(&k, ss, proto_ver);

    /* is it in any kbucket? */
    index = kbucket_index(&ad->this_node->node.id, &k);
    DEBUG("index %d\n", index);
    ASSERT(index < 160);
    n = kbucket_get_node(&ad->kbucket[index], &k);
    if (n) {
        return azureus_node_get_ref(n);
    }

    return NULL;
}

static bool
azureus_dht_contains_node(struct azureus_dht *ad, 
                                struct azureus_node *node)
{
    int index;

    ASSERT(ad && node);

    /* myself? */
    if (key_cmp(&ad->this_node->node.id, &node->node.id) == 0) {
        return TRUE;
    }

    /* is it in any kbucket? */
    index = kbucket_index(&ad->this_node->node.id, &node->node.id);
    DEBUG("index %d\n", index);
    ASSERT(index < 160);
    if (kbucket_contains_node(&ad->kbucket[index], &node->node)) {
        return TRUE;
    }

    return FALSE;
}

static int
azureus_dht_kbucket_refresh(struct azureus_dht *ad) 
{
    struct kbucket *kbucket = NULL;
    struct node *node = NULL, *noden = NULL;
    struct azureus_node *an = NULL;
    u64 curr_time = 0;
    int index, max_index;
    struct key rnd_id;

    ASSERT(ad);

    curr_time = dht_get_current_time();

    max_index = (ad->this_node->node.id.len)*8
                        *sizeof(ad->this_node->node.id.data[0]);

    for (index = 0; index < max_index; index++) {

        kbucket = &ad->kbucket[index];

        LIST_FOREACH_SAFE(node, &kbucket->node_list, kb_next, noden) {

            an = azureus_node_get_ref(node);

            if (an->node_status == AZUREUS_NODE_STATUS_BOOTSTRAP) {
                if ((azureus_dht_get_node_count(ad) > 1) 
                        || an->task_pending) {
                    continue;
                }

                azureus_dht_add_ping_task(ad, an);
                azureus_dht_add_find_node_task(ad, an, &ad->this_node->node.id);
            }

            if (!an->alive && (an->failures < MAX_RPC_FAILURES)) {
                azureus_dht_add_ping_task(ad, an);
                continue;
            }

            if ((curr_time - an->last_ping) > PING_TIMEOUT) {
                /* create a ping task */
                azureus_dht_add_ping_task(ad, an);
            }

            if (an->alive && ((curr_time - an->last_find_node) 
                                                > FIND_NODE_TIMEOUT)) {
                /* create a find_node task */
                azureus_dht_add_find_node_task(ad, an, &ad->this_node->node.id);
            }
#if 0
            if (an->alive && ((curr_time - kbucket->last_refresh) 
                                                > KBUCKET_REFRESH_TIMEOUT)) {
                /* create a find_node task for random id */
                DEBUG("find node rnd_id - index %d\n", index);
                key_new(&rnd_id, KEY_TYPE_RANDOM, NULL, 0);
                azureus_dht_add_find_node_task(ad, an, &rnd_id);
                kbucket->last_refresh = curr_time;
            }
#endif
        }

        LIST_FOREACH_SAFE(node, &kbucket->ext_node_list, kb_next, noden) {

            an = azureus_node_get_ref(node);

            if (!an->alive && (an->failures < MAX_RPC_FAILURES)) {
                azureus_dht_add_ping_task(ad, an);
                continue;
            }

            if ((curr_time - an->last_ping) > PING_TIMEOUT) {
                /* create a ping task */
                azureus_dht_add_ping_task(ad, an);
            }
        }
    }

    return SUCCESS;
}

static void
azureus_dht_kbucket_stats(struct azureus_dht *ad)
{
    int i;
    struct azureus_node *an = NULL;
    struct node *node = NULL, *noden = NULL;
    int total, alive;
    int bigtotal;

    bigtotal = 0;
    for (i = 0; i < 160; i++) {
        total = 0;
        alive = 0;
        LIST_FOREACH_SAFE(node, &ad->kbucket[i].node_list, kb_next, noden) {
            an = azureus_node_get_ref(node);
            total++;
            if (an->alive) {
                alive++;
            }
        }

        if (total) {
            DEBUG("KBUCKET %d total %d alive %d\n", i, total, alive);
            bigtotal += total;
        }
    }
    DEBUG("KBUCKET bigtotal %d\n", bigtotal);

    return;
}

static int
azureus_dht_get_k_closest_nodes(struct azureus_dht *ad, struct key *key, int k,
                                struct kbucket_node_search_list_head *list, 
                                int *n_list)
{
    struct key dist;
    int index, max_index;
    int count = 0;
    int ret;
    int high = 0;
    struct node *tn = NULL, *tnn = NULL;
    struct azureus_node *an = NULL;

    ASSERT(ad && key && k && list && n_list); 

    TAILQ_INIT(list);

    ret = key_distance(&ad->this_node->node.id, key, &dist);

    max_index = key->len*8*sizeof(key->data[0]);

    for (index = (max_index - 1); (index >= 0) && (count < k); index--) {
        if (key_nth_bit(&dist, index) != 1) {
            continue;
        }

        if (index > high) {
            high = index;
            DEBUG("high %d\n", high);
        }

        LIST_FOREACH_SAFE(tn, &ad->kbucket[index].node_list, kb_next, tnn) {
            an = azureus_node_get_ref(tn);
            if (!an->alive) {
                continue;
            }

            TAILQ_INSERT_TAIL(list, tn, next);
            count++;

            if (count == k) {
                *n_list = count;
                return SUCCESS;
            }
        }
    }

    /* we walk backwards now */
    for (index = 0; (index < max_index) && (count < k) 
                            && (index > high); index++) {
        if (key_nth_bit(&dist, index) != 0) {
            continue;
        }

        LIST_FOREACH_SAFE(tn, &ad->kbucket[index].node_list, kb_next, tnn) {
            an = azureus_node_get_ref(tn);
            if (!an->alive) {
                continue;
            }

            TAILQ_INSERT_TAIL(list, tn, next);
            count++;

            if (count == k) {
                *n_list = count;
                return SUCCESS;
            }
        }
    }

    return SUCCESS;
}

static int
azureus_dht_get_node_count(struct azureus_dht *ad)
{
    int index = 0;
    int count = 0;
    int max_index;

    ASSERT(ad);

    max_index = (ad->this_node->node.id.len)*8
                        *sizeof(ad->this_node->node.id.data[0]);

    for (index = 0; index < max_index; index++) {
        count += ad->kbucket[index].n_nodes;

    }

    return count;
}

static int
azureus_dht_db_refresh(struct azureus_dht *ad)
{
    ASSERT(ad);

    if (!azureus_dht_is_stable(ad)) {
        return FAILURE;
    }

    return SUCCESS;
}

static bool
azureus_dht_is_stable(struct azureus_dht *ad)
{
    static u64 prev_time = 0;
    u64 curr_time = 0;
    static int prev_count = 0;
    int curr_count = 0;
    u64 elapsed = 0;

    ASSERT(ad);

    /* first, find out if the DHT's routing table is stable */
    curr_time = dht_get_current_time();

    if ((curr_time - prev_time) < DHT_STABLE_TEST_WINDOW) {
        return FALSE;
    }

    /* if here, we have a one second sample */

    prev_time = curr_time;

    curr_count = azureus_dht_get_node_count(ad);
    if (!curr_count) {
        prev_count = 0;
        return FALSE;
    }

    if ((curr_count - prev_count) != 0) {
        prev_count = curr_count;
        return FALSE;
    }

    if (ad->stats.mem.rpc_msg > 0) {
        return FALSE;
    }

    elapsed = (curr_time - ad->cr_time)/(1000*1000);
    DEBUG("stable in %llu seconds\n", elapsed);
    DEBUG("stable count %d\n", prev_count);
    azureus_dht_task_count(ad);
    azureus_dht_kbucket_stats(ad);
    azureus_dht_db_stats(ad);
    DEBUG("azureus_node_count %d\n", ad->stats.mem.node);
    DEBUG("azureus_rpc_msg_count %d\n", ad->stats.mem.rpc_msg);
    DEBUG("rx (bytes) %llu rx rate (Bps) %llu\n", 
            ad->stats.net.rx, ad->stats.net.rx/(elapsed));
    DEBUG("tx (bytes) %llu tx rate (Bps) %llu\n", 
            ad->stats.net.tx, ad->stats.net.tx/(elapsed));

    return TRUE;
}

static int
azureus_dht_task_count(struct azureus_dht *ad)
{
    struct task *task = NULL;
    struct azureus_task *at = NULL, *atn = NULL;
    int count = 0, wt_count = 0;

    ASSERT(ad);

    TAILQ_FOREACH_SAFE(at, &ad->task_list, next, atn) {
        task = &at->task;
        count++;
        if (task->state == TASK_STATE_WAIT) {
            wt_count++;
        }
    }

    DEBUG("task count %d wait count %d active count %d\n", 
            count, wt_count, (count - wt_count));

    return SUCCESS;
}

void
azureus_dht_exit(struct dht *dht)
{
    struct azureus_dht *ad = NULL;

    ASSERT(dht);

    ad = azureus_dht_get_ref(dht);

    azureus_dht_summary(ad);

    DEBUG("azureus_node_count %d\n", ad->stats.mem.node);
    DEBUG("azureus_rpc_msg_count %d\n", ad->stats.mem.rpc_msg);
    azureus_dht_task_count(ad);
    azureus_dht_kbucket_stats(ad);

    return;
}

static int
azureus_dht_add_db_item(struct azureus_dht *ad, struct azureus_db_key *db_key, 
                        struct azureus_db_valset *db_valset)
{
    struct azureus_db_item *db_item = NULL;

    ASSERT(ad && db_key && db_valset);

    /* if there was already a db_item, remove it! */
    azureus_dht_delete_db_item(ad, db_key);

    db_item = azureus_db_item_new(ad, db_key, db_valset);
    if (!db_item) {
        return FAILURE;
    }

    TAILQ_INSERT_TAIL(&ad->db_list, db_item, db_next);
    DEBUG("Added new db item %p\n", db_item);

    return SUCCESS;
}

static int
azureus_dht_delete_db_item(struct azureus_dht *ad, 
                            struct azureus_db_key *db_key)
{
    struct azureus_db_item *item = NULL, *itemn = NULL;

    ASSERT(ad && db_key);

    TAILQ_FOREACH_SAFE(item, &ad->db_list, db_next, itemn) {
        if (!azureus_db_key_equal(item->key, db_key)) {
            continue;
        }

        TAILQ_REMOVE(&ad->db_list, item, db_next);
        azureus_db_item_delete(item);
        DEBUG("Deleted db item %p\n", item);
    }

    return SUCCESS;
}

static struct azureus_db_item *
azureus_dht_find_db_item(struct azureus_dht *ad, struct azureus_db_key *db_key)
{
    struct azureus_db_item *item = NULL, *itemn = NULL;

    ASSERT(ad && db_key);

    TAILQ_FOREACH_SAFE(item, &ad->db_list, db_next, itemn) {
        DEBUG("key_cmp\n");
        pkt_dump_data(item->key->data, item->key->len);
        pkt_dump_data(db_key->data, db_key->len);
        if (azureus_db_key_equal(item->key, db_key)) {
            return item;
        }
    }

    return NULL;
}

static void
azureus_dht_db_stats(struct azureus_dht *ad)
{
    struct azureus_db_item *item = NULL, *itemn = NULL;
    struct azureus_db_val *v = NULL, *vn = NULL;

    ASSERT(ad);

    TAILQ_FOREACH_SAFE(item, &ad->db_list, db_next, itemn) {
        DEBUG("KEY\n");
        pkt_dump_data(item->key->data, item->key->len);
        DEBUG("VALSET n_vals %d\n", item->valset->n_vals);
        TAILQ_FOREACH_SAFE(v, &item->valset->val_list, next, vn) {
            DEBUG("VAL\n");
            pkt_dump_data(v->data, v->len);
        }
    }
}

static void
azureus_dht_update_rpc_stats(struct azureus_dht *ad, u32 action, 
                                enum pkt_dir dir)
{
    ASSERT(ad);

    switch (action) {
        case ACT_REQUEST_PING:
            if (dir == PKT_DIR_RX) {
                ad->stats.rpc.ping_req_rx++;
            } else {
                ad->stats.rpc.ping_req_tx++;
            }
            break;
        case ACT_REPLY_PING:
            if (dir == PKT_DIR_RX) {
                ad->stats.rpc.ping_rsp_rx++;
            } else {
                ad->stats.rpc.ping_rsp_tx++;
            }
            break;
        case ACT_REQUEST_FIND_NODE:
            if (dir == PKT_DIR_RX) {
                ad->stats.rpc.find_node_req_rx++;
            } else {
                ad->stats.rpc.find_node_req_tx++;
            }
            break;
        case ACT_REPLY_FIND_NODE:
            if (dir == PKT_DIR_RX) {
                ad->stats.rpc.find_node_rsp_rx++;
            } else {
                ad->stats.rpc.find_node_rsp_tx++;
            }
            break;
        case ACT_REQUEST_FIND_VALUE:
            if (dir == PKT_DIR_RX) {
                ad->stats.rpc.find_value_req_rx++;
            } else {
                ad->stats.rpc.find_value_req_tx++;
            }
            break;
        case ACT_REPLY_FIND_VALUE:
            if (dir == PKT_DIR_RX) {
                ad->stats.rpc.find_value_rsp_rx++;
            } else {
                ad->stats.rpc.find_value_rsp_tx++;
            }
            break;
        case ACT_REQUEST_STORE:
            if (dir == PKT_DIR_RX) {
                ad->stats.rpc.store_value_req_rx++;
            } else {
                ad->stats.rpc.store_value_req_tx++;
            }
            break;
        case ACT_REPLY_STORE:
            if (dir == PKT_DIR_RX) {
                ad->stats.rpc.store_value_rsp_rx++;
            } else {
                ad->stats.rpc.store_value_rsp_tx++;
            }
            break;
        default:
            ad->stats.rpc.other_rx++;
            break;
    }
}

static void
azureus_dht_summary(struct azureus_dht *ad)
{
    u64 curr_time = 0;
    u64 elapsed = 0;
    u64 hour = 0, min = 0, sec = 0;

    ASSERT(ad);

    curr_time = dht_get_current_time();
    elapsed = (curr_time - ad->cr_time)/(1000*1000);

    hour = elapsed/3600;
    min = (elapsed - hour*3600)/60;
    sec = elapsed - hour*3600 - min*60;

    INFO("uptime:\n");
    INFO("\t%0llu hours %0llu mins %0llu secs\n", hour, min, sec);

    INFO("mem usage:\n");
    INFO("\trpc_msg     %d (%d KB)\n", ad->stats.mem.rpc_msg, 
            ad->stats.mem.rpc_msg*sizeof(struct azureus_rpc_msg)/1024);
    INFO("\tnode        %d (%d KB)\n", ad->stats.mem.node,
            ad->stats.mem.node*sizeof(struct azureus_node)/1024);
    INFO("\ttask        %d (%d KB)\n", ad->stats.mem.task,
            ad->stats.mem.task*sizeof(struct azureus_task)/1024);

    INFO("net usage:\n");
    INFO("\trx          %llu bytes %llu Bps\n", 
            ad->stats.net.rx, ad->stats.net.rx/elapsed);
    INFO("\ttx          %llu bytes %llu Bps\n", 
            ad->stats.net.tx, ad->stats.net.tx/elapsed);

    INFO("rpc stats:\n");
    INFO("\tping        req rx %d\n", ad->stats.rpc.ping_req_rx);
    INFO("\tping        req tx %d\n", ad->stats.rpc.ping_req_tx);
    INFO("\tping        rsp rx %d\n", ad->stats.rpc.ping_rsp_rx);
    INFO("\tping        rsp tx %d\n", ad->stats.rpc.ping_rsp_tx);
    INFO("\tfind node   req rx %d\n", ad->stats.rpc.find_node_req_rx);
    INFO("\tfind node   req tx %d\n", ad->stats.rpc.find_node_req_tx);
    INFO("\tfind node   rsp rx %d\n", ad->stats.rpc.find_node_rsp_rx);
    INFO("\tfind node   rsp tx %d\n", ad->stats.rpc.find_node_rsp_tx);
    INFO("\tfind value  req rx %d\n", ad->stats.rpc.find_value_req_rx);
    INFO("\tfind value  req tx %d\n", ad->stats.rpc.find_value_req_tx);
    INFO("\tfind value  rsp rx %d\n", ad->stats.rpc.find_value_rsp_rx);
    INFO("\tfind value  rsp tx %d\n", ad->stats.rpc.find_value_rsp_tx);
    INFO("\tstore value req rx %d\n", ad->stats.rpc.store_value_req_rx);
    INFO("\tstore value req tx %d\n", ad->stats.rpc.store_value_req_tx);
    INFO("\tstore value rsp rx %d\n", ad->stats.rpc.store_value_rsp_rx);
    INFO("\tstore value rsp tx %d\n", ad->stats.rpc.store_value_rsp_tx);

    return;
}
