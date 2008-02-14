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

static int azureus_dht_rpc_tx(struct azureus_dht *ad, 
                            struct azureus_task *task, 
                            struct azureus_rpc_msg *msg);

static bool azureus_dht_allow_add_task(struct azureus_dht *ad);
static int azureus_dht_add_task(struct azureus_dht *ad, 
                            struct azureus_task *at);
static int azureus_dht_delete_task(struct azureus_dht *ad, 
                            struct azureus_task *at);
static struct azureus_task * azureus_dht_add_ping_task(struct azureus_dht *ad, 
                            struct azureus_node *an);
static struct azureus_task * azureus_dht_add_find_node_task(
                                                    struct azureus_dht *ad, 
                                                    struct azureus_node *an, 
                                                    struct key *node_id);

static struct azureus_task * azureus_dht_add_find_value_task(
                                            struct azureus_dht *ad, 
                                            struct azureus_node *an, 
                                            struct azureus_db_key *key);
static struct azureus_task * azureus_dht_add_store_value_task(
                                            struct azureus_dht *ad, 
                                            struct azureus_node *an,
                                            struct azureus_db_item *db_item);
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
                                struct key *pivot,
                                struct kbucket_node_search_list_head *list, 
                                int *n_list, u8 min_proto_ver, bool use_ext, 
                                bool use_not_alive);
static int azureus_dht_get_node_count(struct azureus_dht *ad);

static int azureus_dht_kbucket_refresh(struct azureus_dht *ad);
static int azureus_dht_db_refresh(struct azureus_dht *ad);

static bool azureus_dht_is_stable(struct azureus_dht *ad);
static int azureus_dht_add_db_item(struct azureus_dht *ad, 
                                    struct azureus_db_key *db_key, 
                                    struct azureus_db_valset *db_valset,
                                    bool is_local);
static int azureus_dht_delete_db_item(struct azureus_dht *ad, 
                                        struct azureus_db_key *db_key);
static struct azureus_db_item * azureus_dht_find_db_item(
                                            struct azureus_dht *ad, 
                                            struct azureus_db_key *db_key);
static int azureus_dht_notify_parent_task(struct azureus_task *at, bool status);

static void azureus_dht_update_rpc_stats(struct azureus_dht *ad, u32 action, 
                                enum pkt_dir dir);

static void azureus_dht_summary(struct azureus_dht *ad);
static void azureus_dht_print_routing_table_stats(struct azureus_dht *ad);
static void azureus_dht_print_task_stats(struct azureus_dht *ad);
static void azureus_dht_db_stats(struct azureus_dht *ad);


static void azureus_dht_net_usage_update(struct azureus_dht *ad, size_t size, 
                                enum pkt_dir pkt_dir);
static bool azureus_dht_rate_limit_allow(struct azureus_dht *ad);

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
        if (at->task.state == TASK_STATE_WAIT) {
            /* was there a timeout? */
            if ((curr_time - at->task.access_time) < AZUREUS_RPC_TIMEOUT) {
                /* this task hasn't timed out yet, so wait some more! */
                continue;
            }

            if (at->retries == 0) {
                DEBUG("task timed out\n");
                an = azureus_node_get_ref(at->task.node);
                ASSERT(an);
                if (at->task.parent) {
                    azureus_dht_notify_parent_task(at, FAILURE);
                } else {
                    azureus_dht_delete_task(ad, at);      
                }
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

        pkt = at->task.pkt;
//        pkt = TAILQ_FIRST(&task->pkt_list);
        msg = azureus_rpc_msg_get_ref(pkt);

//        DEBUG("pkt->dir %d\n", pkt->dir);
//        DEBUG("msg->action %d\n", msg->action);

        switch (pkt->dir) {
            case PKT_DIR_RX:
                DEBUG("RX\n");
                break;

            case PKT_DIR_TX:

                if (!azureus_dht_rate_limit_allow(ad)) {
                    rate_limit_allow = FALSE;
                    break;
                }

                DEBUG("TX\n");
                // pkt_reset_data(&msg->pkt);
                /* FIXME: encode everytime? */
                ret = azureus_rpc_msg_encode(msg);  
                if (ret != SUCCESS) {
                    return FAILURE;
                }

                azureus_dht_rpc_tx(ad, at, msg);

                break;

            default:
                return FAILURE;
        }
    }

    return SUCCESS;
}

static int
azureus_dht_rpc_tx(struct azureus_dht *ad, struct azureus_task *at, 
                struct azureus_rpc_msg *msg)
{
    struct azureus_node *an = NULL;
    u64 curr_time = 0;
    int ret;

    ASSERT(ad && msg);  /* param "at" can be null! */

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

    azureus_dht_net_usage_update(ad, ret, PKT_DIR_TX);

    azureus_dht_update_rpc_stats(ad, msg->action, msg->pkt.dir);

    if (!at) {
        return SUCCESS;
    }

    at->task.state = TASK_STATE_WAIT;
    at->task.access_time = curr_time;

    an = azureus_node_get_ref(at->task.node);
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
    struct azureus_task *at = NULL;
    struct azureus_node *an = NULL;
    struct azureus_node *tan = NULL, *tann = NULL;
    struct node *tn = NULL, *tnn = NULL;
    struct key key;
    struct kbucket_node_search_list_head list;
    struct azureus_db_item *db_item = NULL;
    struct azureus_db_key *db_key = NULL, *db_keyn = NULL;
    struct azureus_db_valset *db_valset = NULL, *db_valsetn = NULL;
    bool found = FALSE;
    float rtt = 0.0;
    int i;
    int n_list = 0;
    int ret;

    ASSERT(dht && from && data);

    ad = azureus_dht_get_ref(dht);

    azureus_dht_net_usage_update(ad, len, PKT_DIR_RX);

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
            /* new node */
            an = azureus_node_new(ad, msg->u.udp_req.proto_ver, &msg->pkt.ss);
            if (!an) {
                azureus_rpc_msg_delete(msg);
                return FAILURE;
            }

            azureus_dht_add_node(ad, an);
            DEBUG("Added new node %p\n", an);

        } else {
            /* node exists */
            if (an->alive) {
                an->last_ping = timestamp;
            }
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
                                    &ad->this_node->node.id,
                                    &list, &n_list, PROTOCOL_VERSION_MIN, 
                                    TRUE, FALSE);

                DEBUG("n_list %d\n", n_list);

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
                    /* we don't, so send the k-closest nodes instead */
                    rsp->m.find_value_rsp.has_vals = FALSE;

                    ret = key_new(&key, KEY_TYPE_SHA1, 
                                    msg->m.find_value_req.key.data, 
                                    msg->m.find_value_req.key.len);

                    azureus_dht_get_k_closest_nodes(ad, &key, AZUREUS_K, 
                                        &ad->this_node->node.id,
                                        &list, &n_list, PROTOCOL_VERSION_MIN, 
                                        TRUE, FALSE);

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

                    ret = azureus_dht_add_db_item(ad, db_key, db_valset, FALSE);
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
            
            if (at->task.state != TASK_STATE_WAIT) {
                continue;
            }

            msg1 = azureus_rpc_msg_get_ref(at->task.pkt);
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

        an = azureus_node_get_ref(at->task.node);
        ASSERT(an);
        an->alive = TRUE;
        an->failures = 0;
        azureus_dht_add_node(ad, an);

        switch (msg->action) {

            case ACT_REPLY_PING:
                break;

            case ACT_REPLY_FIND_NODE:

                an->my_rnd_id = msg->m.find_node_rsp.rnd_id;

                DEBUG("number of nodes %d\n", msg->m.find_node_rsp.n_nodes);

                if (at->task.parent) {
                    azureus_dht_notify_parent_task(at, SUCCESS);
                    break;
                }

                TAILQ_FOREACH_SAFE(tan, &msg->m.find_node_rsp.node_list, 
                        next, tann) {
                    TAILQ_REMOVE(&msg->m.find_node_rsp.node_list, 
                            tan, next);
                    if (azureus_dht_contains_node(ad, tan)) {
                        azureus_node_delete(tan);
                        continue;
                    }
                    azureus_dht_add_node(ad, tan);
                }

                /* FIXME: fix this later! */
                if (ad->est_dht_size < msg->m.find_node_rsp.est_dht_size) {
                    ad->est_dht_size = msg->m.find_node_rsp.est_dht_size + 1;
                }
                break;

            case ACT_REPLY_FIND_VALUE:

                if (&msg->m.find_value_rsp.has_vals) {
                } else {

                    TAILQ_FOREACH_SAFE(tan, &msg->m.find_value_rsp.node_list, 
                            next, tann) {
                        TAILQ_REMOVE(&msg->m.find_value_rsp.node_list, 
                                tan, next);
                        if (azureus_dht_contains_node(ad, tan)) {
                            azureus_node_delete(tan);
                            continue;
                        }
                        azureus_dht_add_node(ad, tan);
                    }
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
        rtt = 1.0*(timestamp - at->task.access_time)/1000;
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

    k = azureus_db_key_new();
    if (!k) {
        return FAILURE;
    }

    crypto_get_sha1_digest(msg->req.key, msg->req.key_len, k->data);
    k->len = MAX_KEY_SIZE;

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

    ret = azureus_dht_add_db_item(ad, k, vs, TRUE);
    if (ret != SUCCESS) {
        return FAILURE;
    }

    DEBUG("PUT successful\n");

    return SUCCESS;
}

int
azureus_dht_get(struct dht *dht, struct tinydht_msg *msg)
{
    struct azureus_db_item *item = NULL;
    struct azureus_dht *ad = NULL;
    struct azureus_db_val *val = NULL;
    struct azureus_db_key key;

    DEBUG("GET received\n");

    if (!dht) {
        return FAILURE;
    }

    if (msg->req.key_len > AZUREUS_MAX_KEY_LEN) {
        return FAILURE;
    }

    ad = azureus_dht_get_ref(dht);

    bzero(&key, sizeof(struct azureus_db_key));
    crypto_get_sha1_digest(msg->req.key, msg->req.key_len, key.data);
    key.len = MAX_KEY_SIZE;

    item = azureus_dht_find_db_item(ad, &key);
    if (!item) {
        return FAILURE;
    }

    /* we expect only one value per key today */
    val = TAILQ_FIRST(&item->valset->val_list);

    memcpy(msg->rsp.val, val->data, val->len);
    msg->rsp.val_len = val->len;

    DEBUG("GET successful\n");

    return SUCCESS;
}


static bool 
azureus_dht_allow_add_task(struct azureus_dht *ad)
{
    ASSERT(ad);

    if (ad->n_tasks < MAX_OUTSTANDING_TASKS) {
        return TRUE;
    }

    return FALSE;
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

static struct azureus_task *
azureus_dht_add_ping_task(struct azureus_dht *ad, struct azureus_node *an)
{
    struct azureus_rpc_msg *msg = NULL;
    struct azureus_task *at = NULL;

    ASSERT(ad && an);

    if (!azureus_dht_allow_add_task(ad)) {
        return NULL;
    }

    if ((ad->bootstrap != an) && an->task_pending) {
        return NULL;
    }

    msg = azureus_rpc_msg_new(ad, &an->ext_addr, 
                                sizeof(struct sockaddr_storage), NULL, 0);
    if (!msg) {
        return NULL;
    }

    msg->action = ACT_REQUEST_PING;
    msg->pkt.dir = PKT_DIR_TX;

    at = azureus_task_new(ad, an, msg);
    if (!at) {
        azureus_rpc_msg_delete(msg);
        return NULL;
    }

    azureus_dht_add_task(ad, at);

    DEBUG("Added new PING task %p\n", an);

    return at;
}

static struct azureus_task *
azureus_dht_add_find_node_task(struct azureus_dht *ad, struct azureus_node *an,
                                    struct key *node_id)
{
    struct azureus_rpc_msg *msg = NULL;
    struct azureus_task *at = NULL;

    ASSERT(ad && an && node_id);

    if (!azureus_dht_allow_add_task(ad)) {
        return NULL;
    }

    if ((ad->bootstrap != an) && an->task_pending) {
        return NULL;
    }

    msg = azureus_rpc_msg_new(ad, &an->ext_addr, 
                                sizeof(struct sockaddr_storage), NULL, 0);
    if (!msg) {
        return NULL;
    }

    msg->action = ACT_REQUEST_FIND_NODE;
    msg->pkt.dir = PKT_DIR_TX;

    msg->m.find_node_req.id_len = node_id->len;
    memcpy(msg->m.find_node_req.id, node_id->data, node_id->len);

    at = azureus_task_new(ad, an, msg);
    if (!at) {
        azureus_rpc_msg_delete(msg);
        return NULL;
    }

    azureus_dht_add_task(ad, at);

    DEBUG("Added new FIND_NODE task %p\n", an);

    return at;
}

static struct azureus_task *
azureus_dht_add_find_value_task(struct azureus_dht *ad, 
                                struct azureus_node *an,
                                struct azureus_db_key *db_key)
{
    struct azureus_rpc_msg *msg = NULL;
    struct azureus_task *at = NULL;
    struct key key;
    int ret;

    ASSERT(ad && an && db_key);

    if (!an->alive) {
        return NULL;
    }

    if (ad->bootstrap == an) {
        return NULL;
    }

    ret = key_new(&key, KEY_TYPE_SHA1, db_key->data, db_key->len);
    if (ret != SUCCESS) {
        return NULL;
    }

    msg = azureus_rpc_msg_new(ad, &an->ext_addr, 
                                sizeof(struct sockaddr_storage), NULL, 0);
    if (!msg) {
        return NULL;
    }

    msg->action = ACT_REQUEST_FIND_VALUE; 
    msg->pkt.dir = PKT_DIR_TX;

    msg->m.find_value_req.flags = FLAG_SINGLE_VALUE;
    msg->m.find_value_req.max_vals = AZUREUS_MAX_VALS_PER_KEY;
    memcpy(&msg->m.find_value_req.key, &key, sizeof(key));

    at = azureus_task_new(ad, an, msg);
    if (!at) {
        azureus_rpc_msg_delete(msg);
        return NULL;
    }

    an->task_pending = at;
    azureus_dht_add_task(ad, at);

    DEBUG("Added a STORE VALUE task %p\n", at);

    return at;
}

static struct azureus_task *
azureus_dht_add_store_value_task(struct azureus_dht *ad, 
                                    struct azureus_node *an,
                                    struct azureus_db_item *db_item)
{
    struct azureus_rpc_msg *msg = NULL;
    struct azureus_task *at = NULL;
    struct key key;
    int ret;

    ASSERT(ad && an && db_item);

    ret = key_new(&key, KEY_TYPE_SHA1, db_item->key->data, db_item->key->len);
    if (ret != SUCCESS) {
        return NULL;
    }

    msg = azureus_rpc_msg_new(ad, &an->ext_addr, 
                                sizeof(struct sockaddr_storage), NULL, 0);
    if (!msg) {
        return NULL;
    }

    msg->action = ACT_REQUEST_STORE;
    msg->pkt.dir = PKT_DIR_TX;

    at = azureus_task_new(ad, an, msg);
    if (!at) {
        azureus_rpc_msg_delete(msg);
        return NULL;
    }

    an->task_pending = at;
    azureus_dht_add_task(ad, at);

    DEBUG("Added a STORE VALUE task %p\n", at);

    return at;
}

static int
azureus_dht_add_db_task(struct azureus_dht *ad, struct azureus_db_item *db_item)
{
    struct kbucket_node_search_list_head list;
    struct azureus_node *an = NULL;
    struct azureus_task *at = NULL;
    int n_list = 0;

    ASSERT(ad && db_item);

    at = azureus_task_new(ad, an, NULL);
    if (!at) {
        return FAILURE;
    }

    return SUCCESS;
}

static int
azureus_dht_notify_parent_task(struct azureus_task *at, bool status)
{
    struct azureus_node *tn = NULL;
    struct azureus_task *pat = NULL;
    struct azureus_rpc_msg *msg = NULL;

    ASSERT(at);

    pat = azureus_task_get_ref(at->task.parent);
    ASSERT(pat);

    msg = azureus_rpc_msg_get_ref(pat->task.pkt);

    switch (msg->action) {
        case ACT_REQUEST_FIND_VALUE:
        case ACT_REQUEST_STORE:
            break;
        default:
            ASSERT(0);
    }

    return SUCCESS;
}

static int
azureus_dht_add_node(struct azureus_dht *ad, struct azureus_node *an)
{
    int index = 0;
    struct node *n = NULL;
    struct azureus_db_item *item = NULL;
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

    if (an->alive) {
        /* FIXME: if this node is closer to any of the key value pairs,
         * store value it on this node */
        TAILQ_FOREACH(item, &ad->db_list, db_next) {
        }
    }

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

    for (index = (max_index - 1); index >= 0; index--) {

        kbucket = &ad->kbucket[index];
        if (kbucket->n_nodes == 0) {
            continue;
        }

        LIST_FOREACH_SAFE(node, &kbucket->node_list, kb_next, noden) {

            an = azureus_node_get_ref(node);

            if (an->node_status == AZUREUS_NODE_STATUS_BOOTSTRAP) {
                if ((azureus_dht_get_node_count(ad) > 1) 
                        || an->task_pending) {
                    continue;
                }

                azureus_dht_add_ping_task(ad, an);
                azureus_dht_add_find_node_task(ad, an, 
                                    &ad->this_node->node.id);
                continue;
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
azureus_dht_insert_sort_closest_node(struct kbucket_node_search_list_head *list,
                                        struct key *pivot, struct node *new, 
                                        int k)
{
    struct node *tn = NULL, *tnn = NULL, *tnxt = NULL;
    struct key dnew, d1, d2;
    int count = 0;

    ASSERT(list && pivot && new);

    DEBUG("entering ...\n");

    key_dump(pivot);
    key_dump(&new->id);

    if (TAILQ_EMPTY(list)) {
        TAILQ_INSERT_TAIL(list, new, next);
        return;
    }

    key_distance(pivot, &new->id, &dnew);

    count = 0;
    TAILQ_FOREACH_SAFE(tn, list, next, tnn) {

        DEBUG("tn %p\n", tn);
        key_distance(pivot, &tn->id, &d1);

        if (tn == TAILQ_LAST(list, kbucket_node_search_list_head)) {

            DEBUG("here - 1\n");

            if (key_cmp(&dnew, &d1) < 0) {
                TAILQ_INSERT_BEFORE(tn, new, next);
                return;
            } else {
                TAILQ_INSERT_AFTER(list, tn, new, next);
                return;
            }

        } else {

            DEBUG("here - 2\n");
            tnxt = TAILQ_NEXT(tn, next);

            key_distance(pivot, &tnxt->id, &d2);

            if (key_cmp(&dnew, &d1) < 0) {
                TAILQ_INSERT_BEFORE(tn, new, next);
                return;
            } else if (key_cmp(&d1, &dnew) < 0 && key_cmp(&dnew, &d2) < 0) {
                TAILQ_INSERT_AFTER(list, tn, new, next);
                return;
            } 
        }

        count++;
        if (count >= k) {
            /* "new" node is not a top-k candidate, so just ignore it */
            return;
        }
    }

    return;
}

static int
azureus_dht_get_k_closest_nodes(struct azureus_dht *ad, struct key *key, int k,
                                struct key *pivot,
                                struct kbucket_node_search_list_head *list, 
                                int *n_list, u8 min_proto_ver, bool use_ext, 
                                bool use_not_alive)
{
    struct key dist;
    int index, max_index;
    int count = 0;
    int ret;
    struct node *tn = NULL, *tnn = NULL;
    struct azureus_node *an = NULL;
    struct kbucket_node_search_list_head sort_list;

    ASSERT(ad && key && k && list && n_list); 

    TAILQ_INIT(list);

    TAILQ_INIT(&sort_list);

    ret = key_distance(pivot, key, &dist);

    max_index = key->len*8*sizeof(key->data[0]);

    /* first, walk forward - 159th bit, 158th bit, ... 0th bit */
    for (index = (max_index - 1); (index >= 0); index--) {

        if (key_nth_bit(&dist, index) != 1) {
            continue;
        }

        LIST_FOREACH_SAFE(tn, 
                    &ad->kbucket[(max_index - 1) - index].node_list, 
                    kb_next, tnn) {

            an = azureus_node_get_ref(tn);
            if (!an->alive) {
                continue;
            }

            if (an->proto_ver < min_proto_ver) {
                continue;
            }

            azureus_dht_insert_sort_closest_node(&sort_list, 
                                                    &ad->this_node->node.id, 
                                                    tn, k);
        }

        if (use_ext) {

            LIST_FOREACH_SAFE(tn, 
                    &ad->kbucket[(max_index - 1) - index].ext_node_list, 
                    kb_next, tnn) {

                an = azureus_node_get_ref(tn);
                if (!an->alive) {
                    continue;
                }

                if (an->proto_ver < min_proto_ver) {
                    continue;
                }

                azureus_dht_insert_sort_closest_node(&sort_list, 
                                                    &ad->this_node->node.id, 
                                                    tn, k);
            }
        }
    }

    /* we walk backwards now - 0th bit, 1st bit ... 159th bit */
    for (index = 0; (index <= (max_index - 1)); index++) {

        if (key_nth_bit(&dist, index) != 0) {
            continue;
        }

        LIST_FOREACH_SAFE(tn, 
                    &ad->kbucket[(max_index - 1) - index].node_list, 
                    kb_next, tnn) {

            an = azureus_node_get_ref(tn);
            if (!an->alive) {
                continue;
            }

            if (an->proto_ver < min_proto_ver) {
                continue;
            }

            azureus_dht_insert_sort_closest_node(&sort_list, 
                                                    &ad->this_node->node.id, 
                                                    tn, k);
        }

        if (use_ext) {

            LIST_FOREACH_SAFE(tn, 
                    &ad->kbucket[(max_index - 1) - index].ext_node_list, 
                    kb_next, tnn) {

                an = azureus_node_get_ref(tn);
                if (!an->alive) {
                    continue;
                }

                if (an->proto_ver < min_proto_ver) {
                    continue;
                }

                azureus_dht_insert_sort_closest_node(&sort_list, 
                                                    &ad->this_node->node.id, 
                                                    tn, k);
            }
        }
    }

    /* once all the parsing and sorting has been done,
     * pick the top 'k' nodes */

    count = 0;
    TAILQ_FOREACH_SAFE(tn, &sort_list, next, tnn) {
        TAILQ_REMOVE(&sort_list, tn, next);
        TAILQ_INSERT_TAIL(list, tn, next);
        count++;
        if (count == k) {
            break;
        }
    }

    *n_list = count;

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
    struct azureus_db_item *item = NULL, *itemn = NULL;
    u64 curr_time = 0;

    ASSERT(ad);

    curr_time = dht_get_current_time();

    if (!azureus_dht_is_stable(ad)) {
        return FAILURE;
    }

    TAILQ_FOREACH_SAFE(item, &ad->db_list, db_next, itemn) {
        if (!item->is_local) {
            /* FIXME: we don't publish the key-value pair if this is not the
             * originating node */
            continue;
        }

        if ((curr_time - item->last_refresh) > STORE_VALUE_TIMEOUT) {
//            azureus_dht_add_store_value_task(ad, item);
        }
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

    azureus_dht_summary(ad);

    return TRUE;
}

void
azureus_dht_exit(struct dht *dht)
{
    struct azureus_dht *ad = NULL;

    ASSERT(dht);

    ad = azureus_dht_get_ref(dht);

    azureus_dht_summary(ad);

    return;
}

static int
azureus_dht_add_db_item(struct azureus_dht *ad, struct azureus_db_key *db_key, 
                        struct azureus_db_valset *db_valset, bool is_local)
{
    struct azureus_db_item *db_item = NULL;

    ASSERT(ad && db_key && db_valset);

    /* if there was already a db_item, remove it! */
    azureus_dht_delete_db_item(ad, db_key);

    db_item = azureus_db_item_new(ad, db_key, db_valset);
    if (!db_item) {
        return FAILURE;
    }

    db_item->is_local = is_local;

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
    INFO("\t%0llu hour(s) %0llu min(s) %0llu sec(s)\n", hour, min, sec);

    INFO("\n");
    INFO("mem usage:\n");
    INFO("\trpc_msg     %d (%d KB)\n", ad->stats.mem.rpc_msg, 
            ad->stats.mem.rpc_msg*sizeof(struct azureus_rpc_msg)/1024);
    INFO("\tnode        %d (%d KB)\n", ad->stats.mem.node,
            ad->stats.mem.node*sizeof(struct azureus_node)/1024);
    INFO("\ttask        %d (%d KB)\n", ad->stats.mem.task,
            ad->stats.mem.task*sizeof(struct azureus_task)/1024);

    INFO("\n");
    INFO("net usage:\n");
    INFO("\trx          %llu bytes %llu Bps\n", 
            ad->stats.net.rx, ad->stats.net.rx/elapsed);
    INFO("\ttx          %llu bytes %llu Bps\n", 
            ad->stats.net.tx, ad->stats.net.tx/elapsed);

    INFO("\n");
    INFO("rpc stats:\n");
    INFO("\tping        req rx %d\n", ad->stats.rpc.ping_req_rx);
    INFO("\tping        rsp tx %d\n", ad->stats.rpc.ping_rsp_tx);
    INFO("\tping        req tx %d\n", ad->stats.rpc.ping_req_tx);
    INFO("\tping        rsp rx %d\n", ad->stats.rpc.ping_rsp_rx);
    INFO("\tfind node   req rx %d\n", ad->stats.rpc.find_node_req_rx);
    INFO("\tfind node   rsp tx %d\n", ad->stats.rpc.find_node_rsp_tx);
    INFO("\tfind node   req tx %d\n", ad->stats.rpc.find_node_req_tx);
    INFO("\tfind node   rsp rx %d\n", ad->stats.rpc.find_node_rsp_rx);
    INFO("\tfind value  req rx %d\n", ad->stats.rpc.find_value_req_rx);
    INFO("\tfind value  rsp tx %d\n", ad->stats.rpc.find_value_rsp_tx);
    INFO("\tfind value  req tx %d\n", ad->stats.rpc.find_value_req_tx);
    INFO("\tfind value  rsp rx %d\n", ad->stats.rpc.find_value_rsp_rx);
    INFO("\tstore value req rx %d\n", ad->stats.rpc.store_value_req_rx);
    INFO("\tstore value rsp tx %d\n", ad->stats.rpc.store_value_rsp_tx);
    INFO("\tstore value req tx %d\n", ad->stats.rpc.store_value_req_tx);
    INFO("\tstore value rsp rx %d\n", ad->stats.rpc.store_value_rsp_rx);
    INFO("\tother           rx %d\n", ad->stats.rpc.other_rx);

    INFO("\n");
    INFO("routing table:\n");
    azureus_dht_print_routing_table_stats(ad);

    INFO("\n");
    INFO("tasks:\n");
    azureus_dht_print_task_stats(ad);

    return;
}

static void
azureus_dht_print_routing_table_stats(struct azureus_dht *ad)
{
    int i;
    struct azureus_node *an = NULL;
    struct node *node = NULL, *noden = NULL;
    int total, alive;
    int ext_total, ext_alive;
    int bigtotal;
    int ext_bigtotal;

    ASSERT(ad);

    bigtotal = 0;
    ext_bigtotal = 0;

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

        ext_total = 0;
        ext_alive = 0;

        LIST_FOREACH_SAFE(node, &ad->kbucket[i].ext_node_list, kb_next, noden) {
            an = azureus_node_get_ref(node);
            ext_total++;
            if (an->alive) {
                ext_alive++;
            }
        }

        if (!total) {
            continue;
        }

        INFO("\tkbucket #%3d  (M) total %2d alive %2d   "
                "(E) total %3d alive %3d\n", 
                i, total, alive, ext_total, ext_alive);
        bigtotal += total;
        ext_bigtotal += ext_total;
    }

    INFO("\n");
    INFO("\tkbucket total %d      (M) total %d    (E) total %d\n", 
            bigtotal + ext_bigtotal, bigtotal, ext_bigtotal);

    return;
}

static void
azureus_dht_print_task_stats(struct azureus_dht *ad)
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

    INFO("\ttask total %d         new %d  wait %d\n", 
            count, (count - wt_count), wt_count);

    return;
}

/* Rate-limiting */
static void
azureus_dht_net_usage_update(struct azureus_dht *ad, size_t size, 
                                enum pkt_dir pkt_dir)
{
    ASSERT(ad);

    tinydht_rate_limit_update(size);

    switch (pkt_dir) {

        case PKT_DIR_TX:
            ad->stats.net.tx += size;
            break;

        case PKT_DIR_RX:
            ad->stats.net.rx += size;
            break;

        default:
            ASSERT(0);
    }

    return;
}

static bool
azureus_dht_rate_limit_allow(struct azureus_dht *ad)
{
    static u64 prev_time = 0;
    u64 curr_time = 0;
    u64 elapsed = 0;
    u64 n_rx_tx = 0;

    if (!tinydht_rate_limit_allow()) {
        return FALSE;
    }

    curr_time = dht_get_current_time();

    if (prev_time == 0) {
        prev_time = curr_time;
        return TRUE;
    }

    elapsed = (curr_time - prev_time)/1000;

    // DEBUG("elapsed %lld size %lld\n", elapsed, n_rx_tx);
    // DEBUG("result %lld\n", (elapsed*(RATE_LIMIT_BITS_PER_SEC/1000)));
    
    n_rx_tx = ad->stats.net.rx + ad->stats.net.tx;

    if ((elapsed*(RATE_LIMIT_BITS_PER_SEC/1000)) < (n_rx_tx*8)) {
        return FALSE;
    }

    return TRUE;
}
