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
#include <stdio.h>
#include <string.h>

#include "azureus_rpc.h"
#include "azureus_rpc_utils.h"
#include "azureus_dht.h"
#include "azureus_node.h"
#include "dht.h"
#include "debug.h"
#include "crypto.h"
#include "pkt.h"
#include "types.h"
#include "tinydht.h"
#include "azureus_vivaldi.h"
#include "node.h"

static int is_valid_rpc_action(u32 action);
static int is_valid_rpc_req_action(u32 action);
static int is_valid_rpc_rsp_action(u32 action);

static int msg_is_rpc_req(struct azureus_rpc_msg *msg, bool *req);
static int msg_get_rpc_action(struct azureus_rpc_msg *msg, u32 *action);

static int azureus_rpc_ping_req_encode(struct azureus_rpc_msg *msg);
static int azureus_rpc_ping_req_decode(struct azureus_rpc_msg *msg);
static int azureus_rpc_ping_rsp_encode(struct azureus_rpc_msg *msg);
static int azureus_rpc_ping_rsp_decode(struct azureus_rpc_msg *msg);

static int azureus_rpc_find_node_req_encode(struct azureus_rpc_msg *msg);
static int azureus_rpc_find_node_req_decode(struct azureus_rpc_msg *msg);
static int azureus_rpc_find_node_rsp_encode(struct azureus_rpc_msg *msg);
static int azureus_rpc_find_node_rsp_decode(struct azureus_rpc_msg *msg);

static int azureus_rpc_find_value_req_encode(struct azureus_rpc_msg *msg);
static int azureus_rpc_find_value_req_decode(struct azureus_rpc_msg *msg);
static int azureus_rpc_find_value_rsp_encode(struct azureus_rpc_msg *msg);
static int azureus_rpc_find_value_rsp_decode(struct azureus_rpc_msg *msg);

static int azureus_rpc_store_value_req_encode(struct azureus_rpc_msg *msg);
static int azureus_rpc_store_value_req_decode(struct azureus_rpc_msg *msg);
static int azureus_rpc_store_value_rsp_encode(struct azureus_rpc_msg *msg);
static int azureus_rpc_store_value_rsp_decode(struct azureus_rpc_msg *msg);

static int azureus_rpc_vivaldi_encode(struct azureus_rpc_msg *msg);
static int azureus_rpc_vivaldi_decode(struct azureus_rpc_msg *msg);

struct azureus_rpc_msg *
azureus_rpc_msg_new(struct azureus_dht *ad, 
                    struct sockaddr_storage *ss,
                    size_t sslen,
                    u8 *data, 
                    int len)
{
    struct azureus_rpc_msg *msg = NULL;
    int ret;

    ASSERT(ad && (len >= 0));

    msg = (struct azureus_rpc_msg *) malloc(sizeof(struct azureus_rpc_msg));
    if (!msg) {
        return NULL;
    }

    ad->stats.mem.rpc_msg++;

    bzero(msg, sizeof(struct azureus_rpc_msg));

    ret = pkt_new(&msg->pkt, &ad->dht, ss, sslen, data, len);
    if (ret != SUCCESS) {
        goto err;
    }

    return msg;

err:
    azureus_rpc_msg_delete(msg);
    return NULL;
}

void
azureus_rpc_msg_delete(struct azureus_rpc_msg *msg)
{
    struct azureus_dht *ad = NULL;
    struct azureus_node *an = NULL, *ann = NULL;
    struct azureus_db_key *db_key = NULL, *db_keyn = NULL;
    struct azureus_db_valset *db_valset = NULL, *db_valsetn = NULL;

    ASSERT(msg);

    ad = azureus_dht_get_ref(msg->pkt.dht);

    if (msg->pkt.dir != PKT_DIR_RX) {
        goto out;
    }

    switch (msg->action) {

        case ACT_REQUEST_STORE:

            TAILQ_FOREACH_SAFE(db_key, &msg->m.store_value_req.key_list,
                    next, db_keyn) {
                TAILQ_REMOVE(&msg->m.store_value_req.key_list, db_key, next);
                azureus_db_key_delete(db_key);
            }

            TAILQ_FOREACH_SAFE(db_valset, &msg->m.store_value_req.valset_list,
                    next, db_valsetn) {
                TAILQ_REMOVE(&msg->m.store_value_req.valset_list,
                        db_valset, next);
                azureus_db_valset_delete(db_valset);
            }

            break;

        case ACT_REPLY_FIND_NODE:

            TAILQ_FOREACH_SAFE(an, &msg->m.find_node_rsp.node_list, 
                    next, ann) {
                TAILQ_REMOVE(&msg->m.find_node_rsp.node_list, an, next);
                azureus_node_delete(an);
            }

            break;

        case ACT_REPLY_FIND_VALUE:

            TAILQ_FOREACH_SAFE(an, &msg->m.find_value_rsp.node_list, 
                    next, ann) {
                TAILQ_REMOVE(&msg->m.find_value_rsp.node_list, an, next);
                azureus_node_delete(an);
            }

            break;

        default:
            break;
    }

out:
    free(msg);
    ad->stats.mem.rpc_msg--;
}

int
azureus_rpc_msg_encode(struct azureus_rpc_msg *msg)
{
    int ret;

    ASSERT(msg);

    if (msg->is_encoded) {
        return SUCCESS;
    }

    switch (msg->action) {
        case ACT_REQUEST_PING:
            ret = azureus_rpc_ping_req_encode(msg);
            break;

        case ACT_REPLY_PING:
            ret = azureus_rpc_ping_rsp_encode(msg);
            break;

        case ACT_REQUEST_FIND_NODE:
            ret = azureus_rpc_find_node_req_encode(msg);
            break;

        case ACT_REPLY_FIND_NODE:
            ret = azureus_rpc_find_node_rsp_encode(msg);
            break;

        case ACT_REQUEST_FIND_VALUE:
            ret = azureus_rpc_find_value_req_encode(msg);
            break;

        case ACT_REPLY_FIND_VALUE:
            ret = azureus_rpc_find_value_rsp_encode(msg);
            break;

        case ACT_REQUEST_STORE:
            ret = azureus_rpc_store_value_req_encode(msg);
            break;

        case ACT_REPLY_STORE:
            ret = azureus_rpc_store_value_rsp_encode(msg);
            break;

        default:
            return FAILURE;
    }

    /* set the 'is_req' flag appropriately */
    ret = msg_is_rpc_req(msg, &msg->is_req);
    if (ret != SUCCESS) {
        azureus_rpc_msg_delete(msg);
        return FAILURE;
    }

    msg->is_encoded = TRUE;

    pkt_dump(&msg->pkt);

    return SUCCESS;
}

int 
azureus_rpc_msg_decode(struct azureus_dht *ad, 
                    struct sockaddr_storage *from, 
                    size_t fromlen,
                    u8 *data, 
                    int len,
                    struct azureus_rpc_msg **m)
{
    struct azureus_rpc_msg *msg = NULL;
    int ret;

    msg = azureus_rpc_msg_new(ad, from, fromlen, data, len);
    if (!msg) {
        return FAILURE;
    }

    pkt_dump(&msg->pkt);

    ret = msg_get_rpc_action(msg, &msg->action);
    if (ret != SUCCESS) {
        azureus_rpc_msg_delete(msg);
        return ret;
    }

    ret = msg_is_rpc_req(msg, &msg->is_req);
    if (ret != SUCCESS) {
        azureus_rpc_msg_delete(msg);
        return FAILURE;
    }

    switch (msg->action) {

        case ACT_REQUEST_PING:
            DEBUG("REQUEST_PING\n");
            ret = azureus_rpc_ping_req_decode(msg);
            break;

        case ACT_REPLY_PING:
            DEBUG("REPLY_PING\n");
            ret = azureus_rpc_ping_rsp_decode(msg);
            break;

        case ACT_REQUEST_FIND_NODE:
            DEBUG("REQUEST_FIND_NODE\n");
            ret = azureus_rpc_find_node_req_decode(msg);
            break;

        case ACT_REPLY_FIND_NODE:
            DEBUG("REPLY_FIND_NODE\n");
            ret = azureus_rpc_find_node_rsp_decode(msg);
            break;

        case ACT_REQUEST_FIND_VALUE:
            DEBUG("REQUEST_FIND_VALUE\n");
            ret = azureus_rpc_find_value_req_decode(msg);
            break;

        case ACT_REPLY_FIND_VALUE:
            DEBUG("REPLY_FIND_VALUE\n");
            ret = azureus_rpc_find_value_rsp_decode(msg);
            break;

        case ACT_REQUEST_STORE:
            DEBUG("REQUEST_STORE\n");
            ret = azureus_rpc_store_value_req_decode(msg);
            break;

        case ACT_REPLY_STORE:
            DEBUG("REPLY_STORE\n");
            ret = azureus_rpc_store_value_rsp_decode(msg);
            break;

        case ACT_REPLY_ERROR:
            DEBUG("REPLY ERROR\n");
            azureus_rpc_msg_delete(msg);
            return FAILURE;

        default:
            azureus_rpc_msg_delete(msg);
            return FAILURE;
    }

    if (ret != SUCCESS) {
        azureus_rpc_msg_delete(msg);
        return ret;
    }

    if (msg->pkt.cursor != msg->pkt.len) {
        ERROR("unread bytes in pkt!\n");
        azureus_rpc_msg_delete(msg);
        return ret;
    }

    *m = msg;

    return SUCCESS;
}

static u32
azureus_rpc_get_new_trans_id(struct dht *dht)
{
    struct azureus_dht *ad = NULL;
    u32 trans_id;

    ad = azureus_dht_get_ref(dht);
    trans_id = ad->trans_id;
    ad->trans_id++;

    return trans_id;
}

static int
is_valid_rpc_action(u32 action)
{
    int ret = FALSE;

    switch (action) {
        case ACT_REQUEST_PING:
        case ACT_REQUEST_STORE:
        case ACT_REQUEST_FIND_NODE:
        case ACT_REQUEST_FIND_VALUE:
        case ACT_REPLY_PING:
        case ACT_REPLY_STORE:
        case ACT_REPLY_FIND_NODE:
        case ACT_REPLY_FIND_VALUE:
        case ACT_REPLY_ERROR:
        case ACT_REPLY_STATS:
        case ACT_REQUEST_STATS:
        case ACT_DATA:
        case ACT_REQUEST_KEY_BLOCK:
        case ACT_REPLY_KEY_BLOCK:
            ret = TRUE;
            break;

        default:
            break;
    }

    return ret;
}

static int
is_valid_rpc_req_action(u32 action) 
{
    int ret = FALSE;

    switch (action) {
        case ACT_REQUEST_PING:
        case ACT_REQUEST_STORE:
        case ACT_REQUEST_FIND_NODE:
        case ACT_REQUEST_FIND_VALUE:
        case ACT_REQUEST_STATS:
        case ACT_REQUEST_KEY_BLOCK:
            ret = TRUE;
            break;

        default:
            break;
    }

    return ret;
}

static int
is_valid_rpc_rsp_action(u32 action)
{
    int ret = FALSE;

    switch (action) {
        case ACT_REPLY_PING:
        case ACT_REPLY_STORE:
        case ACT_REPLY_FIND_NODE:
        case ACT_REPLY_FIND_VALUE:
        case ACT_REPLY_ERROR:
        case ACT_REPLY_STATS:
        case ACT_REPLY_KEY_BLOCK:
            ret = TRUE;
            break;

        default:
            break;
    }

    return ret;
}
    
static int
msg_is_rpc_req(struct azureus_rpc_msg *msg, bool *req)
{
    u32 action = 0;
    int ret;

    ASSERT(msg);

    ret = pkt_peek(&msg->pkt, 0, &action, sizeof(action));
    if (ret != SUCCESS) {
        return FAILURE;
    }

    if (is_valid_rpc_rsp_action(ntohl(action))) {
        /* this is a response */
        *req = FALSE;
        return SUCCESS;
    }

    ret = pkt_peek(&msg->pkt, sizeof(u64), &action, sizeof(u32));
    if (ret != SUCCESS) {
        return FAILURE;
    }

    if (is_valid_rpc_req_action(ntohl(action))) {
        *req = TRUE;
        return SUCCESS;
    }

    return FAILURE;
}

static int
msg_get_rpc_action(struct azureus_rpc_msg *msg, u32 *action)
{
    bool is_req = FALSE;
    int ret;

    ASSERT(msg && action);

    ret = msg_is_rpc_req(msg, &is_req);
    if (ret != SUCCESS) {
        return ret;
    }

    if (is_req) {       /* request */
        DEBUG("REQUEST\n");
        /* skip over conn_id */
        ret = pkt_peek(&msg->pkt, sizeof(u64), action, sizeof(u32));
        if (ret != SUCCESS) {
            return ret;
        }
        *action = ntohl(*action);
        DEBUG("action %#x\n", *action);
        DEBUG("pkt cursor %#x\n", msg->pkt.cursor);
    } else {            /* response */
        DEBUG("REPLY\n");
        ret = pkt_peek(&msg->pkt, 0, action, sizeof(u32));
        if (ret != SUCCESS) {
            return ret;
        }
        *action = ntohl(*action);
        DEBUG("action %#x\n", *action);
        DEBUG("pkt cursor %#x\n", msg->pkt.cursor);
    }

    return SUCCESS;
}

bool
azureus_rpc_match_req_rsp(struct azureus_rpc_msg *req, 
                            struct azureus_rpc_msg *rsp)
{
    ASSERT(req && rsp);
    ASSERT(req->is_req && !rsp->is_req);

//    DEBUG("%#llx %#llx\n", req->p.pr_udp_req.conn_id, rsp->u.udp_rsp.conn_id);

    if (req->p.pr_udp_req.conn_id == rsp->u.udp_rsp.conn_id) {
        return TRUE;
    } else {
        return FALSE;
    }
}

/*--------------------------------------------------------
 *
 *              Azureus PR_UDP
 *
 *-------------------------------------------------------*/

static int
azureus_rpc_pr_udp_req_encode(struct azureus_rpc_msg *msg)
{
    u64 conn_id = 0;
    u32 trans_id;
    int ret;

    ASSERT(msg);

    crypto_get_rnd_bytes(&conn_id, sizeof(u_int64_t));
    conn_id |= 0x8000000000000000ULL;
    ret = pkt_write_long(&msg->pkt, conn_id);
    if (ret != SUCCESS) {
        return ret;
    }
    msg->p.pr_udp_req.conn_id = conn_id;

    ret = pkt_write_int(&msg->pkt, msg->action);
    if (ret != SUCCESS) {
        return ret;
    }
    msg->p.pr_udp_req.action = msg->action;

    trans_id = azureus_rpc_get_new_trans_id(msg->pkt.dht);
    ret = pkt_write_int(&msg->pkt, trans_id);
    if (ret != SUCCESS) {
        return ret;
    }
    msg->p.pr_udp_req.trans_id = trans_id;

    return SUCCESS;
}

static int
azureus_rpc_pr_udp_req_decode(struct azureus_rpc_msg *msg)
{
    u64 conn_id = 0;
    u32 action = 0;
    u32 trans_id = 0;
    int ret;

    ASSERT(msg);

    ret = pkt_read_long(&msg->pkt, &conn_id);
    if (ret != SUCCESS) {
        return ret;
    }
    msg->p.pr_udp_req.conn_id = conn_id;

    ret = pkt_read_int(&msg->pkt, &action);
    if (ret != SUCCESS) {
        return ret;
    }
    msg->p.pr_udp_req.action = action;

    if (!is_valid_rpc_action(action)) {
        return FAILURE;
    }

    ret = pkt_read_int(&msg->pkt, &trans_id);
    if (ret != SUCCESS) {
        return ret;
    }
    msg->p.pr_udp_req.trans_id = trans_id;

    return SUCCESS;
}

static int
azureus_rpc_pr_udp_rsp_encode(struct azureus_rpc_msg *msg)
{
    int ret;

    ASSERT(msg);

    ret = pkt_write_int(&msg->pkt, msg->action);
    if (ret != SUCCESS) {
        return ret;
    }
    msg->p.pr_udp_rsp.action = msg->action;

    ret = pkt_write_int(&msg->pkt, msg->r.req->p.pr_udp_req.trans_id);
    if (ret != SUCCESS) {
        return ret;
    }

    return SUCCESS;
}

static int
azureus_rpc_pr_udp_rsp_decode(struct azureus_rpc_msg *msg)
{
    u32 action = 0;
    u32 trans_id = 0;
    int ret;

    ASSERT(msg);

    ret = pkt_read_int(&msg->pkt, &action);
    if (ret != SUCCESS) {
        return ret;
    }
    msg->p.pr_udp_rsp.action = action;

    if (!is_valid_rpc_action(action)) {
        return ret;
    }

    ret = pkt_read_int(&msg->pkt, &trans_id);
    if (ret != SUCCESS) {
        return ret;
    }
    msg->p.pr_udp_rsp.trans_id = trans_id;

    return SUCCESS;
}


/*-----------------------------------------------------
 *
 *      Azureus UDP stuff
 *
 *---------------------------------------------------*/

static int
azureus_rpc_udp_req_encode(struct azureus_rpc_msg *msg)
{
    u64 timestamp = 0;
    int ret;
    struct azureus_dht *ad = NULL;

    ASSERT(msg);

    /* First, encode the PR_UDP req */
    ret = azureus_rpc_pr_udp_req_encode(msg);
    if (ret != SUCCESS) {
        return ret;
    }

    ad = azureus_dht_get_ref(msg->pkt.dht);

    ret = pkt_write_byte(&msg->pkt, ad->proto_ver);
    if (ret != SUCCESS) {
        return ret;
    }
    msg->u.udp_req.proto_ver = ad->proto_ver;

    if (ad->proto_ver >= PROTOCOL_VERSION_VENDOR_ID) {
        ret = pkt_write_byte(&msg->pkt, VENDOR_ID_ME);
        if (ret != SUCCESS) {
            return ret;
        }
        msg->u.udp_req.vendor_id = VENDOR_ID_ME;
    }

    if (ad->proto_ver >= PROTOCOL_VERSION_NETWORKS) {
        ret = pkt_write_int(&msg->pkt, ad->network);
        if (ret != SUCCESS) {
            return ret;
        }
        msg->u.udp_req.network = ad->network;
    }

    if (ad->proto_ver >= PROTOCOL_VERSION_FIX_ORIGINATOR) {
        ret = pkt_write_byte(&msg->pkt, ad->proto_ver);
        if (ret != SUCCESS) {
            return ret;
        }
        msg->u.udp_req.orig_ver = ad->proto_ver;
    }

    ret = azureus_pkt_write_inetaddr(&msg->pkt, &ad->this_node->ext_addr);
    if (ret != SUCCESS) {
        return ret;
    }

    ret = pkt_write_int(&msg->pkt, ad->instance_id);
    if (ret != SUCCESS) {
        return ret;
    }
    msg->u.udp_req.orig_inst_id = ad->instance_id;

    timestamp = dht_get_current_time();
    ret = pkt_write_long(&msg->pkt, timestamp);
    if (ret != SUCCESS) {
        return ret;
    }
    msg->u.udp_req.orig_time = timestamp;

    return SUCCESS;
}

static int
azureus_rpc_udp_req_post_encode(struct azureus_rpc_msg *msg)
{
    struct azureus_dht *ad = NULL;
    int ret;

    ASSERT(msg);

    ad = azureus_dht_get_ref(msg->pkt.dht);

    /* post-serialize */
    if (ad->proto_ver < PROTOCOL_VERSION_FIX_ORIGINATOR) {
        ret = pkt_write_byte(&msg->pkt, ad->proto_ver);
        if (ret != SUCCESS) {
            return ret;
        }
    }

    return SUCCESS;
}

static int
azureus_rpc_udp_req_decode(struct azureus_rpc_msg *msg)
{
    u8 proto_ver, orig_ver;
    u8 vendor_id;
    u32 network;
    u32 instance_id;
    struct sockaddr_storage ss;
    u64 timestamp;
    int ret;

    ASSERT(msg);

    ret = azureus_rpc_pr_udp_req_decode(msg);
    if (ret != SUCCESS) {
        return ret;
    }

    ret = pkt_read_byte(&msg->pkt, &proto_ver);
    if (ret != SUCCESS) {
        return ret;
    }
    msg->u.udp_req.proto_ver = proto_ver;

    if (proto_ver < PROTOCOL_VERSION_MIN) {
        /* Azureus Client needs updating */
        return FAILURE;
    }

    if (proto_ver >= PROTOCOL_VERSION_VENDOR_ID) {
        ret = pkt_read_byte(&msg->pkt, &vendor_id);
        if (ret != SUCCESS) {
            return ret;
        }
        msg->u.udp_req.vendor_id = vendor_id;
    }

    if (proto_ver >= PROTOCOL_VERSION_NETWORKS) {
        ret = pkt_read_int(&msg->pkt, &network);
        if (ret != SUCCESS) {
            return ret;
        }
        msg->u.udp_req.network = network;
    }

    /* originator's version to be used? */
    if (proto_ver >= PROTOCOL_VERSION_FIX_ORIGINATOR) {
        ret = pkt_read_byte(&msg->pkt, &orig_ver);
        if (ret != SUCCESS) {
            return ret;
        }
        msg->u.udp_req.orig_ver = orig_ver;
    } else {
        msg->u.udp_req.orig_ver = proto_ver;
    }

    ret = azureus_pkt_read_inetaddr(&msg->pkt, &ss);
    if (ret != SUCCESS) {
        return ret;
    }
    memcpy(&msg->u.udp_req.ss, &ss, sizeof(struct sockaddr_storage));

    ret = pkt_read_int(&msg->pkt, &instance_id);
    if (ret != SUCCESS) {
        return ret;
    }
    msg->u.udp_req.orig_inst_id = instance_id;

    ret = pkt_read_long(&msg->pkt, &timestamp);
    if (ret != SUCCESS) {
        return ret;
    }
    msg->u.udp_req.orig_time = timestamp;

    return SUCCESS;
}

static int
azureus_rpc_udp_req_post_decode(struct azureus_rpc_msg *msg)
{
    struct azureus_dht *ad = NULL;
    u8 proto_ver;
    u8 orig_ver;
    int ret;

    ASSERT(msg);

    ad = azureus_dht_get_ref(msg->pkt.dht);

    proto_ver = msg->u.udp_req.proto_ver;

    if (proto_ver < PROTOCOL_VERSION_FIX_ORIGINATOR) {
        if (pkt_read_is_avail(&msg->pkt)) {
            ret = pkt_read_byte(&msg->pkt, &orig_ver);
            if (ret != SUCCESS) {
                return ret;
            }
            msg->u.udp_req.orig_ver = orig_ver;
        } else {
            msg->u.udp_req.orig_ver = ad->proto_ver;
        }

        if (orig_ver > ad->proto_ver) {
            msg->u.udp_req.orig_ver = ad->proto_ver;
        }
    }

    return SUCCESS;
}

static int
azureus_rpc_udp_rsp_encode(struct azureus_rpc_msg *msg)
{
    struct azureus_dht *ad = NULL;
    int ret;

    ASSERT(msg);

    ret = azureus_rpc_pr_udp_rsp_encode(msg);
    if (ret != SUCCESS) {
        return ret;
    }

    ASSERT(msg->r.req);

    ret = pkt_write_long(&msg->pkt, msg->r.req->p.pr_udp_req.conn_id);
    if (ret != SUCCESS) {
        return ret;
    }

    ad = azureus_dht_get_ref(msg->pkt.dht);

    ret = pkt_write_byte(&msg->pkt, ad->proto_ver);
    if (ret != SUCCESS) {
        return ret;
    }

    if (ad->proto_ver >= PROTOCOL_VERSION_VENDOR_ID) {
        ret = pkt_write_byte(&msg->pkt, VENDOR_ID_ME);
        if (ret != SUCCESS) {
            return ret;
        }
    }

    if (ad->proto_ver >= PROTOCOL_VERSION_NETWORKS) {
        ret = pkt_write_int(&msg->pkt, ad->network);
        if (ret != SUCCESS) {
            return ret;
        }
    }

    ret = pkt_write_int(&msg->pkt, ad->instance_id);
    if (ret != SUCCESS) {
        return ret;
    }

    return SUCCESS;
}

static int
azureus_rpc_udp_rsp_decode(struct azureus_rpc_msg *msg)
{
    u_int64_t conn_id;
    u_int8_t proto_ver;
    u_int8_t vendor_id;
    u_int32_t network;
    u_int32_t tgt_inst_id;
    int ret;

    ASSERT(msg);

    ret = azureus_rpc_pr_udp_rsp_decode(msg);
    if (ret != SUCCESS) {
        return ret;
    }

    ret = pkt_read_long(&msg->pkt, &conn_id);
    if (ret != SUCCESS) {
        return ret;
    }
    msg->u.udp_rsp.conn_id = conn_id;

    ret = pkt_read_byte(&msg->pkt, &proto_ver);
    if (ret != SUCCESS) {
        return ret;
    }
    msg->u.udp_rsp.proto_ver = proto_ver;

    if (proto_ver >= PROTOCOL_VERSION_VENDOR_ID) {
        ret = pkt_read_byte(&msg->pkt, &vendor_id);
        if (ret != SUCCESS) {
            return ret;
        }
        msg->u.udp_rsp.vendor_id = vendor_id;
    }

    if (proto_ver >= PROTOCOL_VERSION_NETWORKS) {
        ret = pkt_read_int(&msg->pkt, &network);
        if (ret != SUCCESS) {
            return ret;
        }
        msg->u.udp_rsp.network = network;
    }

    ret = pkt_read_int(&msg->pkt, &tgt_inst_id);
    if (ret != SUCCESS) {
        return ret;
    }
    msg->u.udp_rsp.tgt_inst_id = tgt_inst_id;

    return SUCCESS;
}

/*-------------------------------------
 *
 *      Azureus RPC - Ping
 *
 *------------------------------------*/

static int
azureus_rpc_ping_req_encode(struct azureus_rpc_msg *msg)
{
    int ret;

    ASSERT(msg);

    ret = azureus_rpc_udp_req_encode(msg);
    if (ret != SUCCESS) {
        return ret;
    }

    ret = azureus_rpc_udp_req_post_encode(msg);
    if (ret != SUCCESS) {
        return ret;
    }

    return SUCCESS;
}

static int
azureus_rpc_ping_req_decode(struct azureus_rpc_msg *msg)
{
    int ret;

    ASSERT(msg);

    ret = azureus_rpc_udp_req_decode(msg);
    if (ret != SUCCESS) {
        return ret;
    }

    ret = azureus_rpc_udp_req_post_decode(msg);
    if (ret != SUCCESS) {
        return ret;
    }

    return SUCCESS;
}

static int
azureus_rpc_ping_rsp_encode(struct azureus_rpc_msg *msg)
{
    struct azureus_dht *ad = NULL;
    int ret;

    ASSERT(msg);

    ret = azureus_rpc_udp_rsp_encode(msg);
    if (ret != SUCCESS) {
        return ret;
    }

    ad = azureus_dht_get_ref(msg->pkt.dht);

    if (ad->proto_ver >= PROTOCOL_VERSION_VIVALDI) {
        ret = azureus_rpc_vivaldi_encode(msg);
        if (ret != SUCCESS) {
            return ret;
        }
    }

    return SUCCESS;
}

static int
azureus_rpc_ping_rsp_decode(struct azureus_rpc_msg *msg)
{
    struct azureus_dht *ad = NULL;
    int ret;

    ASSERT(msg);

    ret = azureus_rpc_udp_rsp_decode(msg);
    if (ret != SUCCESS) {
        return ret;
    }

    ad = azureus_dht_get_ref(msg->pkt.dht);
    
    if (msg->u.udp_rsp.proto_ver >= PROTOCOL_VERSION_VIVALDI) {
        ret = azureus_rpc_vivaldi_decode(msg);
        if (ret != SUCCESS) {
            return ret;
        }
    }

    return SUCCESS;
}

/*-------------------------------------
 *
 *      Azureus RPC - Find Node
 *
 *------------------------------------*/

static int
azureus_rpc_find_node_req_encode(struct azureus_rpc_msg *msg)
{
    int ret;

    ASSERT(msg);

    ret = azureus_rpc_udp_req_encode(msg);
    if (ret != SUCCESS) {
        return ret;
    }

    ret = pkt_write_byte(&msg->pkt, 20);
    if (ret != SUCCESS) {
        return ret;
    }

    ret = pkt_write_arr(&msg->pkt, msg->m.find_node_req.id, 20);
    if (ret != SUCCESS) {
        return ret;
    }

    ret = azureus_rpc_udp_req_post_encode(msg);
    if (ret != SUCCESS) {
        return ret;
    }

    return SUCCESS;
}

static int
azureus_rpc_find_node_req_decode(struct azureus_rpc_msg *msg)
{
    int ret;
    u_int8_t id_len;
    u_int8_t id[20];

    ASSERT(msg);

    ret = azureus_rpc_udp_req_decode(msg);
    if (ret != SUCCESS) {
        return ret;
    }

    ret = pkt_read_byte(&msg->pkt, &id_len);
    if (ret != SUCCESS) {
        return ret;
    }
    msg->m.find_node_req.id_len = id_len;

    ret = pkt_read_arr(&msg->pkt, id, id_len);
    if (ret != SUCCESS) {
        return ret;
    }
    memcpy(msg->m.find_node_req.id, id, id_len); 

    ret = azureus_rpc_udp_req_post_decode(msg);
    if (ret != SUCCESS) {
        return ret;
    }

    return SUCCESS;
}

static int
azureus_rpc_find_node_rsp_encode(struct azureus_rpc_msg *msg)
{
    struct azureus_dht *ad = NULL;
    struct azureus_node *azn = NULL;
    int ret;

    ASSERT(msg);

    ret = azureus_rpc_udp_rsp_encode(msg);
    if (ret != SUCCESS) {
        return ret;
    }

    ad = azureus_dht_get_ref(msg->pkt.dht);

    if (ad->proto_ver >= PROTOCOL_VERSION_ANTI_SPOOF) {
        ret = pkt_write_int(&msg->pkt, msg->m.find_node_rsp.rnd_id);
        if (ret != SUCCESS) {
            return ret;
        }
    }

    if (ad->proto_ver >= PROTOCOL_VERSION_XFER_STATUS) {
        ret = pkt_write_int(&msg->pkt, ad->this_node->node_status);
        if (ret != SUCCESS) {
            return ret;
        }
    }

    if (ad->proto_ver >= PROTOCOL_VERSION_SIZE_ESTIMATE) {
        ret = pkt_write_int(&msg->pkt, ad->est_dht_size);
        if (ret != SUCCESS) {
            return ret;
        }
    }

    if (ad->proto_ver >= PROTOCOL_VERSION_VIVALDI) {
        ret = azureus_rpc_vivaldi_encode(msg);
        if (ret != SUCCESS) {
            return ret;
        }
    }

    ret = pkt_write_short(&msg->pkt, msg->m.find_node_rsp.n_nodes);
    if (ret != SUCCESS) {
        return ret;
    }

    TAILQ_FOREACH(azn, &msg->m.find_node_rsp.node_list, next) {
        ret = azureus_pkt_write_node(&msg->pkt, azn);
        if (ret != SUCCESS) {
            return ret;
        }
    }

    return SUCCESS;
}

static int
azureus_rpc_find_node_rsp_decode(struct azureus_rpc_msg *msg)
{
    struct azureus_dht *ad = NULL;
    u32 rnd_id;
    u32 node_status;
    u32 est_dht_size = 0;
    u32 i = 0;
    struct azureus_node azn, *pazn = NULL;
    int ret;

    ASSERT(msg);

    TAILQ_INIT(&msg->m.find_node_rsp.node_list);

    ret = azureus_rpc_udp_rsp_decode(msg);
    if (ret != SUCCESS) {
        return ret;
    }

    DEBUG("pkt cursor %#x\n", msg->pkt.cursor);

    ad = azureus_dht_get_ref(msg->pkt.dht);

    if (msg->u.udp_rsp.proto_ver >= PROTOCOL_VERSION_ANTI_SPOOF) {
        ret = pkt_read_int(&msg->pkt, &rnd_id);
        if (ret != SUCCESS) {
            return ret;
        }
        /* FIXME: verify the random_id */
        msg->m.find_node_rsp.rnd_id = rnd_id;

        DEBUG("rnd_id %#0x\n", rnd_id);
    }

    if (msg->u.udp_rsp.proto_ver >= PROTOCOL_VERSION_XFER_STATUS) {
        ret = pkt_read_int(&msg->pkt, &node_status);
        if (ret != SUCCESS) {
            return ret;
        }
        /* FIXME: check if this node is routable? */
        msg->m.find_node_rsp.node_status = node_status;
    }
    msg->m.find_node_rsp.node_status = node_status;

    if (msg->u.udp_rsp.proto_ver >= PROTOCOL_VERSION_SIZE_ESTIMATE) {
        ret = pkt_read_int(&msg->pkt, &est_dht_size);
        if (ret != SUCCESS) {
            return ret;
        }
        /* FIXME: do something more about this? */
        msg->m.find_node_rsp.est_dht_size = est_dht_size;
    }

    DEBUG("pkt cursor %#x\n", msg->pkt.cursor);

    if (msg->u.udp_rsp.proto_ver >= PROTOCOL_VERSION_VIVALDI) {
        ret = azureus_rpc_vivaldi_decode(msg);
        if (ret != SUCCESS) {
            return ret;
        }
    }

    ret = pkt_read_short(&msg->pkt, &msg->m.find_node_rsp.n_nodes);
    if (ret != SUCCESS) {
        return ret;
    }


    for (i = 0; i < msg->m.find_node_rsp.n_nodes; i++) {
        ret = azureus_pkt_read_node(&msg->pkt, &azn);
        if (ret != SUCCESS) {
            return ret;
        }

        pazn = azureus_node_new(ad, azn.proto_ver, &azn.ext_addr);
        if (!pazn) {
            return FAILURE;
        }

        TAILQ_INSERT_TAIL(&msg->m.find_node_rsp.node_list, pazn, next);
    }

    return SUCCESS;
}

/*-------------------------------------
 *
 *      Azureus RPC - Find Value
 *
 *------------------------------------*/

static int
azureus_rpc_find_value_req_encode(struct azureus_rpc_msg *msg)
{
    int ret;

    ASSERT(msg);

    ret = azureus_rpc_udp_req_encode(msg);
    if (ret != SUCCESS) {
        return ret;
    }

    ret = pkt_write_byte(&msg->pkt, msg->m.find_value_req.key.len);
    if (ret != SUCCESS) {
        return ret;
    }

    ret = pkt_write_arr(&msg->pkt, msg->m.find_value_req.key.data, 
                        msg->m.find_value_req.key.len);
    if (ret != SUCCESS) {
        return ret;
    }

    ret = pkt_write_byte(&msg->pkt, msg->m.find_value_req.flags);
    if (ret != SUCCESS) {
        return ret;
    }

    ret = pkt_write_byte(&msg->pkt, msg->m.find_value_req.max_vals);
    if (ret != SUCCESS) {
        return ret;
    }

    ret = azureus_rpc_udp_req_post_encode(msg);
    if (ret != SUCCESS) {
        return ret;
    }

    return SUCCESS;
}

static int
azureus_rpc_find_value_req_decode(struct azureus_rpc_msg *msg)
{
    int ret;
    u_int8_t flags, max_vals;

    ASSERT(msg);

    ret = azureus_rpc_udp_req_decode(msg);
    if (ret != SUCCESS) {
        return ret;
    }

    ret = pkt_read_byte(&msg->pkt, &msg->m.find_value_req.key.len);
    if (ret != SUCCESS) {
        return ret;
    }

    ret = pkt_read_arr(&msg->pkt, msg->m.find_value_req.key.data, 
                        msg->m.find_value_req.key.len);
    if (ret != SUCCESS) {
        return ret;
    }

    DEBUG("key len %d\n", msg->m.find_value_req.key.len);

    ret = pkt_read_byte(&msg->pkt, &flags);
    if (ret != SUCCESS) {
        return ret;
    }
    msg->m.find_value_req.flags = flags;
    DEBUG("flags %#x\n", flags);

    ret = pkt_read_byte(&msg->pkt, &max_vals);
    if (ret != SUCCESS) {
        return ret;
    }
    msg->m.find_value_req.max_vals = max_vals;
    DEBUG("max_vals %d\n", max_vals);
    
    ret = azureus_rpc_udp_req_post_decode(msg);
    if (ret != SUCCESS) {
        return ret;
    }

    return SUCCESS;
}


static int
azureus_rpc_find_value_rsp_encode(struct azureus_rpc_msg *msg)
{
    struct azureus_dht *ad = NULL;
    struct azureus_node *azn = NULL;
    int ret;

    ASSERT(msg);

    ret = azureus_rpc_udp_rsp_encode(msg);
    if (ret != SUCCESS) {
        return ret;
    }

    ad = azureus_dht_get_ref(msg->pkt.dht);

    if (ad->proto_ver >= PROTOCOL_VERSION_DIV_AND_CONT) {
        ret = pkt_write_byte(&msg->pkt, msg->m.find_value_rsp.has_cont);
        if (ret != SUCCESS) {
            return ret;
        }
    }

    ret = pkt_write_byte(&msg->pkt, msg->m.find_value_rsp.has_vals);
    if (ret != SUCCESS) {
        return ret;
    }

    if (!msg->m.find_value_rsp.has_vals) {
        /* there are no values, but a list of nodes */
        ret = pkt_write_short(&msg->pkt, msg->m.find_value_rsp.n_nodes);
        if (ret != SUCCESS) {
            return ret;
        }

        TAILQ_FOREACH(azn, &msg->m.find_value_rsp.node_list, next) {
            ret = azureus_pkt_write_node(&msg->pkt, azn);
            if (ret != SUCCESS) {
                return ret;
            }
        }

        if (ad->proto_ver >= PROTOCOL_VERSION_VIVALDI) {
            ret = azureus_rpc_vivaldi_encode(msg);
            if (ret != SUCCESS) {
                return ret;
            }
        }

    } else {

        DEBUG("has vals\n");

        if (ad->proto_ver >= PROTOCOL_VERSION_DIV_AND_CONT) {
            ret = pkt_write_byte(&msg->pkt, msg->m.find_value_rsp.div_type);
            if (ret != SUCCESS) {
                return ret;
            }
        }

        ret = azureus_pkt_write_db_valset(&msg->pkt, 
                                            msg->m.find_value_rsp.valset, 
                                            ad->proto_ver);
        if (ret != SUCCESS) {
            return ret;
        }
    }

    return SUCCESS;
}

static int
azureus_rpc_find_value_rsp_decode(struct azureus_rpc_msg *msg)
{
    struct azureus_dht *ad = NULL;
    struct azureus_node azn, *pazn = NULL;
    u32 i;
    int ret;

    ASSERT(msg);

    TAILQ_INIT(&msg->m.find_value_rsp.node_list);

    ret = azureus_rpc_udp_rsp_decode(msg);
    if (ret != SUCCESS) {
        return ret;
    }

    ad = azureus_dht_get_ref(msg->pkt.dht);

    if (msg->u.udp_rsp.proto_ver >= PROTOCOL_VERSION_DIV_AND_CONT) {
        ret = pkt_read_byte(&msg->pkt, &msg->m.find_value_rsp.has_cont);
        if (ret != SUCCESS) {
            return ret;
        }
    }

    ret = pkt_read_byte(&msg->pkt, &msg->m.find_value_rsp.has_vals);
    if (ret != SUCCESS) {
        return ret;
    }

    if (!msg->m.find_value_rsp.has_vals) {
        /* there are no values, but a list of nodes */
        TAILQ_INIT(&msg->m.find_value_rsp.node_list);

        ret = pkt_read_short(&msg->pkt, &msg->m.find_value_rsp.n_nodes);
        if (ret != SUCCESS) {
            return ret;
        }

        for (i = 0; i < msg->m.find_value_rsp.n_nodes; i++) {
            ret = azureus_pkt_read_node(&msg->pkt, &azn);
            if (ret != SUCCESS) {
                return ret;
            }

            pazn = azureus_node_new(ad, azn.proto_ver, &azn.ext_addr);
            if (!pazn) {
                return FAILURE;
            }

            TAILQ_INSERT_TAIL(&msg->m.find_value_rsp.node_list, pazn, next);
        }

        if (msg->u.udp_rsp.proto_ver >= PROTOCOL_VERSION_VIVALDI) {
            ret = azureus_rpc_vivaldi_decode(msg);
            if (ret != SUCCESS) {
                return ret;
            }
        }

    } else {
        if (msg->u.udp_rsp.proto_ver >= PROTOCOL_VERSION_DIV_AND_CONT) {
            ret = pkt_read_byte(&msg->pkt, &msg->m.find_value_rsp.div_type);
            if (ret != SUCCESS) {
                return ret;
            }
        }

        ret = azureus_pkt_read_db_valset(&msg->pkt, 
                                            &msg->m.find_value_rsp.valset,
                                            msg->u.udp_rsp.proto_ver);
        if (ret != SUCCESS) {
            return ret;
        }
    }

    return SUCCESS;
}

/*-------------------------------------
 *
 *      Azureus RPC - Store Value
 *
 *------------------------------------*/

static int
azureus_rpc_store_value_req_encode(struct azureus_rpc_msg *msg)
{
    struct azureus_dht *ad = NULL;
    struct azureus_db_key *key = NULL;
    struct azureus_db_valset *valset = NULL;
    int ret;

    ASSERT(msg);

    ret = azureus_rpc_udp_req_encode(msg);
    if (ret != SUCCESS) {
        return ret;
    }

    ad = azureus_dht_get_ref(msg->pkt.dht);

    if (ad->proto_ver >= PROTOCOL_VERSION_ANTI_SPOOF) {
        ret = pkt_write_int(&msg->pkt, ad->this_node->rnd_id);
        if (ret != SUCCESS) {
            return ret;
        }
    }

    ret = pkt_write_byte(&msg->pkt, msg->m.store_value_req.n_keys);
    if (ret != SUCCESS) {
        return ret;
    }

    TAILQ_FOREACH(key, &msg->m.store_value_req.key_list, next) {
        ret = azureus_pkt_write_db_key(&msg->pkt, key);
        if (ret != SUCCESS) {
            return ret;
        }
    }

    ret = pkt_write_byte(&msg->pkt, msg->m.store_value_req.n_valsets);
    if (ret != SUCCESS) {
        return ret;
    }

    TAILQ_FOREACH(valset, &msg->m.store_value_req.valset_list, next) {
        ret = azureus_pkt_write_db_valset(&msg->pkt, valset, ad->proto_ver);
        if (ret != SUCCESS) {
            return ret;
        }
    }

    ret = azureus_rpc_udp_req_post_encode(msg);
    if (ret != SUCCESS) {
        return ret;
    }

    return SUCCESS;
}

static int
azureus_rpc_store_value_req_decode(struct azureus_rpc_msg *msg)
{
    int i;
    struct azureus_dht *ad = NULL;
    struct azureus_db_key *pkey = NULL;
    struct azureus_db_valset *pvalset = NULL;
    int ret;

    ASSERT(msg);

    TAILQ_INIT(&msg->m.store_value_req.key_list);
    TAILQ_INIT(&msg->m.store_value_req.valset_list);

    ret = azureus_rpc_udp_req_decode(msg);
    if (ret != SUCCESS) {
        return ret;
    }

    ad = azureus_dht_get_ref(msg->pkt.dht);

    if (msg->u.udp_req.proto_ver >= PROTOCOL_VERSION_ANTI_SPOOF) {
        ret = pkt_read_int(&msg->pkt, &msg->m.store_value_req.rnd_id);
        if (ret != SUCCESS) {
            return ret;
        }
    }

    ret = pkt_read_byte(&msg->pkt, &msg->m.store_value_req.n_keys);
    if (ret != SUCCESS) {
        return ret;
    }

    DEBUG("n_keys %d\n", msg->m.store_value_req.n_keys);

    for (i = 0; i < msg->m.store_value_req.n_keys; i++) {
        ret = azureus_pkt_read_db_key(&msg->pkt, &pkey);
        if (ret != SUCCESS) {
            return ret;
        }

        DEBUG("key len %#x\n", pkey->len);

        TAILQ_INSERT_TAIL(&msg->m.store_value_req.key_list, pkey, next);
    }

    ret = pkt_read_byte(&msg->pkt, &msg->m.store_value_req.n_valsets);
    if (ret != SUCCESS) {
        return ret;
    }

    DEBUG("n_valsets %d\n", msg->m.store_value_req.n_valsets);

    /* sanity check */
    if (msg->m.store_value_req.n_keys != msg->m.store_value_req.n_valsets) {
        ERROR("n_keys %d and n_valsets %d are not equal!!\n", 
                msg->m.store_value_req.n_keys, 
                msg->m.store_value_req.n_valsets);

        return FAILURE;
    }

    /* FIXME: a better check is required?
     * - walk the key_list and valset_list and count for equality? */

    for (i = 0; i < msg->m.store_value_req.n_valsets; i++) {
        ret = azureus_pkt_read_db_valset(&msg->pkt, &pvalset, 
                                            msg->u.udp_req.proto_ver);
        if (ret != SUCCESS) {
            return ret;
        }
        
        DEBUG("pvalset %p\n", pvalset);
        DEBUG("n_vals %#x\n", pvalset->n_vals);

        TAILQ_INSERT_TAIL(&msg->m.store_value_req.valset_list, pvalset, next);
    }

    ret = azureus_rpc_udp_req_post_decode(msg);
    if (ret != SUCCESS) {
        return ret;
    }

    return SUCCESS;
}

static int
azureus_rpc_store_value_rsp_encode(struct azureus_rpc_msg *msg)
{
    int ret;
    struct azureus_dht *ad = NULL;

    ASSERT(msg);

    ret = azureus_rpc_udp_rsp_encode(msg);
    if (ret != SUCCESS) {
        return ret;
    }

    ad = azureus_dht_get_ref(msg->pkt.dht);

    if (ad->proto_ver >= PROTOCOL_VERSION_DIV_AND_CONT) {
        ret = pkt_write_byte(&msg->pkt, msg->m.store_value_rsp.n_divs);
        if (ret != SUCCESS) {
            return ret;
        }

        ret = pkt_write_arr(&msg->pkt, msg->m.store_value_rsp.div, 
                            msg->m.store_value_rsp.n_divs);
        if (ret != SUCCESS) {
            return ret;
        }
    }

    return SUCCESS;
}

static int
azureus_rpc_store_value_rsp_decode(struct azureus_rpc_msg *msg)
{
    int ret;
    struct azureus_dht *ad = NULL;

    ASSERT(msg);

    ret = azureus_rpc_udp_rsp_decode(msg);
    if (ret != SUCCESS) {
        return ret;
    }

    ad = azureus_dht_get_ref(msg->pkt.dht);

    if (msg->u.udp_rsp.proto_ver >= PROTOCOL_VERSION_DIV_AND_CONT) {
        ret = pkt_read_byte(&msg->pkt, &msg->m.store_value_rsp.n_divs);
        if (ret != SUCCESS) {
            return ret;
        }

        ret = pkt_read_arr(&msg->pkt, msg->m.store_value_rsp.div, 
                            msg->m.store_value_rsp.n_divs);
        if (ret != SUCCESS) {
            return ret;
        }
    }

    return SUCCESS;
}

/*-------------------------------------
 *
 *      Azureus RPC - Vivaldi
 *
 *------------------------------------*/

int
azureus_rpc_vivaldi_encode(struct azureus_rpc_msg *msg)
{
    struct azureus_dht *ad = NULL;
    int i;
    bool v1_found = FALSE;
    u8 size;
    int ret = SUCCESS;

    ASSERT(msg);

    ad = azureus_dht_get_ref(msg->pkt.dht);

    if (ad->proto_ver >= PROTOCOL_VERSION_GENERIC_NETPOS) {

        ret = pkt_write_byte(&msg->pkt, msg->n_viv_pos);
        if (ret != SUCCESS) {
            return ret;
        }

        for (i = 0; i < msg->n_viv_pos; i++) {

            switch (msg->viv_pos[i].type) {
                case POSITION_TYPE_VIVALDI_V1:
                    size = 16;
                    v1_found = TRUE;
                    break;
                case POSITION_TYPE_VIVALDI_V2:
                    size = 33;
                    break;
                default:
                    continue;
            }

            ret = pkt_write_byte(&msg->pkt, msg->viv_pos[i].type);
            if (ret != SUCCESS) {
                return ret;
            }

            ret = pkt_write_byte(&msg->pkt, size);
            if (ret != SUCCESS) {
                return ret;
            }

            ret = azureus_vivaldi_encode(&msg->pkt, msg->viv_pos[i].type, 
                                            &msg->viv_pos[i]);
            if (ret != SUCCESS) {
                return ret;
            }
        }

        if (!v1_found) {
            ERROR("Vivaldi V1 missing\n");
            return FAILURE;
        }

    } else {

        for (i = 0; i < msg->n_viv_pos; i++) {
            if (msg->viv_pos[i].type == POSITION_TYPE_VIVALDI_V1) {
                ret = azureus_vivaldi_encode(&msg->pkt, msg->viv_pos[i].type, 
                                                &msg->viv_pos[msg->n_viv_pos]);
                if (ret != SUCCESS) {
                    return ret;
                }

                return SUCCESS;
            }
        }

        ERROR("Vivaldi V1 missing\n");
        return FAILURE;
    }

    return SUCCESS;
}

int
azureus_rpc_vivaldi_decode(struct azureus_rpc_msg *msg)
{
    int ret;
    u8 n_pos;
    u8 type, size;
    int i, j;
    bool v1_found = FALSE;
    u8 _c;

    ASSERT(msg);

    if (msg->u.udp_rsp.proto_ver >= PROTOCOL_VERSION_GENERIC_NETPOS) {

        DEBUG("generic netpos - proto_ver %#x\n", msg->u.udp_rsp.proto_ver);

        ret = pkt_read_byte(&msg->pkt, &n_pos);
        if (ret != SUCCESS) {
            return ret;
        }

        for (i = 0; i < n_pos; i++) {
            ret = pkt_read_byte(&msg->pkt, &type);
            if (ret != SUCCESS) {
                return ret;
            }
            
            ret = pkt_read_byte(&msg->pkt, &size);
            if (ret != SUCCESS) {
                return ret;
            }

            DEBUG("vivaldi n_pos %d type %d size %d\n", n_pos, type, size);

            ret = azureus_vivaldi_decode(&msg->pkt, type, 
                                            &msg->viv_pos[msg->n_viv_pos]);
            if (ret != SUCCESS) {
                for (j = 0; j < size; j++) {
                    ret = pkt_read_byte(&msg->pkt, &_c);
                    if (ret != SUCCESS) {
                        return ret;
                    }
                }

                continue;
            }

            msg->n_viv_pos++;
        }

    } else {
        DEBUG("not generic netpos\n");
        ret = azureus_vivaldi_decode(&msg->pkt, type, 
                                            &msg->viv_pos[msg->n_viv_pos]);
    }

    v1_found = FALSE;

    for (i = 0; i < msg->n_viv_pos; i++) {
        if (msg->viv_pos[i].type == POSITION_TYPE_VIVALDI_V1) {
            v1_found = TRUE;
            azureus_vivaldi_pos_dump(&msg->viv_pos[i]);
        }
    }

    DEBUG("n_pos %d\n", msg->n_viv_pos);

    if (!v1_found) {
        ERROR("Vivaldi V1 missing\n");
        return FAILURE;
    }

    return SUCCESS;
}

