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

static int is_valid_rpc_action(u32 action);
static int is_valid_rpc_req_action(u32 action);
static int is_valid_rpc_rsp_action(u32 action);

static int msg_is_rpc_req(struct azureus_rpc_msg *msg, bool *req);
static int msg_get_rpc_action(struct azureus_rpc_msg *msg, u32 *action);
static int azureus_rpc_match_req_rsp(struct azureus_rpc_msg *req, 
                            struct azureus_rpc_msg *rsp, bool *match);

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

struct azureus_rpc_msg *
azureus_rpc_msg_new(struct dht *dht, 
                    struct sockaddr_storage *from,
                    size_t fromlen,
                    u8 *data, int len)
{
    struct azureus_rpc_msg *msg = NULL;
    int ret;

    ASSERT(dht && data && (len >= 0));

    msg = (struct azureus_rpc_msg *) malloc(sizeof(struct azureus_rpc_msg));
    if (!msg) {
        return NULL;
    }

    bzero(msg, sizeof(struct azureus_rpc_msg));
    ret = pkt_new(&msg->pkt, dht, from, fromlen, data, len);
    if (ret != SUCCESS) {
        goto err;
    }

    return msg;

err:
    free(msg);
    return NULL;
}

void
azureus_rpc_msg_delete(struct azureus_rpc_msg *msg)
{
    free(msg);
}

int 
azureus_decode_rpc(struct dht *dht, 
                    struct sockaddr_storage *from, 
                    size_t fromlen,
                    u8 *data, 
                    int len)
{
    struct azureus_rpc_msg *msg = NULL;
    int ret;
    u32 action;

    msg = azureus_rpc_msg_new(dht, from, fromlen, data, len);
    if (!msg) {
        return FAILURE;
    }

    pkt_dump(&msg->pkt);

    ret = msg_get_rpc_action(msg, &action);
    if (ret != SUCCESS) {
        return ret;
    }

    ret = msg_is_rpc_req(msg, &msg->is_req);
    if (ret != SUCCESS) {
        azureus_rpc_msg_delete(msg);
        return FAILURE;
    }

    switch (action) {

        case ACT_REQUEST_PING:
            ret = azureus_rpc_ping_req_decode(msg);
            break;

        case ACT_REPLY_PING:
            ret = azureus_rpc_ping_rsp_decode(msg);
            break;

        case ACT_REQUEST_FIND_NODE:
            ret = azureus_rpc_find_node_req_decode(msg);
            break;

        case ACT_REPLY_FIND_NODE:
            ret = azureus_rpc_find_node_rsp_decode(msg);
            break;

        case ACT_REQUEST_FIND_VALUE:
            ret = azureus_rpc_find_value_req_decode(msg);
            break;

        case ACT_REPLY_FIND_VALUE:
            ret = azureus_rpc_find_value_rsp_decode(msg);
            break;

        case ACT_REQUEST_STORE:
            ret = azureus_rpc_store_value_req_decode(msg);
            break;

        case ACT_REPLY_STORE:
            ret = azureus_rpc_store_value_rsp_decode(msg);
            break;

        default:
            break;
    }

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
        /* skip over conn_id */
        ret = pkt_peek(&msg->pkt, sizeof(u64), action, sizeof(u32));
        if (ret != SUCCESS) {
            return ret;
        }
    } else {            /* response */
        ret = pkt_peek(&msg->pkt, 0, action, sizeof(u32));
        if (ret != SUCCESS) {
            return ret;
        }
    }

    return SUCCESS;
}

static int
azureus_rpc_match_req_rsp(struct azureus_rpc_msg *req, 
                            struct azureus_rpc_msg *rsp, bool *match)
{
    ASSERT(req && rsp && match);
    ASSERT(req->is_req && !rsp->is_req);

    if (req->p.pr_udp_req.conn_id == rsp->u.udp_rsp.conn_id) {
        *match = TRUE;
    } else {
        *match = FALSE;
    }

    return SUCCESS;
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
#if 0
    if (ad->proto_ver >= PROTOCOL_VERSION_VIVALDI) {
        ret = azureus_rpc_vivaldi_encode(msg);
        if (ret != SUCCESS) {
            return ret;
        }
    }
#endif

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
    
#if 0
    if (msg->u.udp_rsp.proto_ver >= PROTOCOL_VERSION_VIVALDI) {
        ret = azureus_rpc_vivaldi_decode(msg);
        if (ret != SUCCESS) {
            return ret;
        }
    }
#endif

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
    u32 rnd_id;
    u32 i;
    int ret;

    ASSERT(msg);

    ret = azureus_rpc_udp_rsp_encode(msg);
    if (ret != SUCCESS) {
        return ret;
    }

    ad = azureus_dht_get_ref(msg->pkt.dht);

    if (ad->proto_ver >= PROTOCOL_VERSION_ANTI_SPOOF) {
        ret = azureus_node_get_spoof_id(ad->this_node, &rnd_id);
        if (ret != SUCCESS) {
            return ret;
        }

        ret = pkt_write_int(&msg->pkt, rnd_id);
        if (ret != SUCCESS) {
            return ret;
        }
    }

    if (ad->proto_ver >= PROTOCOL_VERSION_XFER_STATUS) {
        ret = pkt_write_int(&msg->pkt, msg->m.find_node_rsp.node_status);
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

#if 0
    if (ad->proto_ver >= PROTOCOL_VERSION_VIVALDI) {
        ret = azureus_rpc_vivaldi_encode(msg);
        if (ret != SUCCESS) {
            return ret;
        }
    }
#endif

    ret = pkt_write_short(&msg->pkt, msg->m.find_node_rsp.n_nodes);
    if (ret != SUCCESS) {
        return ret;
    }

    for (i = 0; i < msg->m.find_node_rsp.n_nodes; i++) {
        ret = azureus_pkt_write_node(&msg->pkt, 
                                        &msg->m.find_node_rsp.nodes[i]);
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
    u32 i;
    int ret;

    ASSERT(msg);

    ret = azureus_rpc_udp_rsp_decode(msg);
    if (ret != SUCCESS) {
        return ret;
    }

    ad = azureus_dht_get_ref(msg->pkt.dht);

    if (msg->u.udp_rsp.proto_ver >= PROTOCOL_VERSION_ANTI_SPOOF) {
        ret = pkt_read_int(&msg->pkt, &rnd_id);
        if (ret != SUCCESS) {
            return ret;
        }
        /* FIXME: verify the random_id */
        msg->m.find_node_rsp.rnd_id = rnd_id;
        
    }
    msg->m.find_node_rsp.rnd_id = rnd_id;

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

#if 0
    if (msg->u.udp_rsp.proto_ver >= PROTOCOL_VERSION_VIVALDI) {
        ret = azureus_rpc_vivaldi_decode(msg);
        if (ret != SUCCESS) {
            return ret;
        }
    }
#endif

    ret = pkt_read_short(&msg->pkt, &msg->m.find_node_rsp.n_nodes);
    if (ret != SUCCESS) {
        return ret;
    }

    for (i = 0; i < msg->m.find_node_rsp.n_nodes; i++) {
        ret = azureus_pkt_read_node(&msg->pkt, &msg->m.find_node_rsp.nodes[i]);
        if (ret != SUCCESS) {
            return ret;
        }
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

    ret = azureus_rpc_udp_rsp_encode(msg);
    if (ret != SUCCESS) {
        return ret;
    }

    ret = pkt_write_byte(&msg->pkt, msg->m.find_value_req.key_len);
    if (ret != SUCCESS) {
        return ret;
    }

    ret = pkt_write_arr(&msg->pkt, msg->m.find_value_req.key, 
                        msg->m.find_value_req.key_len);
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

    ret = azureus_rpc_udp_rsp_decode(msg);
    if (ret != SUCCESS) {
        return ret;
    }

    ret = pkt_read_byte(&msg->pkt, &msg->m.find_value_req.key_len);
    if (ret != SUCCESS) {
        return ret;
    }

    ret = pkt_read_arr(&msg->pkt, msg->m.find_value_req.key, 
                        msg->m.find_value_req.key_len);
    if (ret != SUCCESS) {
        return ret;
    }

    ret = pkt_read_byte(&msg->pkt, &flags);
    if (ret != SUCCESS) {
        return ret;
    }
    msg->m.find_value_req.flags = flags;

    ret = pkt_read_byte(&msg->pkt, &max_vals);
    if (ret != SUCCESS) {
        return ret;
    }
    msg->m.find_value_req.max_vals = max_vals;
    
    ret = azureus_rpc_udp_req_post_decode(msg);
    if (ret != SUCCESS) {
        return ret;
    }

    return SUCCESS;
}


static int
azureus_rpc_find_value_rsp_encode(struct azureus_rpc_msg *msg)
{
    int ret;
    struct azureus_dht *ad = NULL;
    int i;

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

        for (i = 0; i < msg->m.find_value_rsp.n_nodes; i++) {
            ret = azureus_pkt_write_node(&msg->pkt, 
                                            &msg->m.find_value_rsp.nodes[i]);
            if (ret != SUCCESS) {
                return ret;
            }
        }
#if 0
        /* serialize vivaldi */
        if (ad->proto_ver >= PROTOCOL_VERSION_VIVALDI_FINDVALUE) {
            ret = azureus_rpc_vivaldi_pos_encode(msg);
            if (ret != SUCCESS) {
                return ret;
            }
        }
#endif  
    } else {
        if (ad->proto_ver >= PROTOCOL_VERSION_DIV_AND_CONT) {
            ret = pkt_write_byte(&msg->pkt, msg->m.find_value_rsp.div_type);
            if (ret != SUCCESS) {
                return ret;
            }
        }

        ret = azureus_pkt_write_db_valset(&msg->pkt, 
                                            &msg->m.find_value_rsp.valset);
        if (ret != SUCCESS) {
            return ret;
        }
    }

    return SUCCESS;
}

static int
azureus_rpc_find_value_rsp_decode(struct azureus_rpc_msg *msg)
{
    int ret;
    struct azureus_dht *ad = NULL;
    int i;

    ASSERT(msg);

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
        ret = pkt_read_short(&msg->pkt, &msg->m.find_value_rsp.n_nodes);
        if (ret != SUCCESS) {
            return ret;
        }

        for (i = 0; i < msg->m.find_value_rsp.n_nodes; i++) {
            ret = azureus_pkt_read_node(&msg->pkt, 
                                            &msg->m.find_value_rsp.nodes[i]);
            if (ret != SUCCESS) {
                return ret;
            }
        }
#if 0
        /* serialize vivaldi */
        if (msg->u.udp_rsp.proto_ver >= PROTOCOL_VERSION_VIVALDI_FINDVALUE) {
            ret = azureus_rpc_vivaldi_pos_encode(msg);
            if (ret != SUCCESS) {
                return ret;
            }
        }
#endif  
    } else {
        if (msg->u.udp_rsp.proto_ver >= PROTOCOL_VERSION_DIV_AND_CONT) {
            ret = pkt_read_byte(&msg->pkt, &msg->m.find_value_rsp.div_type);
            if (ret != SUCCESS) {
                return ret;
            }
        }

        ret = azureus_pkt_read_db_valset(&msg->pkt, 
                                            &msg->m.find_value_rsp.valset);
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
    int i;
    struct azureus_dht *ad = NULL;
    int ret;

    ASSERT(msg);

    ret = azureus_rpc_udp_rsp_encode(msg);
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

    for (i = 0; i < msg->m.store_value_req.n_keys; i++) {
        ret = azureus_pkt_write_db_key(&msg->pkt, 
                                        &msg->m.store_value_req.key[i]);
        if (ret != SUCCESS) {
            return ret;
        }
    }

    ret = pkt_write_byte(&msg->pkt, msg->m.store_value_req.n_valsets);
    if (ret != SUCCESS) {
        return ret;
    }

    for (i = 0; i < msg->m.store_value_req.n_valsets; i++) {
        ret = azureus_pkt_write_db_valset(&msg->pkt, 
                                            &msg->m.store_value_req.valset[i]);
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
    int ret;

    ASSERT(msg);

    ret = azureus_rpc_udp_rsp_decode(msg);
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

    for (i = 0; i < msg->m.store_value_req.n_keys; i++) {
        ret = azureus_pkt_read_db_key(&msg->pkt, 
                                        &msg->m.store_value_req.key[i]);
        if (ret != SUCCESS) {
            return ret;
        }
    }

    ret = pkt_read_byte(&msg->pkt, &msg->m.store_value_req.n_valsets);
    if (ret != SUCCESS) {
        return ret;
    }

    for (i = 0; i < msg->m.store_value_req.n_valsets; i++) {
        ret = azureus_pkt_read_db_valset(&msg->pkt, 
                                            &msg->m.store_value_req.valset[i]);
        if (ret != SUCCESS) {
            return ret;
        }
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
    int ret = SUCCESS;

    ASSERT(msg);

    if (ret != SUCCESS) {
        return ret;
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
    int skipped;
    u8 _c;

    ASSERT(msg);

    if (msg->u.udp_req.proto_ver >= PROTOCOL_VERSION_GENERIC_NETPOS) {

        skipped = 0;

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

            ret = azureus_vivaldi_decode(&msg->pkt, type, 
                                            &msg->viv_pos[msg->n_viv_pos]);
            if (ret != SUCCESS) {
                for (j = 0; j < size; j++) {
                    ret = pkt_read_byte(&msg->pkt, &_c);
                    if (ret != SUCCESS) {
                        return ret;
                    }
                }
            }

            msg->n_viv_pos++;

            if (type == POSITION_TYPE_VIVALDI_V1) {
                v1_found = TRUE;
            }
        }
    } else {
    }

    return SUCCESS;
}

#if 0
/* call this func. _after_ decoding the pkt */
static int
az_rpc_match_req_rsp(struct rpc_msg *req, struct rpc_msg *rsp)
{
    struct az_rpc_msg *az_req = NULL, *az_rsp = NULL;

    ASSERT(req && rsp);
    
    ASSERT(req->priv && rsp->priv);

    az_req = req->priv;
    az_rsp = rsp->priv;

    if (az_req->p.pr_udp_req.conn_id == az_rsp->u.udp_rsp.conn_id) {
        return TRUE;
    }

    return FALSE;
}

/* convert float to IEEE 754 single-precision 32-bit format */
static int32_t
float_to_ieee754(float f)
{
}

/* convert IEEE 754 single-precision 32-bit format to float */
static float
ieee754_to_float(int32_t i)
{
}

/* not-a-number? */
static int
is_nan(float f)
{
    int32_t i;

    i = float_to_ieee754(f);

    if (i == 0x7fc00000) {
        return TRUE;
    }

    return FALSE;
}

/* infinity? */
static int
is_inf(float f)
{
    int32_t i;

    i = float_to_ieee754(f);

    if ((i == 0x7f800000) ||            /* +ve inf. */
            (i == 0xff800000)) {        /* -ve inf. */
        return TRUE;
    }

    return FALSE;
}

/*
 * 
 * Vivaldi implementation
 *
 */

static int
az_rpc_vivaldi_pos_encode(struct rpc_msg *msg)
{
    u_int8_t *p = NULL;
    float c[4];
    int32_t n = 0;
    int i = 0;

    ASSERT(msg);

    p = &msg->pkt[msg->len];

    for (i = 0; i < 4; i++) {
        n = htonl(float_to_ieee754(c[i]));
        *((int32_t *)p) = n;
        p += sizeof(int32_t);
    }

    msg->len = (p - msg->pkt);

    return SUCCESS;
}

static int
az_rpc_vivaldi_pos_decode(struct rpc_msg *msg)
{
    u_int8_t *p = NULL;
    float c[4];
    int32_t n = 0;
    int i = 0;

    ASSERT(msg);

    p = &msg->pkt[msg->len];

    for (i = 0; i < 4; i++) {
        n = ntohl(*((int32_t *)p));
        p += sizeof(int32_t);
        c[i] = ieee754_to_float(n);
    }

    msg->len = (p - msg->pkt);

    return SUCCESS;
}

static int
az_rpc_vivaldi_encode(struct rpc_msg *msg)
{
    u_int8_t *p = NULL;

    ASSERT(msg);

    return SUCCESS;
}

static int
az_rpc_vivaldi_decode(struct rpc_msg *msg)
{
    u_int8_t *p = NULL;
    u_int8_t n_pos = 0;
    u_int8_t type;
    u_int8_t size;
    int ret;
    int i = 0;
    int v1_found = FALSE;

    ASSERT(msg);

    p = &msg->pkt[msg->len];

    n_pos = *((u_int8_t *)p);
    p += sizeof(u_int8_t);

    for (i = 0; i < n_pos; i++) {

        type = *((u_int8_t *)p);
        p += sizeof(u_int8_t);

        size = *((u_int8_t *)p);
        p += sizeof(u_int8_t);

        switch (type) {
            case POSITION_TYPE_VIVALDI_V1:
                /* we support this type, in fact require it! */
                ret = az_rpc_vivaldi_pos_decode(msg);
                if (ret != SUCCESS) {
                    return FAILURE;
                }
                v1_found = TRUE;
                break;
            case POSITION_TYPE_VIVALDI_V2:
                /* we know this type, but don't do anything today! */
                p += size;
                break;
            default:
                return FAILURE;
        }

        if (!v1_found) {
            return FAILURE;
        }
    }

    return SUCCESS;
}

static float initial_err = 10.0f;
static float error = initial_err;
static float cc = 0.25f;
static float ce = 0.5f;
static int nb_updates = 0;
static int AZ_CONVERGE_EVERY = 5;
static float AZ_CONVERGE_FACTOR = 50.0f;
static float AZ_ERROR_MIN = 0.1f;

struct az_vivaldi_coords *
az_vivaldi_coords_new(float x, float y, float h)
{
    struct az_vivaldi_coords *c = NULL;

    c = (struct az_vivaldi_coords *) malloc(sizeof(struct az_vivaldi_coords));
    if (!c)
        return NULL;
    bzero(c, sizeof(struct az_vivaldi_coords));

    c->x = x;
    c->y = y;
    c->h = h;
    c->err = initial_err;

    return c;
}

static bool
az_valid(float f)
{
    return (!isnan(f) && !isinf(f));
}

bool
az_vivaldi_coords_is_valid(struct az_vivaldi_coords *c)
{
    return (az_valid(c->x) && az_valid(c->y) && az_valid(c->h));
}

struct az_vivaldi_coords * 
az_vivaldi_coords_add(struct az_vivaldi_coords *c1, 
                        struct az_vivaldi_coords *c2)
{
    return az_vivaldi_coords_new((c1->x + c2->x), 
                                    (c1->y + c2->y), 
                                    fabs(c1->h+c2->h));
}

struct az_vivaldi_coords * 
az_vivaldi_coords_sub(struct az_vivaldi_coords *c1, 
                        struct az_vivaldi_coords *c2)
{
    return az_vivaldi_coords_new((c1->x - c2->x), 
                                    (c1->y - c2->y), 
                                    fabs(c1->h+c2->h));
}

struct az_vivaldi_coords * 
az_vivaldi_coords_scale(struct az_vivaldi_coords *c, float scale)
{
    return az_vivaldi_coords_new((scale*c->x), (scale*c->y), (scale*c->h));
}

bool
az_at_origin(struct az_vivaldi_coords *c)
{
    return ((c->x == 0) && (c->y == 0));
}

static float 
az_vivaldi_coords_measure(struct az_vivaldi_coords *c1)
{
    return (sqrt((c1->x * c1->x) + (c1->y * c1->y)) + c1->h);
}

static float
az_vivaldi_distance(struct az_vivaldi_coords *c1, 
                            struct az_vivaldi_coords *c2)
{
    return az_vivaldi_coords_measure(az_vivaldi_coords_sub(c1, c2));
}

static float
az_estimate_rtt(struct az_vivaldi_coords *c1, struct az_vivaldi_coords *c2) 
{
    if (az_at_origin(c1) || az_at_origin(c2)) {
        return NAN;
    }

    return az_vivaldi_distance(c1, c2);
}

static struct az_vivaldi_coords *
az_vivaldi_coords_unity(struct az_vivaldi_coords *c)
{
    int rnd_x, rnd_y, rnd_h;
    float measure;
    struct az_vivaldi_coords *c1;
    
    measure = az_vivaldi_coords_measure(c);

    if (measure == 0) {
        crypto_get_rnd_bytes(&rnd_x, sizeof(rnd_x));
        crypto_get_rnd_bytes(&rnd_y, sizeof(rnd_y));
        crypto_get_rnd_bytes(&rnd_h, sizeof(rnd_h));
        c1 = az_vivaldi_coords_new(rnd_x, rnd_y, rnd_h);

        return az_vivaldi_coords_unity(c1);
    }

    return az_vivaldi_coords_scale(c, 1/measure);
}

int 
az_vivaldi_coords_update(float rtt, 
                                struct az_vivaldi_coords *cj, 
                                float ej)
{
    float w, re, es, new_error, delta, scale;
    int rnd_x, rnd_y, rnd_h;
    struct az_vivaldi_coords *rnd_err = NULL;
    struct az_vivaldi_coords *new_c = NULL;

    if (az_valid(rtt) && az_valid(ej) && az_is_valid(cj)) {

        if(rtt <= 0 || rtt > 5*60*1000 ) 
            return FAILURE;

        if((error + ej) == 0) 
            return FAILURE;

        w = error / (ej + error);

        re = rtt - az_vivaldi_distance(&az_coords, cj);

        es = fabs(re) / rtt;

        new_error = es*ce*w + error*(1-ce*w);

        delta = cc*w;

        scale = delta*re;

        crypto_get_rnd_bytes(&rnd_x, sizeof(rnd_x));
        crypto_get_rnd_bytes(&rnd_y, sizeof(rnd_y));
        crypto_get_rnd_bytes(&rnd_h, sizeof(rnd_h));

        rnd_err = az_vivaldi_coords_new((float)(1.0*rnd_x/10), 
                (float)(1.0*rnd_y/10), 
                (float)0.0f);

        new_c = az_vivaldi_coords_add(&az_coords, 
                az_vivaldi_coords_sub(&az_coords, 
                    az_vivaldi_coords_scale(
                        az_vivaldi_coords_unity(
                            az_vivaldi_coords_add(cj, rnd_err)), scale)));

        if (az_valid(new_error) && az_vivaldi_coords_valid(new_c)) {
            az_coords = *new_c;
            error = new_error > AZ_ERROR_MIN ? new_error : AZ_ERROR_MIN;
        } else {
            az_coords = *az_vivaldi_coords_new(0, 0, 0);
            error = initial_error;
        }

        if (az_at_origin(cj)) {
            nb_updates++;
        }

        if (nb_updates > AZ_CONVERGE_EVERY) {
            nb_updates = 0;
            az_vivaldi_coords_update(10, az_vivaldi_coords_new(0,0,0), AZ_CONVERGE_FACTOR);

        }

    } else {
        return FAILURE;
    }

    return SUCCESS;
}

/*---------------------------------
 *
 *      Azureus initialization routine
 *
 *--------------------------------*/

int 
azureus_dht_rpc_init(struct dht_rpc *rpc)
{
    rpc->decode = az_rpc_decode;
    rpc->encode = az_rpc_encode;
    rpc->match_req_rsp = az_rpc_match_req_rsp;
    crypto_get_rnd_bytes(&az_trans_id, sizeof(az_trans_id));
    crypto_get_rnd_bytes(&az_instance_id, sizeof(az_instance_id));

    return SUCCESS;
}

static int
az_rpc_db_item_key_encode(u_int8_t *pkt, int *pkt_len, int *len, struct db_item *item)
{
    int ret;
    u_int8_t *p = NULL;
    int i;

    ASSERT(pkt);
    ASSERT(pkt_len);
    ASSERT(len);
    ASSERT(item);

    p = pkt;

    *((u_int8_t *p)) = item->key.len;
    p += sizeof(u_int8_t);
    *len += sizeof(u_int8_t);
    *pkt_len += sizeof(u_int8_t);

    memcpy(p, item->key.data, item->key.len);
    p += item->key.len;
    *len += item->key.len;
    *pkt_len += item->key.len;

    return SUCCESS;
}

static int
az_rpc_db_item_valset_encode(u_int8_t *pkt, int *pkt_len, int *len, struct db_item *item)
{
    int ret;
    u_int8_t *p = NULL;
    int i;

    ASSERT(pkt);
    ASSERT(pkt_len);
    ASSERT(len);
    ASSERT(item);

    *((u_int8_t *p)) = item->n_vals;
    p += sizeof(u_int8_t);
    *len += sizeof(u_int8_t);
    *pkt_len += sizeof(u_int8_t);

    for (i = 0; i < n_vals; i++) {

        *((u_int16_t *p)) = htons(item->valset[i].len);
        p += sizeof(u_int16_t);
        *len += sizeof(u_int16_t);
        *pkt_len += sizeof(u_int16_t);

        memcpy(p, item->valset[i].data, item->valset[i].len);
        p += item->valset[i].len;
        *len += item->valset[i].len;
        *pkt_len += item->valset[i].len;
    }

    return SUCCESS;
}

static int
az_rpc_db_item_encode(u_int8_t *pkt, int *pkt_len, int *len, struct db_item *item, int n_items)
{
    int ret;
    u_int8_t *p = NULL;
    int i;

    ASSERT(pkt);
    ASSERT(pkt_len);
    ASSERT(len);
    ASSERT(item);

    p = pkt;

    /* The encoding is as follows:
     *  - no. of keys - 1 octet
     *  - each key as a length, val encoding
     *  - no of valsets - 1 octet
     *  - length of each valset
     *  - length, encoding of val
     **/

    *((u_int8_t *)p) = n_items;
    p += sizeof(u_int8_t);
    *len += sizeof(u_int8_t);
    *pkt_len += sizeof(u_int8_t);

    for (i = 0; i < n_items; i++) {
        ret = az_rpc_db_item_key_encode(pkt, pkt_len, len, &item[i]);
        if (ret != SUCCESS) {
            return FAILURE;
        }
    }

    *((u_int8_t *)p) = n_items; /* FIXME: no. of valsets == no. of keys? */
    p += sizeof(u_int8_t);
    *len += sizeof(u_int8_t);
    *pkt_len += sizeof(u_int8_t);

    for (i = 0; i < n_items; i++) {
        ret = az_rpc_db_item_valset_encode(pkt, pkt_len, len, &item[i]);
        if (ret != SUCCESS) {
            return FAILURE;
        }
    }

    return SUCCESS;
}

static int
az_rpc_db_item_key_decode(u_int8_t *pkt, int *pkt_len, int *len, struct db_item *item)
{
    int ret;
    u_int8_t *p = NULL;
    int i;

    ASSERT(pkt);
    ASSERT(pkt_len);
    ASSERT(len);
    ASSERT(item);

    p = pkt;

    item->key.len = *((u_int8_t *p));
    p += sizeof(u_int8_t);
    *len += sizeof(u_int8_t);

    memcpy(item->key.data, p, item->key.len);
    p += item->key.len;
    *len += item->key.len;

    return SUCCESS;
}

static int
az_rpc_db_item_valset_decode(u_int8_t *pkt, int *pkt_len, int *len, struct db_item *item)
{
    int ret;
    u_int8_t *p = NULL;
    int i;

    ASSERT(pkt);
    ASSERT(pkt_len);
    ASSERT(len);
    ASSERT(item);

    item->n_vals = *((u_int8_t *p));
    p += sizeof(u_int8_t);
    *len += sizeof(u_int8_t);

    for (i = 0; i < item->n_vals; i++) {

        htons(item->valset[i].len) = ntohs(*((u_int16_t *)p));
        p += sizeof(u_int16_t);
        *len += sizeof(u_int16_t);

        memcpy(item->valset[i].data, p, item->vals[i].len);
        p += item->vals[i].len;
        *len += item->vals[i].len;
    }

    return SUCCESS;
}

static int
az_rpc_db_item_decode(u_int8_t *pkt, int *pkt_len, int *len, struct db_item *item, int *n_items)
{
    int ret;
    u_int8_t *p = NULL;
    int i;

    ASSERT(pkt);
    ASSERT(pkt_len);
    ASSERT(len);
    ASSERT(item);
    ASSERT(n_items);

    p = pkt;

    *n_items = *((u_int8_t *)p);
    p += sizeof(u_int8_t);
    *len += sizeof(u_int8_t);

    for (i = 0; i < *n_items; i++) {
        ret = az_rpc_db_item_key_decode(pkt, pkt_len, len, &item[i]);
        if (ret != SUCCESS) {
            return FAILURE;
        }
    }

    n_items = *((u_int8_t *)p);
    p += sizeof(u_int8_t);
    *len += sizeof(u_int8_t);

    for (i = 0; i < n_items; i++) {
        ret = az_rpc_db_item_valset_decode(pkt, pkt_len, len, &item[i]);
        if (ret != SUCCESS) {
            return FAILURE;
        }
    }

    return SUCCESS;
}
#endif
