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

#ifndef __AZUREUS_RPC_H__
#define __AZUREUS_RPC_H__

#include "types.h"
#include "pkt.h"
#include "queue.h"
#include "azureus_node.h"
#include "azureus_db.h"
#include "azureus_vivaldi.h"
#include "node.h"

enum azureus_protocol_version {
   PROTOCOL_VERSION_2304 = 8,
   PROTOCOL_VERSION_2306 = 12,
   PROTOCOL_VERSION_2400 = 13,
   PROTOCOL_VERSION_2402 = 14,
   PROTOCOL_VERSION_2500 = 15,
   PROTOCOL_VERSION_MIN = PROTOCOL_VERSION_2402,
   PROTOCOL_VERSION_DIV_AND_CONT = 6,
   PROTOCOL_VERSION_ANTI_SPOOF = 7,
   PROTOCOL_VERSION_ENCRYPT_TT = 8,
   PROTOCOL_VERSION_ANTI_SPOOF2 = 8,
   PROTOCOL_VERSION_FIX_ORIGINATOR = 9,
   PROTOCOL_VERSION_VIVALDI = 10,
   PROTOCOL_VERSION_REMOVE_DIST_ADD_VER = 11,
   PROTOCOL_VERSION_XFER_STATUS = 12,
   PROTOCOL_VERSION_SIZE_ESTIMATE = 13,
   PROTOCOL_VERSION_VENDOR_ID = 14,
   PROTOCOL_VERSION_BLOCK_KEYS = 14,
   PROTOCOL_VERSION_GENERIC_NETPOS = 15,
   PROTOCOL_VERSION_VIVALDI_FINDVALUE = 16,
   PROTOCOL_VERSION_RESTRICT_ID_PORTS = 32,
   PROTOCOL_VERSION_NETWORKS = PROTOCOL_VERSION_FIX_ORIGINATOR,
   PROTOCOL_VERSION_MAIN = PROTOCOL_VERSION_VIVALDI_FINDVALUE,
   PROTOCOL_VERSION_CVS = PROTOCOL_VERSION_VIVALDI_FINDVALUE,
};

enum azureus_vendor_id {
   VENDOR_ID_AELITIS = 0x00,
   VENDOR_ID_ShareNET = 0x01,
   VENDOR_ID_NONE = (u_int8_t)0xff,
   VENDOR_ID_ME = VENDOR_ID_AELITIS
};

enum azureus_action {
    ACT_REQUEST_PING = 1024,
    ACT_REPLY_PING = 1025,
    ACT_REQUEST_STORE = 1026,
    ACT_REPLY_STORE = 1027,
    ACT_REQUEST_FIND_NODE = 1028,
    ACT_REPLY_FIND_NODE = 1029,
    ACT_REQUEST_FIND_VALUE = 1030,
    ACT_REPLY_FIND_VALUE = 1031,
    ACT_REPLY_ERROR = 1032,
    ACT_REPLY_STATS = 1033,
    ACT_REQUEST_STATS = 1034,
    ACT_DATA = 1035,
    ACT_REQUEST_KEY_BLOCK = 1036,
    ACT_REPLY_KEY_BLOCK = 1037,
};

enum azureus_flags {
    FLAG_SINGLE_VALUE = 0x00,
    FLAG_DOWNLOADING = 0x01,
    FLAG_SEEDING = 0x02,
    FLAG_MULTI_VALUE = 0x04,
    FLAG_STATS = 0x08
};

enum azureus_diversify_type {
    DT_NONE = 1,
    DT_FREQUENCY = 2,
    DT_SIZE = 3
};

enum azureus_contact_type {
    CT_UDP = 1
};

#define MAX_RPC_MSG_NODES       16
#define MAX_RPC_VIVALDI_POS     4

/* PR UDP Request 
    connection id    (0x8000000000000000L | rnd) 
**/
struct azureus_pr_udp_req {
    u64                         conn_id;    
    u32                         action;     /* action           */
    u32                         trans_id;   /* transaction id   */
};

/* PR UDP Response */
struct azureus_pr_udp_rsp {
    u32                         action;     /* action           */
    u32                         trans_id;   /* transaction id   */
};

/* Base Azureus Request */
struct azureus_udp_req {
    u8                          proto_ver;
    u8                          vendor_id;      /* vendor id    */
    u32                         network;        /* network      */
    u8                          orig_ver;       /* originator's version */
    struct sockaddr_storage     ss;
    u32                         orig_inst_id;   /* originator's instance_id */
    u64                         orig_time;
    u64                         skew;
};

/* Base Azureus Response */
struct azureus_udp_rsp {
    u64                         conn_id;
    u8                          proto_ver;
    u8                          vendor_id;      /* vendor id    */
    u32                         network;        /* network      */
    u32                         tgt_inst_id;
};

/* ping request/response */
struct azureus_rpc_ping_req {
};

struct azureus_rpc_ping_rsp {
};

/* find node request/response */
struct azureus_rpc_find_node_req {
    u8                          id[20];
    u8                          id_len;
};

#define AZUREUS_RPC_MAX_NODES   32
struct azureus_rpc_find_node_rsp {
    u32                         rnd_id;
    u32                         node_status;
    u16                         n_nodes;
    TAILQ_HEAD(find_node_rsp_node_list_head, azureus_node) node_list;
    u32                         est_dht_size;
};

/* find value request/response */
struct azureus_rpc_find_value_req {
    u8                          flags;
    u8                          max_vals;
    u8                          key[AZUREUS_MAX_KEY_LEN];
    u8                          key_len;
};

struct azureus_rpc_find_value_rsp {
    bool                        has_cont;
    bool                        has_vals;
    struct azureus_db_valset    valset;
    u8                          div_type;   /* diversification type */
    u16                         n_nodes;
    TAILQ_HEAD(find_value_rsp_node_list_head, azureus_node) node_list;
};

/* store value request/response */
struct azureus_rpc_store_value_req {
    u32                         rnd_id;
    u8                          n_keys;
    /* FIXME: make this a TAILQ? 17M!! */ 
//    struct azureus_db_key       key[AZUREUS_MAX_KEYS_PER_PKT];
    TAILQ_HEAD(store_value_req_key_list_head, azureus_db_key) key_list;
    u8                          n_valsets;
//   struct azureus_db_valset    valset[AZUREUS_MAX_KEYS_PER_PKT];
    TAILQ_HEAD(store_value_req_valset_list_head, azureus_db_valset) valset_list;
};

struct azureus_rpc_store_value_rsp {
    u8                          n_divs;
    u8                          div[AZUREUS_MAX_KEYS_PER_PKT];
};

/* Azureus rpc msg */
struct azureus_rpc_msg {
    u_int32_t                                   action;
    struct pkt                                  pkt;
    union {
        struct azureus_pr_udp_req               pr_udp_req;     /* PR UDP hdr from above */
        struct azureus_pr_udp_rsp               pr_udp_rsp;
    } p;
    union {
        struct azureus_udp_req                  udp_req;
        struct azureus_udp_rsp                  udp_rsp;
    } u;
    union {
        struct azureus_rpc_ping_req             ping_req;
        struct azureus_rpc_ping_rsp             ping_rsp;
        struct azureus_rpc_find_node_req        find_node_req;
        struct azureus_rpc_find_node_rsp        find_node_rsp;
        struct azureus_rpc_find_value_req       find_value_req;
        struct azureus_rpc_find_value_rsp       find_value_rsp;
        struct azureus_rpc_store_value_req      store_value_req;
        struct azureus_rpc_store_value_rsp      store_value_rsp;
    } m;
    bool                                        is_req;
    union {
        struct azureus_rpc_msg                  *req;
        struct azureus_rpc_msg                  *rsp;
    } r;
    u8                                          n_viv_pos;
    struct azureus_vivaldi_pos                  viv_pos[MAX_RPC_VIVALDI_POS];
};

static inline struct azureus_rpc_msg *
azureus_rpc_msg_get_ref(struct pkt *pkt)
{
    return container_of(pkt, struct azureus_rpc_msg, pkt);
}

struct azureus_rpc_msg * azureus_rpc_msg_new(struct dht *dht, 
                                                struct sockaddr_storage *from,
                                                size_t fromlen,
                                                u8 *data, int len);
void azureus_rpc_msg_delete(struct azureus_rpc_msg *msg);

int azureus_encode_rpc(struct azureus_rpc_msg *msg);
int azureus_decode_rpc(struct dht *dht, struct sockaddr_storage *from, 
                            size_t fromlen, u8 *data, int len);

#endif /* __AZUREUS_RPC_H__ */
