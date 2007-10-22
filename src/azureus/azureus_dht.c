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

#include "azureus_dht.h"
#include "dht_types.h"
#include "types.h"
#include "crypto.h"
#include "azureus_rpc.h"
#include "azureus_db.h"

struct dht *
azureus_dht_new(struct dht_net_if *nif, int port)
{
    struct azureus_dht *ad = NULL;
    int ret;

    ad = (struct azureus_dht *) malloc(sizeof(struct azureus_dht));
    if (!ad) {
        return NULL;
    }

    /* initialize parent base class */
    ret = dht_new(&ad->dht, DHT_TYPE_AZUREUS, nif, port);
    if (ret != SUCCESS) {
        free(ad);
        return NULL;
    }

    /* initialize Azureus specific stuff */
    ad->proto_ver = PROTOCOL_VERSION_MAIN;
    ret = crypto_get_rnd_int(&ad->trans_id);
    if (ret != SUCCESS) {
        free(ad);
        return NULL;
    }
    
    ret = crypto_get_rnd_int(&ad->instance_id);
    if (ret != SUCCESS) {
        free(ad);
        return NULL;
    }

    ad->this_node = azureus_node_new(ad->proto_ver, &ad->dht.net_if.ext_addr);
    if (!ad->this_node) {
        free(ad);
        return NULL;
    }

    TAILQ_INIT(&ad->db_list);

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

int 
azureus_task_schedule(struct task *task)
{
    ASSERT(task);

    return SUCCESS;
}

