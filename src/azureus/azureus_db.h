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

#ifndef __AZUREUS_DB_H__
#define __AZUREUS_DB_H__

struct azureus_db_key;
struct azureus_rpc_msg;

#include "types.h"
#include "queue.h"
#include "azureus_dht.h"

#define AZUREUS_MAX_KEYS_PER_PKT    255
#define AZUREUS_MAX_VALS_PER_KEY    255
#define AZUREUS_MAX_KEY_LEN         255
#define AZUREUS_MAX_VAL_LEN         256

struct azureus_db_key {
    u8                      data[AZUREUS_MAX_KEY_LEN];
    u8                      len;
    TAILQ_ENTRY(azureus_db_key) next;
};

struct azureus_db_val {
    u32                         ver;
    u64                         timestamp;
    u8                          data[AZUREUS_MAX_VAL_LEN];
    u16                         len;
    struct azureus_node         orig_node;
    u8                          flags;
    TAILQ_ENTRY(azureus_db_val) next;
};

struct azureus_db_valset {
    u16                                         n_vals;
    TAILQ_HEAD(val_list_head, azureus_db_val)   val_list;
    TAILQ_ENTRY(azureus_db_valset)              next;
};

struct azureus_db_item {
    struct azureus_dht                  *dht;
    u64                                 cr_time;        /* creation time */
    u64                                 last_refresh;   /* last publish time */
    bool                                task_pending;
    struct azureus_db_key               *key;
    struct azureus_db_valset            *valset;
    bool                                is_local;
    TAILQ_ENTRY(azureus_db_item)        db_next;
    TAILQ_HEAD(db_node_list_head, azureus_node) node_list;
};

struct azureus_db_key * azureus_db_key_new(void);
void azureus_db_key_delete(struct azureus_db_key *key);
bool azureus_db_key_equal(struct azureus_db_key *k1, struct azureus_db_key *k2);

struct azureus_db_val * azureus_db_val_new(void);
void azureus_db_val_delete(struct azureus_db_val *v);
struct azureus_db_valset * azureus_db_valset_new(void);
void azureus_db_valset_delete(struct azureus_db_valset *vs);
int azureus_db_valset_add_val(struct azureus_db_valset *vs, 
                                u8 *val, int val_len);

struct azureus_db_item * azureus_db_item_new(struct azureus_dht *dht, struct azureus_db_key *key, 
                                                struct azureus_db_valset *valset);
void azureus_db_item_delete(struct azureus_db_item *item);
int azureus_db_item_set_key(struct azureus_db_item *item, u8 *key, int key_len);
int azureus_db_item_add_val(struct azureus_db_item *item, u8 *val, int val_len);
bool azureus_db_item_match_key(struct azureus_db_item *item, 
                                u8 *key, int key_len);

#endif /* __AZUREUS_DB_H__ */
