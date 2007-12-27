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
#include <string.h>

#include "azureus_db.h"
#include "debug.h"
#include "crypto.h"

struct azureus_db_key *
azureus_db_key_new(void)
{
    struct azureus_db_key *k = NULL;

    k = (struct azureus_db_key *) malloc(sizeof(struct azureus_db_key));
    if (!k) {
        return NULL;
    }

    bzero(k, sizeof(struct azureus_db_key));

    return k;
}

void
azureus_db_key_delete(struct azureus_db_key *key)
{
    free(key);
}

bool
azureus_db_key_equal(struct azureus_db_key *k1, struct azureus_db_key *k2)
{
    ASSERT(k1 && k2);

    if (k1->len != k2->len) {
        return FALSE;
    }

    if (memcmp(k1->data, k2->data, k1->len) != 0) {
        return FALSE;
    }

    return TRUE;
}

struct azureus_db_val *
azureus_db_val_new(void)
{
    struct azureus_db_val *v = NULL;

    v = (struct azureus_db_val *) malloc(sizeof(struct azureus_db_val));
    if (!v) {
        return NULL;
    }

    bzero(v, sizeof(struct azureus_db_val));

    return v;
}

void
azureus_db_val_delete(struct azureus_db_val *v)
{
    free(v);
}

struct azureus_db_valset *
azureus_db_valset_new(void)
{
    struct azureus_db_valset *vs = NULL;

    vs = (struct azureus_db_valset *) malloc(sizeof(struct azureus_db_valset));
    if (!vs) {
        return NULL;
    }

    bzero(vs, sizeof(struct azureus_db_valset));

    TAILQ_INIT(&vs->val_list);

    return vs;
}

void
azureus_db_valset_delete(struct azureus_db_valset *vs)
{
    struct azureus_db_val *v = NULL, *vn = NULL;

    ASSERT(vs);

    TAILQ_FOREACH_SAFE(v, &vs->val_list, next, vn) {
        TAILQ_REMOVE(&vs->val_list, vn, next);
        azureus_db_val_delete(v);
    }

    free(vs);
}

int
azureus_db_valset_add_val(struct azureus_db_valset *vs, u8 *val, int val_len)
{
    struct azureus_db_val *v = NULL;

    ASSERT(vs && (val_len > 0) && val);

    v = azureus_db_val_new();
    if (!v) {
        return FAILURE;
    }

    vs->n_vals++;

    TAILQ_INSERT_TAIL(&vs->val_list, v, next);

    return SUCCESS;
}

struct azureus_db_item *
azureus_db_item_new(struct azureus_dht *ad, struct azureus_db_key *key, 
                    struct azureus_db_valset *valset)
{
    struct azureus_db_item *item = NULL;

    ASSERT(ad && key && valset);

    item = (struct azureus_db_item *) malloc(sizeof(struct azureus_db_item));
    if (!item) {
        return NULL;
    }

    bzero(item, sizeof(struct azureus_db_item));
    item->dht = ad;
    item->key = key;
    item->valset = valset;
    item->cr_time = dht_get_current_time();

    return item;
}

void
azureus_db_item_delete(struct azureus_db_item *item)
{
    ASSERT(item);

    DEBUG("before db_item_delete\n");
    DEBUG("before key_delete\n");
    azureus_db_key_delete(item->key);
    DEBUG("before valset_delete\n");
    azureus_db_valset_delete(item->valset);
    free(item);

    DEBUG("after db_item_delete\n");

    return;
}
#if 0
int
azureus_db_item_set_key(struct azureus_db_item *item, u8 *key, int key_len)
{
    u8 digest[20];
    int ret;

    ASSERT(item && key && (key_len > 0));

    bzero(&item->key, sizeof(struct azureus_db_key));

    ret = crypto_get_sha1_digest(key, key_len, digest);
    if (ret != SUCCESS) {
        return ret;
    }

    memcpy(item->key->data, digest, 20);
    item->key->len = 20;

    return SUCCESS;
}

int
azureus_db_item_add_val(struct azureus_db_item *item, u8 *val, int val_len)
{
    int ret;

    ASSERT(item && (val_len > 0) && val);

    ret = azureus_db_valset_add_val(&item->valset, val, val_len);
    if (ret != SUCCESS) {
        return ret;
    }

    return SUCCESS;
}

bool
azureus_db_item_match_key(struct azureus_db_item *item, u8 *key, int key_len)
{
    u8 digest[20];
    int ret;

    ASSERT(item && key && (key_len > 0));

    ret = crypto_get_sha1_digest(key, key_len, digest);
    if (ret != SUCCESS) {
        return FALSE;
    }

    ASSERT(item->key->len == 20);

    if (memcmp(item->key->data, digest, 20) == 0) {
        return TRUE;
    }

    return FALSE;
}
#endif
