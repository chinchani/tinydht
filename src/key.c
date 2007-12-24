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

#include "key.h"
#include "types.h"
#include "crypto.h"
#include "debug.h"

int
key_new(struct key *k, enum key_type type, void *data, int data_len)
{
    u_int8_t buf[256];
    int ret = 0;

    ASSERT(k);
    
    bzero(k, sizeof(struct key));

    k->type = type;

    switch (type) {
        case KEY_TYPE_RANDOM:
            bzero(buf, sizeof(buf));
            ret = crypto_get_rnd_bytes(buf, sizeof(buf));
            if (ret != SUCCESS) {
                return FAILURE;
            }

            crypto_get_sha1_digest(buf, 16, k->data);
            k->type = KEY_TYPE_SHA1;
            k->len = 20;
            break;

        case KEY_TYPE_SHA1:
            if (data_len != 20) {
                return FAILURE;
            }
            
            memcpy(k->data, data, 20);
            k->len = 20;
            break;

        default:
            return FAILURE;
    }

    key_dump(k);

    return SUCCESS;
}

int
key_xor(struct key *k1, struct key *k2, struct key *xor)
{
    int i;

    ASSERT(k1 && k2 && (k1->type == k2->type) && (k1->len == k2->len) && xor);

    for (i = 0; i < k1->len; i++) {
        xor->data[i] = k1->data[i] ^ k2->data[i];
    }
    xor->len = k1->len;

    return SUCCESS;
}

int
key_distance(struct key *k1, struct key *k2, struct key *dist)
{
    ASSERT(k1 && k2 && dist);
    
    return key_xor(k1, k2, dist);
}

int
key_cmp(struct key *k1, struct key *k2)
{
    int i;
    
    ASSERT(k1 && k2 && (k1->type == k2->type) && (k1->len == k2->len));

    for (i = 0; i < k1->len; i++) {
        if (k1->data[i] < k2->data[i]) {
            return -1;
        } else if (k1->data[i] > k2->data[i]) {
            return 1;
        }
    }

    return 0;
}

int
key_nth_bit(struct key *k, unsigned n)
{
    int which_byte = 0;
    int which_bit = 0;
    int bit_val = 0;

    ASSERT(k && (n < k->len*8*sizeof(k->data[0])));

    which_byte = k->len - (n/(8*sizeof(k->data[0]))) - 1;
    which_bit = n % (8*sizeof(k->data[0]));

    bit_val = (k->data[which_byte] & (1 << which_bit)) >> which_bit;

    ASSERT((bit_val == ZERO) || (bit_val == ONE));

    return bit_val;
}

int
key_get_size_from_type(enum key_type type)
{
    int size = 0;
    
    switch (type) {
        
        case KEY_TYPE_SHA1:
            size = 160;
            break;
            
        default:
            break;
    }

    return size;
}

void
key_dump(struct key *k)
{
    int i;

    ASSERT(k);

    printf("%p: ", k);
    for (i = 0; i < k->len; i++) {
        printf("%02x", k->data[i]);
    }
    printf("\n");
}
