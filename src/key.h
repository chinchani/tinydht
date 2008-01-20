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

#ifndef __KEY_H__
#define __KEY_H__

#include "types.h"

#define MAX_KEY_SIZE        20

enum key_type {
    KEY_TYPE_UNKNOWN = 0,
    KEY_TYPE_RANDOM,
    KEY_TYPE_SHA1,
    KEY_TYPE_MAX
};

struct key {
    enum key_type   type;
    u8              data[MAX_KEY_SIZE];
    int             len;
};

int key_new(struct key *k, enum key_type type, void *data, int data_len);

int key_xor(struct key *k1, struct key *k2, struct key *xor);
int key_distance(struct key *k1, struct key *k2, struct key *dist);

int key_cmp(struct key *k1, struct key *k2);
int key_nth_bit(struct key *k, unsigned n);
int key_get_size_from_type(enum key_type type);

void key_dump(struct key *k);

#endif /* __KEY_H__ */

