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

#ifndef __NODE_H__
#define __NODE_H__

#include "queue.h"
#include "key.h"
#include "types.h"

enum node_state {
    NODE_STATE_UNKNOWN = 0,
    NODE_STATE_GOOD,
    NODE_STATE_QUESTIONABLE,
    NODE_STATE_BAD
};

struct node {
    struct key                  id;
    enum node_state             state;
    LIST_ENTRY(node)            kb_next;
    TAILQ_ENTRY(node)           next;
};

TAILQ_HEAD(node_list, node);

int node_new(struct node *n, struct key *id);

#endif /* __NODE_H__ */
