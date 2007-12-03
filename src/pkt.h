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

#ifndef __PKT_H__
#define __PKT_H__

#include <netinet/in.h>

#include "types.h"
#include "dht.h"
#include "queue.h"

#define MAX_PKT_LEN     1400    /* MTU size */

enum pkt_dir {
    PKT_DIR_UNKNOWN = 0,
    PKT_DIR_TX,
    PKT_DIR_RX
};

struct pkt {
    enum pkt_dir                dir;    /* outgoing/incoming? */
    struct sockaddr_storage     ss;
    u_int8_t                    data[MAX_PKT_LEN];
    unsigned int                len;    /* actual pkt len */
    unsigned int                cursor; /* to track write/read */
    unsigned int                mark_pos;
    unsigned int                mark_rdlim;
    struct dht                  *dht;
    TAILQ_ENTRY(pkt)            next;
};

int pkt_new(struct pkt *pkt, struct dht *dht, 
                struct sockaddr_storage *ss, size_t sslen, 
                u8 *data, unsigned int len);
void pkt_reset_data(struct pkt *pkt);
int pkt_delete(struct pkt *pkt);
int pkt_sanity(struct pkt *pkt);

int pkt_mark(struct pkt *pkt, unsigned int rdlim);
int pkt_reset(struct pkt *pkt);

int pkt_write_byte(struct pkt *pkt, u8 b);
int pkt_write_short(struct pkt *pkt, u16 s);
int pkt_write_int(struct pkt *pkt, u32 i);
int pkt_write_long(struct pkt *pkt, u64 l);
int pkt_write_float(struct pkt *pkt, float f);
int pkt_write_arr(struct pkt *pkt, u8 *arr, size_t arr_len);

int pkt_read_byte(struct pkt *pkt, u8 *b);
int pkt_read_short(struct pkt *pkt, u16 *s);
int pkt_read_int(struct pkt *pkt, u32 *i);
int pkt_read_long(struct pkt *pkt, u64 *l);
int pkt_read_float(struct pkt *pkt, float *f);
int pkt_read_arr(struct pkt *pkt, u8 *arr, size_t arr_len);

int pkt_read_is_avail(struct pkt *pkt);
int pkt_peek(struct pkt *pkt, unsigned int offset, void *p, size_t size);

int pkt_dump(struct pkt *pkt);
int pkt_dump_data(u8 *data, size_t len);

#endif /* __PKT_H__ */
