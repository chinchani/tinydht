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

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include "ctype.h"

#include "pkt.h"
#include "dht.h"
#include "debug.h"
#include "float.h"

int
pkt_new(struct pkt *pkt, struct dht *dht, 
            struct sockaddr_storage *from, size_t fromlen, 
            u8 *data, unsigned int len)
{
    ASSERT(pkt && dht && data && (len < MAX_PKT_LEN));
    
    bzero(pkt, sizeof(struct pkt));
    pkt->dht = dht;
    memcpy(&pkt->from, from, fromlen);
    memcpy(pkt->data, data, len);
    pkt->len = len;
    
    return SUCCESS;
}

int
pkt_sanity(struct pkt *pkt)
{
    ASSERT(pkt);
    ASSERT(pkt->cursor < pkt->len);
    ASSERT(pkt->dht);
    return SUCCESS;
}

int
pkt_mark(struct pkt *pkt, unsigned int rdlim)
{
    int ret;

    ret = pkt_sanity(pkt);
    if (ret != SUCCESS) {
        return ret;
    }

    if (pkt->cursor + rdlim > pkt->len) {
        return FAILURE;
    }

    pkt->mark_pos = pkt->cursor;
    /* FIXME: fix rdlim logic for reads/writes */
    pkt->mark_rdlim = rdlim;

    return SUCCESS;
}

int
pkt_reset(struct pkt *pkt)
{
    int ret;

    ret = pkt_sanity(pkt);
    if (ret != SUCCESS) {
        return ret;
    }

    pkt->cursor = pkt->mark_pos;
    pkt->mark_pos = 0;
    pkt->mark_rdlim = 0;

    return SUCCESS;
}

static int
pkt_write_check(struct pkt *pkt, size_t size)
{
    pkt_sanity(pkt);

    if ((size <= 0) ||
         (pkt->cursor > pkt->len) || ((pkt->cursor + size) > MAX_PKT_LEN)) {
        return FAILURE;
    }

    if (pkt->cursor != pkt->len) {
        return FAILURE;
    }

    return SUCCESS;
}

static int
pkt_read_check(struct pkt *pkt, size_t size)
{
    pkt_sanity(pkt);

    if ((size <= 0) ||
         (pkt->cursor > pkt->len) || ((pkt->cursor + size) > MAX_PKT_LEN)) {
        return FAILURE;
    }

    if ((pkt->cursor + size) > pkt->len) {
        return FAILURE;
    }

    return SUCCESS;
}

int
pkt_write_byte(struct pkt *pkt, u8 b)
{
    int ret;
    
    ret = pkt_write_check(pkt, sizeof(u8));
    if (ret != SUCCESS) {
        return ret;
    }
    
    memcpy(&pkt->data[pkt->cursor], &b, sizeof(u8));
    pkt->cursor += sizeof(u8);
    pkt->len += sizeof(u8);

    return SUCCESS;
}

int
pkt_write_short(struct pkt *pkt, u16 s)
{
    u16 ns;
    int ret;
    
    ret = pkt_write_check(pkt, sizeof(u16));
    if (ret != SUCCESS) {
        return ret;
    }    

    ns = htons(s);
    memcpy(&pkt->data[pkt->cursor], &ns, sizeof(u16));
    pkt->cursor += sizeof(u16);
    pkt->len += sizeof(u16);

    return SUCCESS;
}

int
pkt_write_int(struct pkt *pkt, u32 i)
{
    u32 ni;
    int ret;
    
    ret = pkt_write_check(pkt, sizeof(u32));
    if (ret != SUCCESS) {
        return ret;
    }

    ni = htonl(i);
    memcpy(&pkt->data[pkt->cursor], &ni, sizeof(u32));
    pkt->cursor += sizeof(u32);
    pkt->len += sizeof(u32);

    return SUCCESS;
}

int
pkt_write_long(struct pkt *pkt, u64 l)
{
    u64 nl;
    int ret;
    
    ret = pkt_write_check(pkt, sizeof(u64));
    if (ret != SUCCESS) {
        return ret;
    }

    nl = hton64(l);
    memcpy(&pkt->data[pkt->cursor], &nl, sizeof(u64));
    pkt->cursor += sizeof(u64);
    pkt->len += sizeof(u64);

    return SUCCESS;
}

int
pkt_write_float(struct pkt *pkt, float f)
{
    int ret;

    ret = pkt_write_check(pkt, sizeof(u32));
    if (ret != SUCCESS) {
        return ret;
    }

    ret = pkt_write_int(pkt, float_to_ieee754(f));
    if (ret != SUCCESS) {
        return ret;
    }

    return SUCCESS;
}

int
pkt_write_arr(struct pkt *pkt, u8 *arr, size_t arr_len)
{
    int ret;
    
    ret = pkt_write_check(pkt, arr_len);
    if (ret != SUCCESS) {
        return ret;
    }

    memcpy(&pkt->data[pkt->cursor], arr, arr_len);
    pkt->cursor += arr_len;
    pkt->len += arr_len;

    return SUCCESS;
}

int
pkt_read_byte(struct pkt *pkt, u8 *b)
{
    int ret;

    if (!b) {
        return FAILURE;
    }
        
    ret = pkt_read_check(pkt, sizeof(u8));
    if (ret != SUCCESS) {
        return ret;
    }

    memcpy(b, &pkt->data[pkt->cursor], sizeof(u8));
    pkt->cursor += sizeof(u8);

    return SUCCESS;
}

int
pkt_read_short(struct pkt *pkt, u16 *s)
{
    u16 ns;
    int ret;
    
    if (!s) {
        return FAILURE;
    }
    
    ret = pkt_read_check(pkt, sizeof(u16));
    if (ret != SUCCESS) {
        return ret;
    }

    memcpy(&ns, &pkt->data[pkt->cursor], sizeof(u16));
    pkt->cursor += sizeof(u16);

    *s = ntohs(ns);

    return SUCCESS;
}

int
pkt_read_int(struct pkt *pkt, u32 *i)
{
    u32 ni;
    int ret;
    
    if (!i) {
        return FAILURE;
    }
    
    ret = pkt_read_check(pkt, sizeof(u32));
    if (ret != SUCCESS) {
        return ret;
    }

    memcpy(&ni, &pkt->data[pkt->cursor], sizeof(u32));
    pkt->cursor += sizeof(u32);

    *i = ntohl(ni);

    return SUCCESS;
}

int
pkt_read_long(struct pkt *pkt, u64 *l)
{
    u64 nl;
    int ret;
    
    if (!l) {
        return FAILURE;
    }
    
    ret = pkt_read_check(pkt, sizeof(u64));
    if (ret != SUCCESS) {
        return ret;
    }

    memcpy(&nl, &pkt->data[pkt->cursor], sizeof(u64));
    pkt->cursor += sizeof(u64);

    *l = ntoh64(nl);

    return SUCCESS;
}

int
pkt_read_float(struct pkt *pkt, float *f)
{
    int ret;
    u32 ief;

    if (!f) {
        return FAILURE;
    }

    ret = pkt_read_check(pkt, sizeof(u32));
    if (ret != SUCCESS) {
        return ret;
    }

    ret = pkt_read_int(pkt, &ief);
    if (ret != SUCCESS) {
        return ret;
    }

    *f = ieee754_to_float(ief);

    return SUCCESS;
}

int
pkt_read_arr(struct pkt *pkt, u8 *arr, size_t arr_len)
{
    int ret;

    if (!arr) {
        return FAILURE;
    }

    ret = pkt_read_check(pkt, arr_len);
    if (ret != SUCCESS) {
        return ret;
    }

    memcpy(arr, &pkt->data[pkt->cursor], arr_len);
    pkt->cursor += arr_len;

    return SUCCESS;
}

int
pkt_read_is_avail(struct pkt *pkt)
{
    if (pkt->cursor < pkt->len) {
        return TRUE;
    }
    
    return FALSE;
}

int
pkt_peek(struct pkt *pkt, unsigned int offset, void *p, size_t size)
{
    if (!pkt || (offset > pkt->len) || (offset + size > pkt->len)) {
        return FAILURE;
    }

    memcpy(p, &pkt->data[offset], size);
    
    return SUCCESS;
}

int
pkt_dump(struct pkt *pkt)
{
    unsigned int width = 16;
    int row, col;
    int max_row, max_col;
    char ch;
    int len;

    ASSERT(pkt && (pkt->len > 0));

    max_row = pkt->len/width + ((pkt->len % width) ? 1 : 0);
    
    len = pkt->len;

    printf("pkt (%p) - cursor (%d) len (%d)\n", pkt, pkt->cursor, pkt->len);
    for (row = 0; row < max_row; row++) {
        max_col = len / width ? width : len % width;
        printf("%04x| ", row);
        for (col = 0; col < max_col; col++) {
            printf("%02x ", pkt->data[row*width + col]);
        }
        for (col = max_col; col < width; col++) {
            printf("%2s ", "  ");
        }
        printf("| ");
        for (col = 0; col < max_col; col++) {
            ch = pkt->data[row*width + col];
            printf("%c", (isprint(ch) ? ch : '.'));
        }
        printf("\n");

        len -= max_row;
    }
    printf("\n");

    return SUCCESS;
}

int
pkt_dump_data(u8 *data, size_t len)
{
    unsigned int width = 16;
    int row, col;
    int max_row, max_col;
    char ch;

    ASSERT(data && len);

    max_row = len/width + ((len % width) ? 1 : 0);
  
    printf("data (%p) - len (%d)\n", data, len);
    for (row = 0; row < max_row; row++) {
        max_col = len / width ? width : len % width;
        printf("%04x| ", row);
        for (col = 0; col < max_col; col++) {
            printf("%02x ", data[row*width + col]);
        }
        for (col = max_col; col < width; col++) {
            printf("%2s ", "  ");
        }
        printf("| ");
        for (col = 0; col < max_col; col++) {
            ch = data[row*width + col];
            printf("%c", (isprint(ch) ? ch : '.'));
        }
        printf("\n");
        len -= max_col;
    }
    printf("\n");

    return SUCCESS;
}
