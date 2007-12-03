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

#include <stdio.h>
#include <string.h>
#include <netinet/in.h>

#include "azureus_rpc_utils.h"
#include "azureus_rpc.h"
#include "azureus_node.h"

int
azureus_pkt_write_inetaddr(struct pkt *pkt, struct sockaddr_storage *ss)
{
    int sa_family;
    struct sockaddr_in *sin4 = NULL;
    struct sockaddr_in6 *sin6 = NULL;
    int ret;

    ASSERT(pkt && ss);

    sa_family = ((struct sockaddr *)ss)->sa_family;

    switch (sa_family) {
        case AF_INET:
            /* len (1 byte) + addr (4 bytes) + port (2 bytes) = 7 bytes */
            ret = pkt_write_byte(pkt, 4);
            if (ret != SUCCESS) {
                return ret;
            }

            sin4 = (struct sockaddr_in *)ss;

            ret = pkt_write_arr(pkt, (u8 *)&sin4->sin_addr, 
                                    sizeof(sin4->sin_addr));
            if (ret != SUCCESS) {
                return ret;
            }

            ret = pkt_write_short(pkt, htons(sin4->sin_port));
            if (ret != SUCCESS) {
                return ret;
            }

            break;

        case AF_INET6:
            /* len (1 byte) + addr (16 bytes) + port (2 bytes) = 19 bytes */
            ret = pkt_write_byte(pkt, 16);
            if (ret != SUCCESS) {
                return ret;
            }

            sin6 = (struct sockaddr_in6 *)ss;

            ret = pkt_write_arr(pkt, (u8 *)&sin6->sin6_addr, 
                                    sizeof(sin6->sin6_addr));
            if (ret != SUCCESS) {
                return ret;
            }

            ret = pkt_write_short(pkt, sin6->sin6_port);
            if (ret != SUCCESS) {
                return ret;
            }

            break;

        default:
            return FAILURE;
    }

    return SUCCESS;
}

int
azureus_pkt_read_inetaddr(struct pkt *pkt, struct sockaddr_storage *ss) 
{
    u8 len;
    struct sockaddr_in *sin4 = NULL;
    struct sockaddr_in6 *sin6 = NULL;
    int ret;

    ASSERT(pkt && ss);

    ret = pkt_read_byte(pkt, &len);
    if (ret != SUCCESS) {
        return ret;
    }

    switch (len) {
        case 4:
            sin4 = (struct sockaddr_in *)ss;
            ((struct sockaddr *)ss)->sa_family = AF_INET;
            ret = pkt_read_arr(pkt, (u8 *)&sin4->sin_addr, 
                                    sizeof(sin4->sin_addr));
            if (ret != SUCCESS) {
                return ret;
            }

            ret = pkt_read_short(pkt, &sin4->sin_port);
            if (ret != SUCCESS) {
                return ret;
            }
            sin4->sin_port = ntohs(sin4->sin_port);

            break;

        case 16:
            sin6 = (struct sockaddr_in6 *)ss;
            ((struct sockaddr *)ss)->sa_family = AF_INET6;
            ret = pkt_read_arr(pkt, (u8 *)&sin6->sin6_addr, 
                                    sizeof(sin6->sin6_addr));
            if (ret != SUCCESS) {
                return ret;
            }

            ret = pkt_read_short(pkt, &sin6->sin6_port);
            if (ret != SUCCESS) {
                return ret;
            }
            sin6->sin6_port = ntohs(sin6->sin6_port);

            break;

        default:
            return FAILURE;
    }

    return SUCCESS;
}

int
azureus_pkt_write_node(struct pkt *pkt, struct azureus_node *an)
{
    int sa_family;
    struct sockaddr_in *sin4;
    struct sockaddr_in6 *sin6;
    int ret;

    ASSERT(pkt && an);

    ret = pkt_write_byte(pkt, CT_UDP);
    if (ret != SUCCESS) {
        return ret;
    }

    ret = pkt_write_byte(pkt, an->proto_ver);
    if (ret != SUCCESS) {
        return ret;
    }

    sa_family = ((struct sockaddr *)&an->ext_addr)->sa_family;

    switch (sa_family) {
        case AF_INET:
            sin4 = (struct sockaddr_in *)&an->ext_addr;

            ret = azureus_pkt_write_inetaddr(pkt, &an->ext_addr);
            if (ret != SUCCESS) {
                return ret;
            }

            break;

        case AF_INET6:
            sin6 = (struct sockaddr_in6 *)&an->ext_addr;

            ret = azureus_pkt_write_inetaddr(pkt, &an->ext_addr);
            if (ret != SUCCESS) {
                return ret;
            }

            break;

        default:
            return FAILURE;
    }

    return SUCCESS;
}

int
azureus_pkt_read_node(struct pkt *pkt, struct azureus_node *an)
{
    u8 nd_type;
    u8 proto_ver;
    struct sockaddr_storage ext_addr;
    int ret;

    ASSERT(pkt && an);

    ret = pkt_read_byte(pkt, &nd_type);
    if (ret != SUCCESS) {
        return ret;
    }

    if (nd_type != CT_UDP) {
        printf("%s:%d - unsupported node type\n", __func__, __LINE__);
        return FAILURE;
    }

    ret = pkt_read_byte(pkt, &proto_ver);
    if (ret != SUCCESS) {
        return ret;
    }
    an->proto_ver = proto_ver;

    ret = azureus_pkt_read_inetaddr(pkt, &ext_addr);
    if (ret != SUCCESS) {
        return ret;
    }
    memcpy(&an->ext_addr, &ext_addr, sizeof(struct sockaddr_storage));
#if 0

    n = azureus_node_new(proto_ver, &ext_addr);
    if (!an) {
        return FAILURE;
    }
#endif

    return SUCCESS;
}

int
azureus_pkt_write_db_key(struct pkt *pkt, struct azureus_db_key *key)
{
    int ret;
    
    ASSERT(pkt && key);

    ret = pkt_write_byte(pkt, key->len);
    if (ret != SUCCESS) {
        return ret;
    }

    ret = pkt_write_arr(pkt, key->data, key->len);
    if (ret != SUCCESS) {
        return ret;
    }
    
    return SUCCESS;
}

int
azureus_pkt_read_db_key(struct pkt *pkt, struct azureus_db_key *key)
{
    int ret;
    
    ASSERT(pkt && key);

    ret = pkt_read_byte(pkt, &key->len);
    if (ret != SUCCESS) {
        return ret;
    }

    ret = pkt_read_arr(pkt, key->data, key->len);
    if (ret != SUCCESS) {
        return ret;
    }
    
    return SUCCESS;
}

int
azureus_pkt_write_db_val(struct pkt *pkt, struct azureus_db_val *val)
{
    int ret;
    
    ASSERT(pkt && val);

    ret = pkt_write_short(pkt, val->len);
    if (ret != SUCCESS) {
        return ret;
    }

    ret = pkt_write_arr(pkt, val->data, val->len);
    if (ret != SUCCESS) {
        return ret;
    }

    return SUCCESS;
}

int
azureus_pkt_read_db_val(struct pkt *pkt, struct azureus_db_val *val)
{
    int ret;
    
    ASSERT(pkt && val);

    ret = pkt_read_short(pkt, &val->len);
    if (ret != SUCCESS) {
        return ret;
    }

    ret = pkt_read_arr(pkt, val->data, val->len);
    if (ret != SUCCESS) {
        return ret;
    }

    return SUCCESS;
}

int
azureus_pkt_write_db_valset(struct pkt *pkt, struct azureus_db_valset *valset)
{
    struct azureus_db_val *val = NULL;
    int ret;

    ASSERT(pkt && valset);

    ret = pkt_write_byte(pkt, valset->n_vals);
    if (ret != SUCCESS) {
        return ret;
    }

    TAILQ_FOREACH(val, &valset->val_list, next) {
        ret = azureus_pkt_write_db_val(pkt, val);
        if (ret != SUCCESS) {
            return ret;
        }
    }

    return SUCCESS;
}

int
azureus_pkt_read_db_valset(struct pkt *pkt, struct azureus_db_valset *valset)
{
    int i;
    struct azureus_db_val val, *pval = NULL;
    int ret;

    ASSERT(pkt && valset);

    ret = pkt_read_byte(pkt, &valset->n_vals);
    if (ret != SUCCESS) {
        return ret;
    }

    for (i = 0; i < valset->n_vals; i++) {
        ret = azureus_pkt_read_db_val(pkt, &val);
        if (ret != SUCCESS) {
            return ret;
        }

        pval = azureus_db_val_new(val.data, val.len);
        if (!pval) {
            return FAILURE;
        }

        TAILQ_INSERT_TAIL(&valset->val_list, pval, next);
    }

    return SUCCESS;
}
