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
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "azureus_node.h"
#include "azureus_rpc.h"
#include "types.h"
#include "debug.h"
#include "crypto.h"

struct azureus_node *
azureus_node_new(u8 proto_ver, struct sockaddr_storage *ss)
{
    struct azureus_node *an = NULL;
    struct key k;
    int ret;

    ASSERT(ss);

    an = (struct azureus_node *) malloc(sizeof(struct azureus_node));
    if (!an) {
        return NULL;
    }

    bzero(an, sizeof(struct azureus_node));

    an->proto_ver = proto_ver;
    memcpy(&an->ext_addr, ss, sizeof(struct sockaddr_storage));

    ret = azureus_node_get_id(&k, &an->ext_addr, proto_ver);
    if (ret != SUCCESS) {
        return NULL;
    }

    /* initialize the base class */
    ret = node_new(&an->node, &k);
    if (ret != SUCCESS) {
        free(an);
        return NULL;
    }

    /* FIXME: initialize the spoof-id differently */
    ret = azureus_node_get_spoof_id(an, &an->rnd_id);
    if (ret != SUCCESS) {
        free(an);
        return NULL;
    }

    an->node_status = AZUREUS_NODE_STATUS_ROUTABLE;

    return an;
}

void
azureus_node_delete(struct azureus_node *n)
{
    free(n);
}

int
azureus_node_get_id(struct key *k, struct sockaddr_storage *ss, u8 proto_ver)
{
    u_int8_t digest[20];
    char buf[64];
    char addr[64];
    socklen_t salen;
    int len;
    int ret;
    char const *pret = NULL;
    struct sockaddr_in *in4 = NULL;
    struct sockaddr_in6 *in6 = NULL;
    short port;
    
    switch (ss->ss_family) {
        case AF_INET:
            salen = sizeof(struct sockaddr_in);
            in4 = (struct sockaddr_in *)ss;
            port = in4->sin_port;
            pret = inet_ntop(ss->ss_family, (void *)&in4->sin_addr, 
                                addr, sizeof(addr));
            if (!pret) {
                return FAILURE;
            }
            
            break;

        case AF_INET6:
            salen = sizeof(struct sockaddr_in6);
            in6 = (struct sockaddr_in6 *)ss;
            port = in6->sin6_port;
            pret = inet_ntop(ss->ss_family, (void *)&in6->sin6_addr, 
                                addr, sizeof(addr));
            if (!pret) {
                return FAILURE;
            }

            break;

        default:
            return FAILURE;
    }

#if 0
    /* can we resolve this IP address? */
    ret = getnameinfo((struct sockaddr *)ss, salen,
                namebuf, sizeof(namebuf), NULL, 0, 0);

    if (ret) {
        if (ret != EAI_NONAME) {
            return FAILURE;
        } else {
            name = NULL;
        }
    } else {
        name = namebuf;
    }
#endif

    bzero(digest, sizeof(digest));

    if (proto_ver >= PROTOCOL_VERSION_RESTRICT_ID_PORTS) {
        len = snprintf(buf, sizeof(buf)-1, "%s:%hu",
                            addr, ntohs(port) % 1999);
    } else {
        len = snprintf(buf, sizeof(buf)-1, "%s:%hu",
                            addr, ntohs(port));
    }

    DEBUG("%#x %s\n", proto_ver, buf);

    ret = crypto_get_sha1_digest(buf, len, digest);
    if (ret != SUCCESS) {
        return ret;
    }

    ret = key_new(k, KEY_TYPE_SHA1, digest, 20);
    
    return SUCCESS;
}

int
azureus_node_get_spoof_id(struct azureus_node *an, u32 *id)
{
    int ret;

    ASSERT(an && id);

    /* FIXME: need to use DESede/ECB/PKCS5Padding(ip addr, key) */
    ret = crypto_get_rnd_int(id);
    if (ret != SUCCESS) {
        return ret;
    }

    return SUCCESS;
}
