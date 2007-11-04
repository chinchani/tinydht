/***************************************************************************
 *   Copyright (C) 2007 by Saritha Kalyanam                                *
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

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/time.h>
#include <time.h>
#include <stdlib.h>

#include "tinydht.h"
#include "crypto.h"

#define MAX_KEYS        5

const char * key[] = {
    "key1",
    "key2",
    "key3",
    "key4",
    "key5",
    (char *)0
};

const char * value[] = {
    "value1",
    "value2",
    "value3",
    "value4",
    "value5",
    (char *)0
};

int
main(int argc, char *argv[])
{
    int sock;
    struct sockaddr_in addr4;
    int ret;
    struct tinydht_msg_req req;
    struct tinydht_msg_rsp rsp;
    u32 index;
    struct timeval tv;

    bzero(&tv, sizeof(tv));
    gettimeofday(&tv, NULL);
    srandom(tv.tv_usec);
    index = random() % MAX_KEYS;

    /* do a PUT on TinyDHT */
    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) {
        perror("socket()");
        return -1;
    }

    bzero(&addr4, sizeof(struct sockaddr_in));
    addr4.sin_family = AF_INET;
    addr4.sin_port = htons(TINYDHT_SERVICE);
    ret = inet_aton("127.0.0.1", &addr4.sin_addr);
    if (ret < 0) {
        return -1;
    }

    printf("%s:%hu\n", inet_ntoa(addr4.sin_addr), TINYDHT_SERVICE);

    ret = connect(sock, (struct sockaddr *)&addr4, sizeof(addr4));
    if (ret < 0) {
        perror("connect()");
        return -1;
    }

    bzero(&req, sizeof(req));
    req.action = TINYDHT_ACTION_PUT;
    strncpy(req.key, key[index], MAX_KEY_LEN);
    req.key_len = htonl(strlen(key[index]));
    strncpy(req.val, value[index], MAX_KEY_LEN);
    req.val_len = htonl(strlen(value[index]));

    DEBUG("PUT send - key(%s) -> val(%s)\n", req.key, req.val);
    ret = send(sock, &req, sizeof(req), 0);
    if (ret < 0 || ret != sizeof(req)) {
        perror("send()");
        return -1;
    }

    ret = recv(sock, &rsp, sizeof(rsp), 0);
    if (ret < 0 || ret != sizeof(rsp)) {
        perror("recv()");
        return -1;
    }
    DEBUG("PUT recv %d\n", rsp.status);

    close(sock);

    return 0;
}