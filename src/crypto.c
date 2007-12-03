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

#include <openssl/rand.h>
#include <openssl/sha.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "crypto.h"
#include "types.h"
#include "float.h"
#include "debug.h"

#if 0
static const char *crypto_seed_file = ".tinydht-crypto-rng-seed";
#endif

int
crypto_init(void)
{
    int fd;
    char buf[CRYPTO_MAX_SEED_BYTES];
    int len;
    int ret;

    /* rng seed file does not exist, read /dev/random */
    fd = open("/dev/random", O_RDONLY);
    if (fd < 0) {
        return FAILURE;
    }

    len = read(fd, buf, CRYPTO_MAX_SEED_BYTES);
    if (len <= 0) {
        close(fd);
        return FAILURE;
    }

    close(fd);

    RAND_seed(buf, len);

    ret = RAND_status();
    if (!ret) {
        return FAILURE;
    }

    /* FIXME: now, create a seed file and save it
     * so that we dont have to read /dev/random repeatedly */

    return SUCCESS;
}

void
crypto_exit(void)
{
    RAND_cleanup();
}

int
crypto_get_rnd_bytes(void *buf, int num)
{
    int ret;

    CRYPTO_ASSERT(buf && (num > 0));

    ret = RAND_bytes(buf, num);
    if (!ret) {
        return FAILURE;
    }

    return SUCCESS;
}

int
crypto_get_rnd_short(u16 *s)
{
    int ret;

    if (!s) {
        return FAILURE;
    }
    
    ret = crypto_get_rnd_bytes(s, sizeof(u16));
    if (ret != SUCCESS) {
        return ret;
    }

    return SUCCESS;
}

int
crypto_get_rnd_int(u32 *i) 
{
    int ret;

    if (!i) {
        return FAILURE;
    }
    
    ret = crypto_get_rnd_bytes(i, sizeof(u32));
    if (ret != SUCCESS) {
        return ret;
    }

    return SUCCESS;
}

int
crypto_get_rnd_long(u64 *l) 
{
    int ret;

    if (!l) {
        return FAILURE;
    }
    
    ret = crypto_get_rnd_bytes(l, sizeof(u64));
    if (ret != SUCCESS) {
        return ret;
    }

    return SUCCESS;
}

int
crypto_get_sha1_digest(void *data, int len, void *digest)
{
    CRYPTO_ASSERT(data && (len > 0) && digest);
    SHA1(data, len, digest);
    return SUCCESS;
}


