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

#ifndef __TYPES_H__
#define __TYPES_H__

#include <stddef.h>
#include <sys/types.h>
#include <features.h>
#include <stdint.h>
#include <arpa/inet.h>

/* yes, yes, Greg Kroah-Hartman absolutely despises 'typedef'
 * but quite useful for us actually, 
 * and I promise this is the only place :) 
 **/
typedef u_int8_t    u8;
typedef u_int16_t   u16;
typedef u_int32_t   u32;
typedef u_int64_t   u64;

typedef u8          bool;

#define TRUE        ((bool)1)
#define FALSE       ((bool)(!TRUE))

#define SUCCESS     0
#define FAILURE     (-(!SUCCESS))

#define ZERO        (0)
#define ONE         (1)

#define BIT32(x)        ((u32)(1) << x)

extern uint64_t ntoh64 (uint64_t __netlong) 
    __THROW __attribute__ ((__const__));
extern uint64_t hton64 (uint64_t __hostlong) 
    __THROW __attribute__ ((__const__));

# if __BYTE_ORDER == __BIG_ENDIAN
/* The host byte order is the same as network byte order,
   so these functions are all just identity.  */
# define ntoh64(x)      (x)
# else
#  if __BYTE_ORDER == __LITTLE_ENDIAN
#   define ntoh64(x)    __bswap_64 (x)
#  endif
# endif

# if __BYTE_ORDER == __BIG_ENDIAN
/* The host byte order is the same as network byte order,
   so these functions are all just identity.  */
# define hton64(x)      (x)
# else
#  if __BYTE_ORDER == __LITTLE_ENDIAN
#   define hton64(x)    __bswap_64 (x)
#  endif
# endif

#define container_of(ptr, type, member) ({              \
  const typeof( ((type *)0)->member ) *__mptr = (ptr);  \
  (type *)( (char *)__mptr - offsetof(type,member) );})

#define NANOSLEEP(nanoseconds)                                  \
        do {                                                    \
                struct timespec ts;                             \
                                                                \
                bzero(&ts, sizeof(ts));                         \
                ts.tv_sec = nanoseconds/(1000*1000*1000);       \
                ts.tv_nsec = nanoseconds % (1000*1000*1000);    \
        } while(0)

#define MICROSLEEP(x)   NANOSLEEP((x)*1000)
#define MILLISLEEP(x)   NANOSLEEP((x)*1000*1000)

#endif /* __TYPES_H__ */

