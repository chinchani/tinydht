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

#ifndef __STUN_H__
#define __STUN_H__

#include "types.h"

/* http://www.ietf.org/rfc/rfc3489.txt */
/* http://tools.ietf.org/html/draft-ietf-behave-rfc3489bis-11 */

/* NOTE: STUN implementations out there are a mashup of rfc 3489 and 
 * the later ietf revisions */

#define STUN_SERVICE     3478

enum stun_msg_type {
    BINDING_REQUEST             = 0x0001,
    BINDING_RESPONSE            = 0x0101,
    BINDING_ERROR_RESPONSE      = 0x0111,
    SHARED_SECRET_REQUEST       = 0x0002,
    SHARED_SECRET_RESPONSE      = 0x0102,
    SHARED_SECRET_ERROR_RESPONSE = 0x0112
};

/* STUN header (20 bytes) */
struct stun_msg_hdr {
    u16         type;
    u16         len;
    u8          trans_id[16];
} __attribute__((packed));

enum stun_attr_type {
    MAPPED_ADDRESS      = 0x0001,
    RESPONSE_ADDRESS    = 0x0002,
    CHANGE_REQUEST      = 0x0003,
    SOURCE_ADDRESS      = 0x0004,
    CHANGED_ADDRESS     = 0x0005,
    USERNAME            = 0x0006,
    PASSWORD            = 0x0007,
    MESSAGE_INGERITY    = 0x0008,
    ERROR_CODE          = 0x0009,
    UNKNOWN_ATTRIBUTES  = 0x000a,
    REFLECTED_FROM      = 0x000b,
    REALM               = 0x0014,
    NONCE               = 0x0015,
    XOR_MAPPED_ADDRESS  = 0x0020,
    SERVER              = 0x8022,
    ALTERNATE_SERVER    = 0x8023,
    FINGERPRINT         = 0x8028
};

struct stun_tlv {
    u16         type;
    u16         len;
    u8          val[0];
} __attribute__((packed));


struct stun_inetaddr_attr {
    u16         family;
    u16         port;
    u8          addr[0];
} __attribute__((packed));
#define STUN_INETADDR4_TYPE     0x0001

struct stun_chg_req_attr {
    u32         flags;
} __attribute__((packed));
#define CHANGE_IP_MASK          BIT32(1)
#define CHANGE_PORT_MASK        BIT32(2)

struct stun_err_code_attr {
    u32         classnum;
    u8          *val;          
} __attribute__((packed));
#define ERROR_CODE_CLASS_MASK   (BIT32(4) | BIT32(5) | BIT32(6))
#define ERROR_CODE_NUMBER_MASK  (BIT32(0) | BIT32(1) | BIT32(2) | BIT32(3))

struct stun_msg {
    struct stun_msg_hdr         hdr;
    struct sockaddr_in          map_addr;
    struct sockaddr_in          rsp_addr;
    struct sockaddr_in          server;
    struct sockaddr_in          alt_server;
    struct sockaddr_in          xor_addr;
    struct sockaddr_in          chg_addr;
    struct sockaddr_in          src_addr;
    struct stun_chg_req_attr    chg_req;
    struct stun_err_code_attr   err_code;
};

enum stun_nat_type {
    STUN_NAT_TYPE_UNKNOWN = 0,
    STUN_NO_NAT,
    STUN_NAT_FULL_CONE,
    STUN_NAT_RESTRICTED_CONE,
    STUN_NAT_PORT_RESTRICTED_CONE,
    STUN_NAT_SYMMETRIC
};

struct stun_nat_info {
    enum stun_nat_type          nat_type;
    struct sockaddr_storage     internal;
    struct sockaddr_storage     external;
};


int stun_get_nat_info(struct stun_nat_info *info);

#endif /* __STUN_H__ */
