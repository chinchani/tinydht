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

#ifndef __AZUREUS_RPC_UTILS_H__
#define __AZUREUS_RPC_UTILS_H__

#include <netinet/in.h>

#include "pkt.h"
#include "azureus_node.h"
#include "azureus_db.h"

int azureus_pkt_write_inetaddr(struct pkt *pkt, struct sockaddr_storage *ss); 
int azureus_pkt_read_inetaddr(struct pkt *pkt, struct sockaddr_storage *ss);

int azureus_pkt_write_node(struct pkt *pkt, struct azureus_node *an);
int azureus_pkt_read_node(struct pkt *pkt, struct azureus_node *an);

int azureus_pkt_write_db_key(struct pkt *pkt, struct azureus_db_key *key);
int azureus_pkt_read_db_key(struct pkt *pkt, struct azureus_db_key **key);

int azureus_pkt_write_db_valset(struct pkt *pkt, 
                                struct azureus_db_valset *valset, u8 proto_ver);
int azureus_pkt_read_db_valset(struct pkt *pkt, 
                                struct azureus_db_valset **valset, u8 proto_ver);

#endif /* __AZUREUS_RPC_UTILS_H__ */
