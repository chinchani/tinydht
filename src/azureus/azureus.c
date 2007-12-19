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

#include "azureus.h"
#include "azureus_dht.h"
#include "azureus_rpc.h"
#include "dht_types.h"

struct dht_prototype azureus_dht_prototype = {
    type:               DHT_TYPE_AZUREUS,
    constructor:        azureus_dht_new,
    destructor:         azureus_dht_delete,
    put:                azureus_dht_put,
    get:                azureus_dht_get,
    rpc_rx:             azureus_dht_rpc_rx,
    task_schedule:      azureus_dht_task_schedule,
    exit:               azureus_dht_exit
};

