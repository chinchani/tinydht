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

#ifndef __DEBUG_H__
#define __DEBUG_H__

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#define PROCESS_CRASH(x)                                        \
    do {                                                        \
        char *__p = NULL;                                       \
        *__p = 0;                                               \
    } while (0)

#define ASSERT(x)                                               \
    do {                                                        \
        if ((x) == 0) {                                         \
            printf("[ASSERT] %s:%d %s\n",                       \
                    __FILE__, __LINE__, __FUNCTION__);          \
            PROCESS_CRASH(x);                                   \
        }                                                       \
    } while (0)

#define ERROR(_fmt, _args...)                                   \
    do {                                                        \
        printf("[ERROR] %s:%d %s() - " _fmt,                    \
                __FILE__, __LINE__, __FUNCTION__, ##_args);     \
    } while (0)

#define INFO(_fmt, _args...)                                    \
    do {                                                        \
        printf("[INFO] %s:%d %s() - " _fmt,                     \
                __FILE__, __LINE__, __FUNCTION__, ##_args);     \
    } while (0)

#define DEBUG(_fmt, _args...)                                    \
    do {                                                        \
        printf("[DEBUG] %s:%d %s() - " _fmt,                     \
                __FILE__, __LINE__, __FUNCTION__, ##_args);     \
    } while (0)

#endif /* __DEBUG_H__ */
