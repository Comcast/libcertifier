/**
* Copyright 2019 Comcast Cable Communications Management, LLC
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*
* SPDX-License-Identifier: Apache-2.0
*/

/*
 * Copyright 2012-2014 Luke Dashjr
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the standard MIT license.  See COPYING for more details.
 */

# define true    1
# define false   0

#include "certifier/base58.h"
#include "certifier/types.h"


#define MAXBUFSIZE 4096

static const char b58digits_ordered[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

int
base58_b58enc(char *b58, const void *data, size_t binsz) {
    uint8_t buf[MAXBUFSIZE];

    const uint8_t *bin = (const uint8_t *) data;
    int carry;
    int i, j, high, zcount = 0;
    size_t size;

    while (zcount < (int) binsz && !bin[zcount])
        ++zcount;

    size = (binsz - zcount) * 138 / 100 + 1;

    if (size > MAXBUFSIZE)
        return 0;

    XMEMSET(buf, 0, size);

    for (i = zcount, high = (int) size - 1; i < (int) binsz; ++i, high = j) {
        for (carry = bin[i], j = (int) size - 1; (j > high) || carry; --j) {
            carry += 256 * buf[j];
            buf[j] = carry % 58;
            carry /= 58;
        }
    }

    for (j = 0; j < (int) size && !buf[j]; ++j);

    if (zcount)
        XMEMSET(b58, '1', zcount);
    for (i = zcount; j < (int) size; ++i, ++j)
        b58[i] = b58digits_ordered[buf[j]];
    b58[i] = '\0';

    return i + 1;
} /* b58enc */
