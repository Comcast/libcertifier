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

#include "certifier/base64.h"

static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const unsigned char table[] = {
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 62, 64, 64, 64, 63,
        52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64, 64, 64, 64, 64, 64,
        64, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
        15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 64, 64, 64, 64, 64,
        64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
        41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64
};

static int base64_count(const unsigned char *start) {
    const unsigned char *end = start;
    while (table[*end++] != 64);
    return end - start;
}

int base64_decode_len(const char *coded_src) {
    return ((base64_count((const unsigned char *) coded_src) + 2) / 4) * 3 + 1;
}

int base64_decode(unsigned char *plain_dst, const char *coded_src) {
    unsigned char a, b, c, d;
    int n = base64_count((const unsigned char *) coded_src) - 1;
    unsigned char *data = (unsigned char *) plain_dst;
    const unsigned char *p = (const unsigned char *) coded_src;
    while (n > 4) {
        a = table[*p++];
        b = table[*p++];
        c = table[*p++];
        d = table[*p++];
        *data++ = a << 2 | b >> 4;
        *data++ = b << 4 | c >> 2;
        *data++ = c << 6 | d;
        n -= 4;
    }
    if (n > 1) {
        a = table[*p++];
        b = table[*p++];
        *data++ = a << 2 | b >> 4;
        if (n > 2) {
            c = table[*p++];
            *data++ = b << 4 | c >> 2;
            if (n > 3) {
                d = table[*p++];
                *data++ = c << 6 | d;
            }
        }
    }
    *data++ = '\0';
    return data - plain_dst - 1;
}

int base64_encode_len(int len) {
    return (((len + 2) / 3) * 4) + 1;
}

int base64_encode(char *coded_dst, const unsigned char *plain_src, int len_plain_src) {
    unsigned char a, b, c;
    char *p = coded_dst;
    const unsigned char *data = plain_src;
    int n = len_plain_src;
    while (n > 2) {
        a = *data++;
        b = *data++;
        c = *data++;
        *p++ = b64[a >> 2];
        *p++ = b64[b >> 4 | (a & 0x03) << 4];
        *p++ = b64[c >> 6 | (b & 0x0F) << 2];
        *p++ = b64[c & 0x3F];
        n -= 3;
    }
    if (n > 0) {
        a = *data++;
        *p++ = b64[a >> 2];
        if (n == 1) {
            *p++ = b64[(a & 0x03) << 4];
            *p++ = '=';
        } else {
            b = *data++;
            *p++ = b64[b >> 4 | (a & 0x03) << 4];
            *p++ = b64[(b & 0x0F) << 2];
        }
        *p++ = '=';
    }
    *p++ = '\0';
    return p - coded_dst;
}