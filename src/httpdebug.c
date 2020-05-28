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

#include <curl/curl.h>
#include "certifier/log.h"

struct data {
    char trace_ascii; // 1 or 0
};


static
void dump(const char *text, unsigned char *ptr, size_t size, char nohex) {
    size_t i;
    size_t c;

    unsigned int width = 0x10;

    if (nohex)
        /* without the hex output, we can fit more on screen */
        width = 0x40;

    log_debug("%s, %10.10ld bytes (0x%8.8lx)\n",
              text, (long) size, (long) size);

    for (i = 0; i < size; i += width) {

        log_debug("%4.4lx: ", (long) i);

        if (!nohex) {
            /* hex not disabled, show it */
            for (c = 0; c < width; c++)
                if (i + c < size)
                    log_debug("%02x ", ptr[i + c]);
                else
                    log_debug("   ");
        }

        for (c = 0; (c < width) && (i + c < size); c++) {
            /* check for 0D0A; if found, skip past and start a new line of output */
            if (nohex && (i + c + 1 < size) && ptr[i + c] == 0x0D &&
                ptr[i + c + 1] == 0x0A) {
                i += (c + 2 - width);
                break;
            }
            log_debug("%c",
                      (ptr[i + c] >= 0x20) && (ptr[i + c] < 0x80) ? ptr[i + c] : '.');
            /* check again for 0D0A, to avoid an extra \n if it's at width */
            if (nohex && (i + c + 2 < size) && ptr[i + c + 1] == 0x0D &&
                ptr[i + c + 2] == 0x0A) {
                i += (c + 3 - width);
                break;
            }
        }
        log_debug("\n"); /* newline */
    }
}

int
http_debug_trace(CURL *handle, curl_infotype type, char *data, size_t size, void *userp) {
    struct data config;

    // struct data * config = (struct data *) userp;
    const char *text = "";

    config.trace_ascii = 1;

    (void) handle; /* prevent compiler warning */

    XASSERT(userp == NULL);

    switch (type) {
        case CURLINFO_TEXT:
            printf("== Info: %s", data);
            break;
        case CURLINFO_HEADER_OUT:
            text = "=> Send header";
            break;
        case CURLINFO_DATA_OUT:
            text = "=> Send data";
            break;
        case CURLINFO_SSL_DATA_OUT:
            text = "=> Send SSL data";
            break;
        case CURLINFO_HEADER_IN:
            text = "<= Recv header";
            break;
        case CURLINFO_DATA_IN:
            text = "<= Recv data";
            break;
        case CURLINFO_SSL_DATA_IN:
            text = "<= Recv SSL data";
            break;
        default: /* in case a new one is introduced to shock us */
            return 0;
    }

    log_set_stripped(1);
    log_set_newlines(0);
    dump(text, (unsigned char *) data, size, config.trace_ascii);
    log_set_newlines(1);
    log_set_stripped(0);
    return 0;
} /* my_trace */
