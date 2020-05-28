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

#ifndef UTIL_H
#define UTIL_H

#include "certifier/types.h"

/**
 * Format an error message for the source location this is called at
 */
#define util_format_error_here(err_msg) util_format_error(__func__, err_msg, __FILE__, __LINE__)

typedef void (*util_error_callback)(const char *error_string);

int util_is_empty(const char *s);

int util_is_not_empty(const char *s);


size_t util_split(char *buffer, char **argv, size_t argv_size, int delimiter);

void util_trim(char *str);

bool
util_file_exists(const char *filename);

/**
 * Delete a file
 * @param filename to check.
 */
int
util_delete_file(const char *filename);

int
util_rename_file(const char *old_filename, const char *new_filename);

char *util_format_curl_error(const char *method, long http_code, long curl_code,
                             const char *error_message, const char *http_response_str,
                             const char *file, int line);

char *util_format_error(const char *method, const char *error_message, const char *file, int line);

char *
util_generate_random_value(int num_chars, const char *allow_chars);

bool util_starts_with(const char *a, const char *b);

int
util_slurp(const char *filename, char **bufo, size_t *leno);

void util_hex_dump(XFILE fp, void *addr, int len);

int util_execute(const char *command, int *status, char **out, int *outlen, char **err, int *errlen);

/**
 * Get the current UNIX timestamp, in milliseconds
 * @param timestamp a non-NULL location to write the timestamp
 * @return 0 on success, or an errno.
 * @see gettimeofday, clock_gettime
 */
int util_get_unixtime_ms(int64_t *timestamp);

char *util_format_str(const char *fmt, ...);

#endif
