// https://github.com/rxi/log.c
/**
 * Copyright (c) 2017 rxi
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the MIT license. See `log.c` for details.
 */

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

#ifndef LOG_H
#define LOG_H

#include "certifier/types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define LOG_VERSION "0.1.0"

#define LOG_ERR_1 1
#define LOG_ERR_2 2
#define LOG_ERR_3 3
#define LOG_ERR_4 4
#define LOG_ERR_5 5

#define MAX_NEW_NAME_SIZE 2048

typedef enum
{
    LOG_TRACE,
    LOG_DEBUG,
    LOG_INFO,
    LOG_WARN,
    LOG_ERROR,
    LOG_FATAL
} log_level;

typedef void (*log_LockFn)(void * udata, int lock);

typedef void (*log_callback)(const log_level level, const char * file, const int line, const char * msg);

#define log_trace(...) log_log(LOG_TRACE, __FILE__, __LINE__, __VA_ARGS__)
#define log_debug(...) log_log(LOG_DEBUG, __FILE__, __LINE__, __VA_ARGS__)
#define log_info(...) log_log(LOG_INFO, __FILE__, __LINE__, __VA_ARGS__)
#define log_warn(...) log_log(LOG_WARN, __FILE__, __LINE__, __VA_ARGS__)
#define log_error(...) log_log(LOG_ERROR, __FILE__, __LINE__, __VA_ARGS__)
#define log_fatal(...) log_log(LOG_FATAL, __FILE__, __LINE__, __VA_ARGS__)

XFILE log_get_fp();

void log_set_udata(void * udata);

void log_set_lock(log_LockFn fn);

void log_set_file_name(const char * file_name);

void log_set_level(int level);

void log_set_quiet(int enable);

void log_set_stripped(int enable);

void log_set_newlines(int enable);

void log_set_max_size(int max_size);

void log_set_callback(log_callback cb);

void log_log(int level, const char * file, int line, const char * fmt, ...);

int log_destroy(void);

#ifdef __cplusplus
}
#endif

#endif
