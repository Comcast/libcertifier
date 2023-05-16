#define _XOPEN_SOURCE 700

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

// https://github.com/rxi/log.c
// Made a few mods to support rotation and other things
/*
 * Copyright (c) 2017 rxi
 *
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include "certifier/log.h"
#include "certifier/certifier_internal.h"

static struct
{
    void * udata;
    log_LockFn lock;
    log_callback cb;
    char file_name[MEDIUM_STRING_SIZE];
    XFILE fp;
    int level;
    int quiet;
    int newlines;
    int stripped;
    unsigned long long max_size;
} L;

static const char * level_names[] = { "TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL" };

#ifdef LOG_USE_COLOR
static const char * level_colors[] = { "\x1b[94m", "\x1b[36m", "\x1b[32m", "\x1b[33m", "\x1b[31m", "\x1b[35m" };
#endif

static unsigned long long get_file_size(XFILE fp)
{
    if (fp == NULL)
    {
        return 0;
    }

    struct XSTAT sb;
    int res = XFSTAT(XFILENO(fp), &sb);
    if (res != 0)
    {
        XFPRINTF(stderr, "[log.get_file_size()] - Error fstat res(%d): %d (%s)\n", res, errno, XSTRERROR(errno));
        return res;
    }
    return sb.st_size;
}

static XFILE open_output(void)
{
    XFILE fp = NULL;
    // Open Output File
    int fd = XOPEN(L.file_name, XO_CREAT | XO_APPEND | XO_WRONLY, XS_IRUSR | XS_IWUSR | XS_IRGRP | XS_IWGRP | XS_IROTH | XS_IWOTH);
    if (fd < 0)
    {
        XFPRINTF(stderr, "[log.open_output()] - Error open: %d (%s)\n", errno, XSTRERROR(errno));
    }
    else
    {
        fp = XFDOPEN(fd, "a");
    }
    return fp;
}

static int rotate_as_needed(void)
{

    int rc = 0;
    unsigned long long file_size;

    if (XSTRLEN(L.file_name) == 0)
    {
        rc = LOG_ERR_1;
        goto cleanup;
    }

    // set up as needed
    if (L.fp == NULL)
    {
        L.fp = open_output();
        if (L.fp == NULL)
        {
            rc = LOG_ERR_2;
            goto cleanup;
        }
    }

    file_size = get_file_size(L.fp);
    if ((L.max_size > 0) && (file_size > L.max_size))
    {
        char new_name[MAX_NEW_NAME_SIZE];
        if (XFCLOSE(L.fp))
        {
            rc = LOG_ERR_3;
            goto cleanup;
        }
        L.fp = NULL;
        XSNPRINTF(new_name, sizeof(new_name), "%s.old", L.file_name);
        if (XRENAME(L.file_name, new_name))
        {
            rc = LOG_ERR_4;
            goto cleanup;
        }
        L.fp = open_output();
        if (L.fp == NULL)
        {
            rc = LOG_ERR_5;
            goto cleanup;
        }
    }

cleanup:
    return rc;
}

static void lock(void)
{
    if (L.lock)
    {
        L.lock(L.udata, 1);
    }
}

static void unlock(void)
{
    if (L.lock)
    {
        L.lock(L.udata, 0);
    }
}

XFILE log_get_fp()
{
    return L.fp;
}

void log_set_udata(void * udata)
{
    L.udata = udata;
}

void log_set_lock(log_LockFn fn)
{
    L.lock = fn;
}

void log_set_file_name(const char * file_name)
{
    char * copied_file_name = NULL;
    if (file_name != NULL)
    {
        copied_file_name = XSTRDUP(file_name);
        if (copied_file_name != NULL)
        {
            XSTRNCPY(L.file_name, copied_file_name, sizeof(L.file_name) - 1);
            L.file_name[sizeof(L.file_name) - 1] = '\0';
            XFREE(copied_file_name);
        }
    }
}

void log_set_level(int level)
{
    L.level = level;
}

void log_set_quiet(int enable)
{
    L.quiet = enable ? 1 : 0;
}

void log_set_stripped(int enable)
{
    L.stripped = enable ? 1 : 0;
}

void log_set_newlines(int enable)
{
    L.newlines = enable ? 1 : 0;
}

void log_set_max_size(int max_size)
{
    L.max_size = max_size;
}

void log_set_callback(log_callback cb)
{
    L.cb = cb;
}

void log_log(int level, const char * file, int line, const char * fmt, ...)
{

    int rc;

    if (L.cb != NULL)
    {
        char * msg = NULL;
        XVA_LIST args;

        XVA_START(args, fmt);
        if (XVASPRINTF(&msg, fmt, args) == -1)
        {
            msg = NULL;
        }

        if (msg != NULL)
        {
            L.cb(level, file, line, msg);
            XFREE(msg);
        }
        XVA_END(args);

        return;
    }

    if (level < L.level)
    {
        return;
    }

    /* Acquire lock */
    lock();

    /* Get current time */
    time_t t       = time(NULL);
    struct tm * lt = localtime(&t);

    /* Log to stderr */
    if (!L.quiet)
    {
        XVA_LIST args;
        char buf[VERY_SMALL_STRING_SIZE];
        if (lt == NULL)
        {
            return;
        }
        buf[strftime(buf, sizeof(buf), "%H:%M:%S", lt)] = '\0';
#ifdef LOG_USE_COLOR
        XFPRINTF(stderr, "%s %s%-5s\x1b[0m \x1b[90m%s:%d:\x1b[0m ", buf, level_colors[level], level_names[level], file, line);
#else
        if (!L.stripped)
            XFPRINTF(stderr, "%s %-5s %s:%d: ", buf, level_names[level], file, line);
#endif
        XVA_START(args, fmt);
        XVFPRINTF(stderr, fmt, args);
        XVA_END(args);

        if (L.newlines)
        {
            XFPRINTF(stderr, "\n");
        }

        XFFLUSH(stderr);

        /* Log to file */
        if (XSTRLEN(L.file_name) > 0)
        {
            // rotate as needed
            rc = rotate_as_needed();
            if (rc)
            {
                XFPRINTF(stderr, "[log_log.rotate_as_needed()] - Critical error and received error code: %i\n", rc);
                goto cleanup;
            }

            XVA_LIST args;
            char buf[VERY_SMALL_STRING_SIZE];
            buf[strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", lt)] = '\0';

            if (!L.stripped)
                XFPRINTF(L.fp, "%s %-5s %s:%d: ", buf, level_names[level], file, line);

            XVA_START(args, fmt);
            XVFPRINTF(L.fp, fmt, args);
            XVA_END(args);

            if (L.newlines)
            {
                XFPRINTF(L.fp, "\n");
            }

            XFFLUSH(L.fp);
            XFSYNC(fileno(L.fp));
        }
    }

cleanup:
    /* Release lock */
    unlock();
}

int log_destroy(void)
{
    if (L.fp != NULL)
    {
        XFCLOSE(L.fp);
        L.fp = NULL;
    }
    return 0;
}
