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

#define _POSIX_C_SOURCE 200809L

#include "certifier/util.h"
#include "certifier/certifier_internal.h"
#include "certifier/parson.h"
#include "certifier/security.h"
#include "certifier/types.h"

#define MAX_ARGS 64
#define BUFFER_SIZE BUFSIZ

int util_is_empty(const char * s)
{
    if (s == NULL)
    {
        return 1;
    }
    while (XISSPACE(*s) && s++)
        ;
    return !*s;
}

int util_is_not_empty(const char * s)
{
    return !util_is_empty(s);
}

size_t util_split(char * buffer, char ** argv, size_t argv_size, int delimiter)
{
    char *p = NULL, *start_of_word = NULL;
    int c;
    enum states
    {
        DULL,
        IN_WORD,
        IN_STRING
    } state     = DULL;
    size_t argc = 0;

    for (p = buffer; argc < argv_size && *p != '\0'; p++)
    {
        c = (unsigned char) *p;
        switch (state)
        {
        case DULL:
            if (delimiter == c)
            {
                continue;
            }

            if (c == '\'')
            {
                state         = IN_STRING;
                start_of_word = p + 1;
                continue;
            }
            state         = IN_WORD;
            start_of_word = p;
            continue;

        case IN_STRING:
            if (c == '\'')
            {
                *p           = 0;
                argv[argc++] = start_of_word;
                state        = DULL;
            }
            continue;

        case IN_WORD:
            if (delimiter == c)
            {
                *p           = 0;
                argv[argc++] = start_of_word;
                state        = DULL;
            }
            continue;
        }
    }

    if (state != DULL && argc < argv_size)
        argv[argc++] = start_of_word;

    return argc;
}

void util_trim(char * str)
{
    int i;
    int begin = 0;
    int end   = XSTRLEN(str) - 1;

    while (XISSPACE((unsigned char) str[begin]))
        begin++;

    while ((end >= begin) && XISSPACE((unsigned char) str[end]))
        end--;

    // Shift all characters back to the start of the string array.
    for (i = begin; i <= end; i++)
        str[i - begin] = str[i];

    str[i - begin] = '\0'; // Null terminate string.
}

/**
 * Checks if a file exists.
 * @param filename to check.
 */
bool util_file_exists(const char * filename)
{
    struct XSTAT buffer;

    if (util_is_empty(filename))
    {
        return false;
    }

    int exist = XSTAT(filename, &buffer);
    if (exist == 0)
        return true;
    else
        return false;
}

int util_delete_file(const char * filename)
{
    int status = 1;

    if (util_is_not_empty(filename))
    {
        status = XREMOVE(filename);
    }
    return status;
}

int util_rename_file(const char * old_filename, const char * new_filename)
{
    int status = 1;

    if ((util_is_not_empty(old_filename)) && (util_is_not_empty(new_filename)))
    {
        status = XRENAME(old_filename, new_filename);
    }
    return status;
}

static JSON_Value * create_error(const char * method, const char * error_message, const char * file, int line)
{
    char tmp[MEDIUM_STRING_SIZE];

    JSON_Value * root_value   = json_value_init_object();
    JSON_Object * root_object = json_value_get_object(root_value);

    if (method)
    {
        XSTRNCPY(tmp, method, sizeof(tmp) - 1);
        tmp[sizeof(tmp) - 1] = '\0';
        json_object_set_string(root_object, "method", tmp);
    }

    if (error_message)
    {
        XSTRNCPY(tmp, error_message, sizeof(tmp) - 1);
        tmp[sizeof(tmp) - 1] = '\0';
        json_object_set_string(root_object, "error_message", tmp);
    }

    if (file)
    {
        json_object_set_string(root_object, "file", file);
    }

    json_object_set_number(root_object, "line", line);

    return root_value;
}

char * util_format_curl_error(const char * method, long http_code, long curl_code, const char * error_message,
                              const char * http_response_str, const char * file, int line)
{

    JSON_Value * root_value   = create_error(method, error_message, file, line);
    JSON_Object * root_object = json_value_get_object(root_value);
    char * serialized_string  = NULL;

    json_object_set_number(root_object, "http_code", http_code);
    json_object_set_number(root_object, "curl_code", curl_code);

    if (http_response_str)
    {
        json_object_set_string(root_object, "http_response", http_response_str);
    }

    serialized_string = json_serialize_to_string_pretty(root_value);

    if (root_value)
    {
        json_value_free(root_value);
    }

    return serialized_string;
} /* util_curl_error_msg */

char * util_format_error(const char * method, const char * error_message, const char * file, int line)
{
    JSON_Value * root_value  = create_error(method, error_message, file, line);
    char * serialized_string = json_serialize_to_string_pretty(root_value);

    if (root_value)
    {
        json_value_free(root_value);
    }

    return serialized_string;
} /* util_format_error */

char * util_generate_random_value(int num_chars, const char * allow_chars)
{
    char * nc        = NULL;
    unsigned int max = XSTRLEN(allow_chars);
    int i, len;

    if (max == 0)
        return NULL;

    len = num_chars;
    nc  = (char *) XMALLOC((len + 1) * sizeof(char));
    if (nc != NULL)
    {
        for (i = 0; i < len; i++)
        {
            unsigned char buf = '\0';
            security_get_random_bytes(&buf, 1);
            nc[i] = allow_chars[((short) buf) % max];
        }
        nc[i] = '\0';
    }
    return (nc);
}

bool util_starts_with(const char * a, const char * b)
{
    if (XSTRNCMP(a, b, XSTRLEN(b)) == 0)
        return 1;
    return 0;
}

int util_slurp(const char * filename, char ** bufo, size_t * leno)
{
    int fd;
    struct XSTAT st;
    ssize_t nread = 0;
    ssize_t n;
    int r = 0;

    fd = XOPEN(filename, XO_RDONLY);
    XFFLUSH(stdout);

    if (fd < 0)
    {
        r = XERRNO;
        goto out;
    }

    if (XFSTAT(fd, &st) < 0)
    {
        r = XERRNO;
        goto out;
    }

    if (st.st_size == 0)
    {
        *bufo = "";
        *leno = 0;
        r     = 0;
        goto out;
    }

    *bufo = XMALLOC(st.st_size + 1);
    if (!*bufo)
    {
        r = XENOMEM;
        goto out;
    }

    do
    {
        if ((n = XREAD(fd, *bufo + nread, st.st_size - nread)) < 0)
        {
            if (XERRNO == XEINTR)
            {
                continue;
            }
            else
            {
                r = XERRNO;
                goto out;
            }
        }
        if (!n)
            break;
        nread += n;
    } while (nread < st.st_size);

    *leno               = nread;
    (*bufo)[st.st_size] = 0;

out:
    if (fd >= 0)
    {
        XCLOSE(fd);
    }
    return r;
}

void util_hex_dump(XFILE fp, void * data, int len)
{

    unsigned int i;
    unsigned int r, c;

    if (!fp)
        return;
    if (!data)
        return;

    for (r = 0, i = 0; r < (len / 16 + (len % 16 != 0)); r++, i += 16)
    {
        XFPRINTF(fp, "%04X:   ", i); /* location of first byte in line */

        for (c = i; c < i + 8; c++) /* left half of hex dump */
            if (c < len)
                XFPRINTF(fp, "%02X ", ((unsigned char const *) data)[c]);
            else
                XFPRINTF(fp, "   "); /* pad if short line */

        XFPRINTF(fp, "  ");

        for (c = i + 8; c < i + 16; c++) /* right half of hex dump */
            if (c < len)
                XFPRINTF(fp, "%02X ", ((unsigned char const *) data)[c]);
            else
                XFPRINTF(fp, "   "); /* pad if short line */

        XFPRINTF(fp, "   ");

        for (c = i; c < i + 16; c++) /* ASCII dump */
            if (c < len)
                if (((unsigned char const *) data)[c] >= 32 && ((unsigned char const *) data)[c] < 127)
                    XFPRINTF(fp, "%c", ((char const *) data)[c]);
                else
                    XFPRINTF(fp, "."); /* put this for non-printables */
            else
                XFPRINTF(fp, " "); /* pad if short line */

        XFPRINTF(fp, "\n");
    }

    XFFLUSH(fp);
}

int util_get_unixtime_ms(int64_t * timestamp)
{
    struct timespec now;
    if (timestamp == NULL)
    {
        return EFAULT;
    }

    int rc = clock_gettime(CLOCK_REALTIME, &now);

    if (rc == 0)
    {
        *timestamp = now.tv_sec * 1000LL;
        *timestamp += now.tv_nsec / (1000LL * 1000LL);
    }

    return rc;
}

char * util_format_str(const char * fmt, ...)
{
    char * msg = NULL;
    XVA_LIST args;
    XVA_START(args, fmt);
    if (XVASPRINTF(&msg, fmt, args) == -1)
    {
        msg = NULL;
    }
    XVA_END(args);

    return msg;
}
