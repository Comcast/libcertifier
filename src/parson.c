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
 Parson ( http://kgabis.github.com/parson/ )
 Copyright (c) 2012 - 2017 Krzysztof Gabis

 Permission is hereby granted, free of charge, to any person obtaining a copy
 of this software and associated documentation files (the "Software"), to deal
 in the Software without restriction, including without limitation the rights
 to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 copies of the Software, and to permit persons to whom the Software is
 furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included in
 all copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 THE SOFTWARE.
*/
#ifdef _MSC_VER
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif /* _CRT_SECURE_NO_WARNINGS */
#endif /* _MSC_VER */

#include "certifier/parson.h"
#include "certifier/types.h"

/* Apparently sscanf is not implemented in some "standard" libraries, so don't use it, if you
 * don't have to. */
#define sscanf THINK_TWICE_ABOUT_USING_SSCANF

#define STARTING_CAPACITY 16
#define MAX_NESTING       2048
#define FLOAT_FORMAT      "%1.17g"

#define SIZEOF_TOKEN(a)       (sizeof(a) - 1)
#define SKIP_CHAR(str)        ((*str)++)
#define SKIP_WHITESPACES(str) while (XISSPACE((unsigned char)(**str))) { SKIP_CHAR(str); }
#define MAX(a, b)             ((a) > (b) ? (a) : (b))

#undef malloc
#undef free

static JSON_Malloc_Function parson_malloc = malloc;
static JSON_Free_Function parson_free = free;

#define IS_CONT(b) (((unsigned char)(b) & 0xC0) == 0x80) /* is utf-8 continuation byte */

/* Type definitions */
typedef union json_value_value {
    char *string;
    double number;
    JSON_Object *object;
    JSON_Array *array;
    int boolean;
    int null;
} JSON_Value_Value;

struct json_value_t {
    JSON_Value *parent;
    JSON_Value_Type type;
    JSON_Value_Value value;
};

struct json_object_t {
    JSON_Value *wrapping_value;
    char **names;
    JSON_Value **values;
    size_t count;
    size_t capacity;
};

struct json_array_t {
    JSON_Value *wrapping_value;
    JSON_Value **items;
    size_t count;
    size_t capacity;
};

static void remove_comments(char *string, const char *start_token, const char *end_token);

static char *parson_strndup(const char *string, size_t n);

static char *parson_strdup(const char *string);

static int hex_char_to_int(char c);

static int parse_utf16_hex(const char *string, unsigned int *result);

static int num_bytes_in_utf8_sequence(unsigned char c);

static int verify_utf8_sequence(const unsigned char *string, int *len);

static int is_valid_utf8(const char *string, size_t string_len);

static int is_decimal(const char *string, size_t length);

/* JSON Object */
static JSON_Object *json_object_init(JSON_Value *wrapping_value);

static JSON_Status json_object_add(JSON_Object *object, const char *name, JSON_Value *value);

static JSON_Status json_object_resize(JSON_Object *object, size_t new_capacity);

static JSON_Value *json_object_nget_value(const JSON_Object *object, const char *name, size_t n);

static void json_object_free(JSON_Object *object);

/* JSON Array */
static JSON_Array *json_array_init(JSON_Value *wrapping_value);

static JSON_Status json_array_add(JSON_Array *array, JSON_Value *value);

static JSON_Status json_array_resize(JSON_Array *array, size_t new_capacity);

static void json_array_free(JSON_Array *array);

/* JSON Value */
static JSON_Value *json_value_init_string_no_copy(char *string);

/* Parser */
static JSON_Status skip_quotes(const char **string);

static int parse_utf16(const char **unprocessed, char **processed);

static char *process_string(const char *input, size_t len);

static char *get_quoted_string(const char **string);

static JSON_Value *parse_object_value(const char **string, size_t nesting);

static JSON_Value *parse_array_value(const char **string, size_t nesting);

static JSON_Value *parse_string_value(const char **string);

static JSON_Value *parse_boolean_value(const char **string);

static JSON_Value *parse_number_value(const char **string);

static JSON_Value *parse_null_value(const char **string);

static JSON_Value *parse_value(const char **string, size_t nesting);

/* Serialization */
static int json_serialize_to_buffer_r(const JSON_Value *value, char *buf, int level, int is_pretty, char *num_buf, size_t buf_size_in_bytes);

static int json_serialize_string(const char *string, char *buf, size_t buf_size_in_bytes);

static int append_indent(char *buf, int level, size_t buf_size_in_bytes);

static int append_string(char *buf, const char *string, size_t buf_size_in_bytes);

/* Various */
static char *parson_strndup(const char *string, size_t n) {
    char *output_string = (char *) parson_malloc(n + 1);
    if (!output_string) {
        return NULL;
    }
    output_string[n] = '\0';
    XSTRNCPY(output_string, string, n);
    return output_string;
}

static char *parson_strdup(const char *string) {
    return parson_strndup(string, XSTRLEN(string));
}

static int hex_char_to_int(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    } else if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    } else if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

static int parse_utf16_hex(const char *s, unsigned int *result) {
    int x1, x2, x3, x4;
    if (s[0] == '\0' || s[1] == '\0' || s[2] == '\0' || s[3] == '\0') {
        return 0;
    }
    x1 = hex_char_to_int(s[0]);
    x2 = hex_char_to_int(s[1]);
    x3 = hex_char_to_int(s[2]);
    x4 = hex_char_to_int(s[3]);
    if (x1 == -1 || x2 == -1 || x3 == -1 || x4 == -1) {
        return 0;
    }
    *result = (unsigned int) ((x1 << 12) | (x2 << 8) | (x3 << 4) | x4);
    return 1;
}

static int num_bytes_in_utf8_sequence(unsigned char c) {
    if (c == 0xC0 || c == 0xC1 || c > 0xF4 || IS_CONT(c)) {
        return 0;
    } else if ((c & 0x80) == 0) {    /* 0xxxxxxx */
        return 1;
    } else if ((c & 0xE0) == 0xC0) { /* 110xxxxx */
        return 2;
    } else if ((c & 0xF0) == 0xE0) { /* 1110xxxx */
        return 3;
    } else if ((c & 0xF8) == 0xF0) { /* 11110xxx */
        return 4;
    }
    return 0; /* won't happen */
}

static int verify_utf8_sequence(const unsigned char *string, int *len) {
    unsigned int cp = 0;
    *len = num_bytes_in_utf8_sequence(string[0]);

    if (*len == 1) {
        cp = string[0];
    } else if (*len == 2 && IS_CONT(string[1])) {
        cp = string[0] & 0x1F;
        cp = (cp << 6) | (string[1] & 0x3F);
    } else if (*len == 3 && IS_CONT(string[1]) && IS_CONT(string[2])) {
        cp = ((unsigned char) string[0]) & 0xF;
        cp = (cp << 6) | (string[1] & 0x3F);
        cp = (cp << 6) | (string[2] & 0x3F);
    } else if (*len == 4 && IS_CONT(string[1]) && IS_CONT(string[2]) && IS_CONT(string[3])) {
        cp = string[0] & 0x7;
        cp = (cp << 6) | (string[1] & 0x3F);
        cp = (cp << 6) | (string[2] & 0x3F);
        cp = (cp << 6) | (string[3] & 0x3F);
    } else {
        return 0;
    }

    /* overlong encodings */
    if ((cp < 0x80 && *len > 1) ||
        (cp < 0x800 && *len > 2) ||
        (cp < 0x10000 && *len > 3)) {
        return 0;
    }

    /* invalid unicode */
    if (cp > 0x10FFFF) {
        return 0;
    }

    /* surrogate halves */
    if (cp >= 0xD800 && cp <= 0xDFFF) {
        return 0;
    }

    return 1;
}

static int is_valid_utf8(const char *string, size_t string_len) {
    int len = 0;
    const char *string_end = string + string_len;
    while (string < string_end) {
        if (!verify_utf8_sequence((const unsigned char *) string, &len)) {
            return 0;
        }
        string += len;
    }
    return 1;
}

static int is_decimal(const char *string, size_t length) {
    if (length > 1 && string[0] == '0' && string[1] != '.') {
        return 0;
    }
    if (length > 2 && !XSTRNCMP(string, "-0", 2) && string[2] != '.') {
        return 0;
    }
    while (length--) {
        if (XSTRCHR("xX", string[length])) {
            return 0;
        }
    }
    return 1;
}

static void remove_comments(char *string, const char *start_token, const char *end_token) {
    int in_string = 0, escaped = 0;
    size_t i;
    char *ptr = NULL, current_char;
    size_t start_token_len = XSTRLEN(start_token);
    size_t end_token_len = XSTRLEN(end_token);
    if (start_token_len == 0 || end_token_len == 0) {
        return;
    }
    while ((current_char = *string) != '\0') {
        if (current_char == '\\' && !escaped) {
            escaped = 1;
            string++;
            continue;
        } else if (current_char == '\"' && !escaped) {
            in_string = !in_string;
        } else if (!in_string && XSTRNCMP(string, start_token, start_token_len) == 0) {
            for (i = 0; i < start_token_len; i++) {
                string[i] = ' ';
            }
            string = string + start_token_len;
            ptr = XSTRSTR(string, end_token);
            if (!ptr) {
                return;
            }
            for (i = 0; i < (ptr - string) + end_token_len; i++) {
                string[i] = ' ';
            }
            string = ptr + end_token_len - 1;
        }
        escaped = 0;
        string++;
    }
}

/* JSON Object */
static JSON_Object *json_object_init(JSON_Value *wrapping_value) {
    JSON_Object *new_obj = (JSON_Object *) parson_malloc(sizeof(JSON_Object));
    if (new_obj == NULL) {
        return NULL;
    }
    new_obj->wrapping_value = wrapping_value;
    new_obj->names = (char **) NULL;
    new_obj->values = (JSON_Value **) NULL;
    new_obj->capacity = 0;
    new_obj->count = 0;
    return new_obj;
}

static JSON_Status json_object_add(JSON_Object *object, const char *name, JSON_Value *value) {
    size_t index = 0;
    if (object == NULL || name == NULL || value == NULL) {
        return JSONFailure;
    }
    if (json_object_get_value(object, name) != NULL) {
        return JSONFailure;
    }
    if (object->count >= object->capacity) {
        size_t new_capacity = MAX(object->capacity * 2, STARTING_CAPACITY);
        if (json_object_resize(object, new_capacity) == JSONFailure) {
            return JSONFailure;
        }
    }
    index = object->count;
    object->names[index] = parson_strdup(name);
    if (object->names[index] == NULL) {
        return JSONFailure;
    }
    value->parent = json_object_get_wrapping_value(object);
    object->values[index] = value;
    object->count++;
    return JSONSuccess;
}

static JSON_Status json_object_resize(JSON_Object *object, size_t new_capacity) {
    char **temp_names = NULL;
    JSON_Value **temp_values = NULL;

    if ((object->names == NULL && object->values != NULL) ||
        (object->names != NULL && object->values == NULL) ||
        new_capacity == 0) {
        return JSONFailure; /* Shouldn't happen */
    }
    temp_names = (char **) parson_malloc(new_capacity * sizeof(char *));
    if (temp_names == NULL) {
        return JSONFailure;
    }
    temp_values = (JSON_Value **) parson_malloc(new_capacity * sizeof(JSON_Value *));
    if (temp_values == NULL) {
        parson_free(temp_names);
        return JSONFailure;
    }
    if (object->names != NULL && object->values != NULL && object->count > 0) {
        XMEMCPY(temp_names, object->names, object->count * sizeof(char *));
        XMEMCPY(temp_values, object->values, object->count * sizeof(JSON_Value *));
    }
    parson_free(object->names);
    parson_free(object->values);
    object->names = temp_names;
    object->values = temp_values;
    object->capacity = new_capacity;
    return JSONSuccess;
}

static JSON_Value *json_object_nget_value(const JSON_Object *object, const char *name, size_t n) {
    size_t i, name_length;
    for (i = 0; i < json_object_get_count(object); i++) {
        name_length = XSTRLEN(object->names[i]);
        if (name_length != n) {
            continue;
        }
        if (XSTRNCMP(object->names[i], name, n) == 0) {
            return object->values[i];
        }
    }
    return NULL;
}

static void json_object_free(JSON_Object *object) {
    size_t i;
    for (i = 0; i < object->count; i++) {
        parson_free(object->names[i]);
        json_value_free(object->values[i]);
    }
    parson_free(object->names);
    parson_free(object->values);
    parson_free(object);
}

/* JSON Array */
static JSON_Array *json_array_init(JSON_Value *wrapping_value) {
    JSON_Array *new_array = (JSON_Array *) parson_malloc(sizeof(JSON_Array));
    if (new_array == NULL) {
        return NULL;
    }
    new_array->wrapping_value = wrapping_value;
    new_array->items = (JSON_Value **) NULL;
    new_array->capacity = 0;
    new_array->count = 0;
    return new_array;
}

static JSON_Status json_array_add(JSON_Array *array, JSON_Value *value) {
    if (array->count >= array->capacity) {
        size_t new_capacity = MAX(array->capacity * 2, STARTING_CAPACITY);
        if (json_array_resize(array, new_capacity) == JSONFailure) {
            return JSONFailure;
        }
    }
    value->parent = json_array_get_wrapping_value(array);
    array->items[array->count] = value;
    array->count++;
    return JSONSuccess;
}

static JSON_Status json_array_resize(JSON_Array *array, size_t new_capacity) {
    JSON_Value **new_items = NULL;
    if (new_capacity == 0) {
        return JSONFailure;
    }
    new_items = (JSON_Value **) parson_malloc(new_capacity * sizeof(JSON_Value *));
    if (new_items == NULL) {
        return JSONFailure;
    }
    if (array->items != NULL && array->count > 0) {
        XMEMCPY(new_items, array->items, array->count * sizeof(JSON_Value *));
    }
    parson_free(array->items);
    array->items = new_items;
    array->capacity = new_capacity;
    return JSONSuccess;
}

static void json_array_free(JSON_Array *array) {
    size_t i;
    for (i = 0; i < array->count; i++) {
        json_value_free(array->items[i]);
    }
    parson_free(array->items);
    parson_free(array);
}

/* JSON Value */
static JSON_Value *json_value_init_string_no_copy(char *string) {
    JSON_Value *new_value = (JSON_Value *) parson_malloc(sizeof(JSON_Value));
    if (!new_value) {
        return NULL;
    }
    new_value->parent = NULL;
    new_value->type = JSONString;
    new_value->value.string = string;
    return new_value;
}

/* Parser */
static JSON_Status skip_quotes(const char **string) {
    if (**string != '\"') {
        return JSONFailure;
    }
    SKIP_CHAR(string);
    while (**string != '\"') {
        if (**string == '\0') {
            return JSONFailure;
        } else if (**string == '\\') {
            SKIP_CHAR(string);
            if (**string == '\0') {
                return JSONFailure;
            }
        }
        SKIP_CHAR(string);
    }
    SKIP_CHAR(string);
    return JSONSuccess;
}

static int parse_utf16(const char **unprocessed, char **processed) {
    unsigned int cp, lead, trail;
    int parse_succeeded = 0;
    char *processed_ptr = *processed;
    const char *unprocessed_ptr = *unprocessed;
    unprocessed_ptr++; /* skips u */
    parse_succeeded = parse_utf16_hex(unprocessed_ptr, &cp);
    if (!parse_succeeded) {
        return JSONFailure;
    }
    if (cp < 0x80) {
        processed_ptr[0] = (char) cp; /* 0xxxxxxx */
    } else if (cp < 0x800) {
        processed_ptr[0] = ((cp >> 6) & 0x1F) | 0xC0; /* 110xxxxx */
        processed_ptr[1] = ((cp) & 0x3F) | 0x80; /* 10xxxxxx */
        processed_ptr += 1;
    } else if (cp < 0xD800 || cp > 0xDFFF) {
        processed_ptr[0] = ((cp >> 12) & 0x0F) | 0xE0; /* 1110xxxx */
        processed_ptr[1] = ((cp >> 6) & 0x3F) | 0x80; /* 10xxxxxx */
        processed_ptr[2] = ((cp) & 0x3F) | 0x80; /* 10xxxxxx */
        processed_ptr += 2;
    } else if (cp >= 0xD800 && cp <= 0xDBFF) { /* lead surrogate (0xD800..0xDBFF) */
        lead = cp;
        unprocessed_ptr += 4; /* should always be within the buffer, otherwise previous sscanf would fail */
        if (*unprocessed_ptr++ != '\\' || *unprocessed_ptr++ != 'u') {
            return JSONFailure;
        }
        parse_succeeded = parse_utf16_hex(unprocessed_ptr, &trail);
        if (!parse_succeeded || trail < 0xDC00 || trail > 0xDFFF) { /* valid trail surrogate? (0xDC00..0xDFFF) */
            return JSONFailure;
        }
        cp = ((((lead - 0xD800) & 0x3FF) << 10) | ((trail - 0xDC00) & 0x3FF)) + 0x010000;
        processed_ptr[0] = (((cp >> 18) & 0x07) | 0xF0); /* 11110xxx */
        processed_ptr[1] = (((cp >> 12) & 0x3F) | 0x80); /* 10xxxxxx */
        processed_ptr[2] = (((cp >> 6) & 0x3F) | 0x80); /* 10xxxxxx */
        processed_ptr[3] = (((cp) & 0x3F) | 0x80); /* 10xxxxxx */
        processed_ptr += 3;
    } else { /* trail surrogate before lead surrogate */
        return JSONFailure;
    }
    unprocessed_ptr += 3;
    *processed = processed_ptr;
    *unprocessed = unprocessed_ptr;
    return JSONSuccess;
}


/* Copies and processes passed string up to supplied length.
Example: "\u006Corem ipsum" -> lorem ipsum */
static char *process_string(const char *input, size_t len) {
    const char *input_ptr = input;
    size_t initial_size = (len + 1) * sizeof(char);
    size_t final_size = 0;
    char *output = NULL, *output_ptr = NULL, *resized_output = NULL;
    output = (char *) parson_malloc(initial_size);
    if (output == NULL) {
        goto error;
    }
    output_ptr = output;
    while ((*input_ptr != '\0') && (size_t) (input_ptr - input) < len) {
        if (*input_ptr == '\\') {
            input_ptr++;
            switch (*input_ptr) {
                case '\"':
                    *output_ptr = '\"';
                    break;
                case '\\':
                    *output_ptr = '\\';
                    break;
                case '/':
                    *output_ptr = '/';
                    break;
                case 'b':
                    *output_ptr = '\b';
                    break;
                case 'f':
                    *output_ptr = '\f';
                    break;
                case 'n':
                    *output_ptr = '\n';
                    break;
                case 'r':
                    *output_ptr = '\r';
                    break;
                case 't':
                    *output_ptr = '\t';
                    break;
                case 'u':
                    if (parse_utf16(&input_ptr, &output_ptr) == JSONFailure) {
                        goto error;
                    }
                    break;
                default:
                    goto error;
            }
        } else if ((unsigned char) *input_ptr < 0x20) {
            goto error; /* 0x00-0x19 are invalid characters for json string (http://www.ietf.org/rfc/rfc4627.txt) */
        } else {
            *output_ptr = *input_ptr;
        }
        output_ptr++;
        input_ptr++;
    }
    *output_ptr = '\0';
    /* resize to new length */
    final_size = (size_t) (output_ptr - output) + 1;
    /* todo: don't resize if final_size == initial_size */
    resized_output = (char *) parson_malloc(final_size);
    if (resized_output == NULL) {
        goto error;
    }
    XMEMCPY(resized_output, output, final_size);
    parson_free(output);
    return resized_output;
    error:
    parson_free(output);
    return NULL;
}

/* Return processed contents of a string between quotes and
   skips passed argument to a matching quote. */
static char *get_quoted_string(const char **string) {
    const char *string_start = *string;
    size_t string_len = 0;
    JSON_Status status = skip_quotes(string);
    if (status != JSONSuccess) {
        return NULL;
    }
    string_len = *string - string_start - 2; /* length without quotes */
    return process_string(string_start + 1, string_len);
}

static JSON_Value *parse_value(const char **string, size_t nesting) {
    if (nesting > MAX_NESTING) {
        return NULL;
    }
    SKIP_WHITESPACES(string);
    switch (**string) {
        case '{':
            return parse_object_value(string, nesting + 1);
        case '[':
            return parse_array_value(string, nesting + 1);
        case '\"':
            return parse_string_value(string);
        case 'f':
        case 't':
            return parse_boolean_value(string);
        case '-':
        case '0':
        case '1':
        case '2':
        case '3':
        case '4':
        case '5':
        case '6':
        case '7':
        case '8':
        case '9':
            return parse_number_value(string);
        case 'n':
            return parse_null_value(string);
        default:
            return NULL;
    }
}

static JSON_Value *parse_object_value(const char **string, size_t nesting) {
    JSON_Value *output_value = json_value_init_object(), *new_value = NULL;
    JSON_Object *output_object = json_value_get_object(output_value);
    char *new_key = NULL;
    if (output_value == NULL || **string != '{' || output_object == NULL) {
        return NULL;
    }
    SKIP_CHAR(string);
    SKIP_WHITESPACES(string);
    if (**string == '}') { /* empty object */
        SKIP_CHAR(string);
        return output_value;
    }
    while (**string != '\0') {
        new_key = get_quoted_string(string);
        if (new_key == NULL) {
            json_value_free(output_value);
            return NULL;
        }
        SKIP_WHITESPACES(string);
        if (**string != ':') {
            parson_free(new_key);
            json_value_free(output_value);
            return NULL;
        }
        SKIP_CHAR(string);
        new_value = parse_value(string, nesting);
        if (new_value == NULL) {
            parson_free(new_key);
            json_value_free(output_value);
            return NULL;
        }
        if (json_object_add(output_object, new_key, new_value) == JSONFailure) {
            parson_free(new_key);
            json_value_free(new_value);
            json_value_free(output_value);
            return NULL;
        }
        parson_free(new_key);
        SKIP_WHITESPACES(string);
        if (**string != ',') {
            break;
        }
        SKIP_CHAR(string);
        SKIP_WHITESPACES(string);
    }
    SKIP_WHITESPACES(string);
    if (**string != '}' || /* Trim object after parsing is over */
        json_object_resize(output_object, json_object_get_count(output_object)) == JSONFailure) {
        json_value_free(output_value);
        return NULL;
    }
    SKIP_CHAR(string);
    return output_value;
}

static JSON_Value *parse_array_value(const char **string, size_t nesting) {
    JSON_Value *output_value = json_value_init_array(), *new_array_value = NULL;
    JSON_Array *output_array = json_value_get_array(output_value);
    size_t count;
    if (!output_value || **string != '[' || !output_array) {
        return NULL;
    }
    SKIP_CHAR(string);
    SKIP_WHITESPACES(string);
    if (**string == ']') { /* empty array */
        SKIP_CHAR(string);
        return output_value;
    }
    while (**string != '\0') {
        new_array_value = parse_value(string, nesting);
        if (new_array_value == NULL) {
            json_value_free(output_value);
            return NULL;
        }
        if (json_array_add(output_array, new_array_value) == JSONFailure) {
            json_value_free(new_array_value);
            json_value_free(output_value);
            return NULL;
        }
        SKIP_WHITESPACES(string);
        if (**string != ',') {
            break;
        }
        SKIP_CHAR(string);
        SKIP_WHITESPACES(string);
    }
    SKIP_WHITESPACES(string);
    count = json_array_get_count(output_array);
    if (count > 0) {
        if (**string != ']' || /* Trim array after parsing is over */
            json_array_resize(output_array, count) == JSONFailure) {
            json_value_free(output_value);
            return NULL;
        }
    }
    SKIP_CHAR(string);
    return output_value;
}

static JSON_Value *parse_string_value(const char **string) {
    JSON_Value *value = NULL;
    char *new_string = get_quoted_string(string);
    if (new_string == NULL) {
        return NULL;
    }
    value = json_value_init_string_no_copy(new_string);
    if (value == NULL) {
        parson_free(new_string);
        return NULL;
    }
    return value;
}

static JSON_Value *parse_boolean_value(const char **string) {
    size_t true_token_size = SIZEOF_TOKEN("true");
    size_t false_token_size = SIZEOF_TOKEN("false");
    if (XSTRNCMP("true", *string, true_token_size) == 0) {
        *string += true_token_size;
        return json_value_init_boolean(1);
    } else if (XSTRNCMP("false", *string, false_token_size) == 0) {
        *string += false_token_size;
        return json_value_init_boolean(0);
    }
    return NULL;
}

static JSON_Value *parse_number_value(const char **string) {
    char *end;
    double number = 0;
    errno = 0;

    number = strtod(*string, &end);
    if (errno || !is_decimal(*string, end - *string)) {
        return NULL;
    }
    *string = end;
    return json_value_init_number(number);
}

static JSON_Value *parse_null_value(const char **string) {
    size_t token_size = SIZEOF_TOKEN("null");
    if (XSTRNCMP("null", *string, token_size) == 0) {
        *string += token_size;
        return json_value_init_null();
    }
    return NULL;
}

/* Serialization */
#define APPEND_STRING(str) do { written = append_string(buf, (str), buf_size_in_bytes);\
                                if (written < 0) { return -1; }\
                                if (buf != NULL) { buf += written; buf_size_in_bytes -= written; }\
                                written_total += written; } while(0)

#define APPEND_INDENT(level) do { written = append_indent(buf, (level), buf_size_in_bytes);\
                                  if (written < 0) { return -1; }\
                                  if (buf != NULL) { buf += written; buf_size_in_bytes -= written; }\
                                  written_total += written; } while(0)

static int json_serialize_to_buffer_r(const JSON_Value *value, char *buf, int level, int is_pretty, char *num_buf, size_t buf_size_in_bytes) {
    const char *key = NULL, *string = NULL;
    JSON_Value *temp_value = NULL;
    JSON_Array *array = NULL;
    JSON_Object *object = NULL;
    size_t i = 0, count = 0;
    double num = 0.0;
    int written, written_total = 0;

    switch (json_value_get_type(value)) {
        case JSONArray:
            array = json_value_get_array(value);
            count = json_array_get_count(array);
            APPEND_STRING("[");
            if (count > 0 && is_pretty) {
                APPEND_STRING("\n");
            }
            for (i = 0; i < count; i++) {
                if (is_pretty) {
                    APPEND_INDENT(level + 1);
                }
                temp_value = json_array_get_value(array, i);
                written = json_serialize_to_buffer_r(temp_value, buf, level + 1, is_pretty, num_buf, buf_size_in_bytes);
                if (written < 0) {
                    return -1;
                }
                if (buf != NULL) {
                    buf += written;
                }
                written_total += written;
                if (i < (count - 1)) {
                    APPEND_STRING(",");
                }
                if (is_pretty) {
                    APPEND_STRING("\n");
                }
            }
            if (count > 0 && is_pretty) {
                APPEND_INDENT(level);
            }
            APPEND_STRING("]");
            return written_total;
        case JSONObject:
            object = json_value_get_object(value);
            count = json_object_get_count(object);
            APPEND_STRING("{");
            if (count > 0 && is_pretty) {
                APPEND_STRING("\n");
            }
            for (i = 0; i < count; i++) {
                key = json_object_get_name(object, i);
                if (key == NULL) {
                    return -1;
                }
                if (is_pretty) {
                    APPEND_INDENT(level + 1);
                }
                written = json_serialize_string(key, buf, buf_size_in_bytes);
                if (written < 0) {
                    return -1;
                }
                if (buf != NULL) {
                    buf += written;
                }
                written_total += written;
                APPEND_STRING(":");
                if (is_pretty) {
                    APPEND_STRING(" ");
                }
                temp_value = json_object_get_value(object, key);
                written = json_serialize_to_buffer_r(temp_value, buf, level + 1, is_pretty, num_buf, buf_size_in_bytes);
                if (written < 0) {
                    return -1;
                }
                if (buf != NULL) {
                    buf += written;
                }
                written_total += written;
                if (i < (count - 1)) {
                    APPEND_STRING(",");
                }
                if (is_pretty) {
                    APPEND_STRING("\n");
                }
            }
            if (count > 0 && is_pretty) {
                APPEND_INDENT(level);
            }
            APPEND_STRING("}");
            return written_total;
        case JSONString:
            string = json_value_get_string(value);
            if (string == NULL) {
                return -1;
            }
            written = json_serialize_string(string, buf, buf_size_in_bytes);
            if (written < 0) {
                return -1;
            }
            if (buf != NULL) {
                buf += written;
            }
            written_total += written;
            return written_total;
        case JSONBoolean:
            if (json_value_get_boolean(value)) {
                APPEND_STRING("true");
            } else {
                APPEND_STRING("false");
            }
            return written_total;
        case JSONNumber:
            num = json_value_get_number(value);
            if (buf != NULL) {
                num_buf = buf;
            }
            written = sprintf(num_buf, FLOAT_FORMAT, num);
            if (written < 0) {
                return -1;
            }
            if (buf != NULL) {
                buf += written;
            }
            written_total += written;
            return written_total;
        case JSONNull:
            APPEND_STRING("null");
            return written_total;
        case JSONError:
            return -1;
        default:
            return -1;
    }
}

static int json_serialize_string(const char *string, char *buf, size_t buf_size_in_bytes) {
    size_t i = 0, len = XSTRLEN(string);
    char c = '\0';
    int written = -1, written_total = 0;
    APPEND_STRING("\"");
    for (i = 0; i < len; i++) {
        c = string[i];
        switch (c) {
            case '\"':
                APPEND_STRING("\\\"");
                break;
            case '\\':
                APPEND_STRING("\\\\");
                break;
            case '/':
                APPEND_STRING("\\/");
                break; /* to make json embeddable in xml\/html */
            case '\b':
                APPEND_STRING("\\b");
                break;
            case '\f':
                APPEND_STRING("\\f");
                break;
            case '\n':
                APPEND_STRING("\\n");
                break;
            case '\r':
                APPEND_STRING("\\r");
                break;
            case '\t':
                APPEND_STRING("\\t");
                break;
            case '\x00':
                APPEND_STRING("\\u0000");
                break;
            case '\x01':
                APPEND_STRING("\\u0001");
                break;
            case '\x02':
                APPEND_STRING("\\u0002");
                break;
            case '\x03':
                APPEND_STRING("\\u0003");
                break;
            case '\x04':
                APPEND_STRING("\\u0004");
                break;
            case '\x05':
                APPEND_STRING("\\u0005");
                break;
            case '\x06':
                APPEND_STRING("\\u0006");
                break;
            case '\x07':
                APPEND_STRING("\\u0007");
                break;
                /* '\x08' duplicate: '\b' */
                /* '\x09' duplicate: '\t' */
                /* '\x0a' duplicate: '\n' */
            case '\x0b':
                APPEND_STRING("\\u000b");
                break;
                /* '\x0c' duplicate: '\f' */
                /* '\x0d' duplicate: '\r' */
            case '\x0e':
                APPEND_STRING("\\u000e");
                break;
            case '\x0f':
                APPEND_STRING("\\u000f");
                break;
            case '\x10':
                APPEND_STRING("\\u0010");
                break;
            case '\x11':
                APPEND_STRING("\\u0011");
                break;
            case '\x12':
                APPEND_STRING("\\u0012");
                break;
            case '\x13':
                APPEND_STRING("\\u0013");
                break;
            case '\x14':
                APPEND_STRING("\\u0014");
                break;
            case '\x15':
                APPEND_STRING("\\u0015");
                break;
            case '\x16':
                APPEND_STRING("\\u0016");
                break;
            case '\x17':
                APPEND_STRING("\\u0017");
                break;
            case '\x18':
                APPEND_STRING("\\u0018");
                break;
            case '\x19':
                APPEND_STRING("\\u0019");
                break;
            case '\x1a':
                APPEND_STRING("\\u001a");
                break;
            case '\x1b':
                APPEND_STRING("\\u001b");
                break;
            case '\x1c':
                APPEND_STRING("\\u001c");
                break;
            case '\x1d':
                APPEND_STRING("\\u001d");
                break;
            case '\x1e':
                APPEND_STRING("\\u001e");
                break;
            case '\x1f':
                APPEND_STRING("\\u001f");
                break;
            default:
                if (buf != NULL) {
                    buf[0] = c;
                    buf += 1;
                }
                written_total += 1;
                break;
        }
    }
    APPEND_STRING("\"");
    return written_total;
}

static int append_indent(char *buf, int level, size_t buf_size_in_bytes) {
    int i;
    int written = -1, written_total = 0;
    for (i = 0; i < level; i++) {
        APPEND_STRING("    ");
    }
    return written_total;
}

static int append_string(char *buf, const char *string, size_t buf_size_in_bytes) {
    if (buf == NULL) {
        return (int) XSTRLEN(string);
    }
    return snprintf(buf, buf_size_in_bytes, "%s", string);
}

#undef APPEND_STRING
#undef APPEND_INDENT


JSON_Value *json_parse_string(const char *string) {
    if (!string) {
        return NULL;
    }
    if (string[0] == '\xEF' && string[1] == '\xBB' && string[2] == '\xBF') {
        string += 3;
    }
    return parse_value((const char **) &string, 0);
}

JSON_Value *json_parse_string_with_comments(const char *string) {
    JSON_Value *result = NULL;
    char *string_mutable_copy = NULL, *string_mutable_copy_ptr = NULL;
    string_mutable_copy = parson_strdup(string);
    if (string_mutable_copy == NULL) {
        return NULL;
    }
    remove_comments(string_mutable_copy, "/*", "*/");
    remove_comments(string_mutable_copy, "//", "\n");
    string_mutable_copy_ptr = string_mutable_copy;
    result = parse_value((const char **) &string_mutable_copy_ptr, 0);
    parson_free(string_mutable_copy);
    return result;
}

/* JSON Object API */

JSON_Value *json_object_get_value(const JSON_Object *object, const char *name) {
    if (object == NULL || name == NULL) {
        return NULL;
    }
    return json_object_nget_value(object, name, XSTRLEN(name));
}

const char *json_object_get_string(const JSON_Object *object, const char *name) {
    return json_value_get_string(json_object_get_value(object, name));
}

double json_object_get_number(const JSON_Object *object, const char *name) {
    return json_value_get_number(json_object_get_value(object, name));
}

JSON_Object *json_object_get_object(const JSON_Object *object, const char *name) {
    return json_value_get_object(json_object_get_value(object, name));
}

JSON_Array *json_object_get_array(const JSON_Object *object, const char *name) {
    return json_value_get_array(json_object_get_value(object, name));
}

int json_object_get_boolean(const JSON_Object *object, const char *name) {
    return json_value_get_boolean(json_object_get_value(object, name));
}

JSON_Value *json_object_dotget_value(const JSON_Object *object, const char *name) {
    const char *dot_position = XSTRCHR(name, '.');
    if (!dot_position) {
        return json_object_get_value(object, name);
    }
    object = json_value_get_object(json_object_nget_value(object, name, dot_position - name));
    return json_object_dotget_value(object, dot_position + 1);
}

size_t json_object_get_count(const JSON_Object *object) {
    return object ? object->count : 0;
}

const char *json_object_get_name(const JSON_Object *object, size_t index) {
    if (object == NULL || index >= json_object_get_count(object)) {
        return NULL;
    }
    return object->names[index];
}

JSON_Value *json_object_get_value_at(const JSON_Object *object, size_t index) {
    if (object == NULL || index >= json_object_get_count(object)) {
        return NULL;
    }
    return object->values[index];
}

JSON_Value *json_object_get_wrapping_value(const JSON_Object *object) {
    return object->wrapping_value;
}

/* JSON Array API */
JSON_Value *json_array_get_value(const JSON_Array *array, size_t index) {
    if (array == NULL || index >= json_array_get_count(array)) {
        return NULL;
    }
    return array->items[index];
}

JSON_Object *json_array_get_object(const JSON_Array *array, size_t index) {
    return json_value_get_object(json_array_get_value(array, index));
}

size_t json_array_get_count(const JSON_Array *array) {
    return array ? array->count : 0;
}

JSON_Value *json_array_get_wrapping_value(const JSON_Array *array) {
    return array->wrapping_value;
}

/* JSON Value API */
JSON_Value_Type json_value_get_type(const JSON_Value *value) {
    return value ? value->type : JSONError;
}

JSON_Object *json_value_get_object(const JSON_Value *value) {
    return json_value_get_type(value) == JSONObject ? value->value.object : NULL;
}

JSON_Array *json_value_get_array(const JSON_Value *value) {
    return json_value_get_type(value) == JSONArray ? value->value.array : NULL;
}

const char *json_value_get_string(const JSON_Value *value) {
    return json_value_get_type(value) == JSONString ? value->value.string : NULL;
}

double json_value_get_number(const JSON_Value *value) {
    return json_value_get_type(value) == JSONNumber ? value->value.number : 0;
}

int json_value_get_boolean(const JSON_Value *value) {
    return json_value_get_type(value) == JSONBoolean ? value->value.boolean : -1;
}


void json_value_free(JSON_Value *value) {
    switch (json_value_get_type(value)) {
        case JSONObject:
            json_object_free(value->value.object);
            break;
        case JSONString:
            parson_free(value->value.string);
            break;
        case JSONArray:
            json_array_free(value->value.array);
            break;
        default:
            break;
    }
    parson_free(value);
}

JSON_Value *json_value_init_object(void) {
    JSON_Value *new_value = (JSON_Value *) parson_malloc(sizeof(JSON_Value));
    if (!new_value) {
        return NULL;
    }
    new_value->parent = NULL;
    new_value->type = JSONObject;
    new_value->value.object = json_object_init(new_value);
    if (!new_value->value.object) {
        parson_free(new_value);
        return NULL;
    }
    return new_value;
}

JSON_Value *json_value_init_array(void) {
    JSON_Value *new_value = (JSON_Value *) parson_malloc(sizeof(JSON_Value));
    if (!new_value) {
        return NULL;
    }
    new_value->parent = NULL;
    new_value->type = JSONArray;
    new_value->value.array = json_array_init(new_value);
    if (!new_value->value.array) {
        parson_free(new_value);
        return NULL;
    }
    return new_value;
}

JSON_Value *json_value_init_string(const char *string) {
    char *copy = NULL;
    JSON_Value *value;
    size_t string_len = 0;
    if (string == NULL) {
        return NULL;
    }
    string_len = XSTRLEN(string);
    if (!is_valid_utf8(string, string_len)) {
        return NULL;
    }
    copy = parson_strndup(string, string_len);
    if (copy == NULL) {
        return NULL;
    }
    value = json_value_init_string_no_copy(copy);
    if (value == NULL) {
        parson_free(copy);
    }
    return value;
}

JSON_Value *json_value_init_number(double number) {
    JSON_Value *new_value = NULL;
    if ((number * 0.0) != 0.0) { /* nan and inf test */
        return NULL;
    }
    new_value = (JSON_Value *) parson_malloc(sizeof(JSON_Value));
    if (new_value == NULL) {
        return NULL;
    }
    new_value->parent = NULL;
    new_value->type = JSONNumber;
    new_value->value.number = number;
    return new_value;
}

JSON_Value *json_value_init_boolean(int boolean) {
    JSON_Value *new_value = (JSON_Value *) parson_malloc(sizeof(JSON_Value));
    if (!new_value) {
        return NULL;
    }
    new_value->parent = NULL;
    new_value->type = JSONBoolean;
    new_value->value.boolean = boolean ? 1 : 0;
    return new_value;
}

JSON_Value *json_value_init_null(void) {
    JSON_Value *new_value = (JSON_Value *) parson_malloc(sizeof(JSON_Value));
    if (!new_value) {
        return NULL;
    }
    new_value->parent = NULL;
    new_value->type = JSONNull;
    return new_value;
}

size_t json_serialization_size(const JSON_Value *value) {
    char num_buf[1100]; /* recursively allocating buffer on stack is a bad idea, so let's do it only once */
    int res = json_serialize_to_buffer_r(value, NULL, 0, 0, num_buf, 0);
    return res < 0 ? 0 : (size_t) (res + 1);
}

JSON_Status json_serialize_to_buffer(const JSON_Value *value, char *buf, size_t buf_size_in_bytes) {
    int written;
    size_t needed_size_in_bytes = json_serialization_size(value);
    if (needed_size_in_bytes == 0 || buf_size_in_bytes < needed_size_in_bytes) {
        return JSONFailure;
    }

    if ((value == NULL) || (buf == NULL)) {
        return JSONFailure;
    }

    written = json_serialize_to_buffer_r(value, buf, 0, 0, NULL, buf_size_in_bytes);
    if (written < 0) {
        return JSONFailure;
    }
    return JSONSuccess;
}

char *json_serialize_to_string(const JSON_Value *value) {
    JSON_Status serialization_result;
    size_t buf_size_bytes = json_serialization_size(value);
    char *buf = NULL;
    if (buf_size_bytes == 0) {
        return NULL;
    }
    buf = (char *) parson_malloc(buf_size_bytes);
    if (buf == NULL) {
        return NULL;
    }
    serialization_result = json_serialize_to_buffer(value, buf, buf_size_bytes);
    if (serialization_result == JSONFailure) {
        json_free_serialized_string(buf);
        return NULL;
    }
    return buf;
}

size_t json_serialization_size_pretty(const JSON_Value *value) {
    char num_buf[1100]; /* recursively allocating buffer on stack is a bad idea, so let's do it only once */
    int res = json_serialize_to_buffer_r(value, NULL, 0, 1, num_buf, 0);
    return res < 0 ? 0 : (size_t) (res + 1);
}

JSON_Status json_serialize_to_buffer_pretty(const JSON_Value *value, char *buf, size_t buf_size_in_bytes) {
    int written;
    size_t needed_size_in_bytes = json_serialization_size_pretty(value);
    if (needed_size_in_bytes == 0 || buf_size_in_bytes < needed_size_in_bytes) {
        return JSONFailure;
    }

    if ((value == NULL) || (buf == NULL)) {
        return JSONFailure;
    }

    written = json_serialize_to_buffer_r(value, buf, 0, 1, NULL, buf_size_in_bytes);
    if (written < 0) {
        return JSONFailure;
    }
    return JSONSuccess;
}

char *json_serialize_to_string_pretty(const JSON_Value *value) {
    JSON_Status serialization_result;
    size_t buf_size_bytes = json_serialization_size_pretty(value);
    char *buf = NULL;
    if (buf_size_bytes == 0) {
        return NULL;
    }
    buf = (char *) parson_malloc(buf_size_bytes);
    if (buf == NULL) {
        return NULL;
    }
    serialization_result = json_serialize_to_buffer_pretty(value, buf, buf_size_bytes);
    if (serialization_result == JSONFailure) {
        json_free_serialized_string(buf);
        return NULL;
    }
    return buf;
}

void json_free_serialized_string(char *string) {
    parson_free(string);
}

JSON_Status json_array_append_value(JSON_Array *array, JSON_Value *value) {
    if (array == NULL || value == NULL || value->parent != NULL) {
        return JSONFailure;
    }
    return json_array_add(array, value);
}


JSON_Status json_object_set_value(JSON_Object *object, const char *name, JSON_Value *value) {
    size_t i = 0;
    JSON_Value *old_value;
    if (object == NULL || name == NULL || value == NULL || value->parent != NULL) {
        return JSONFailure;
    }
    old_value = json_object_get_value(object, name);
    if (old_value != NULL) { /* free and overwrite old value */
        json_value_free(old_value);
        for (i = 0; i < json_object_get_count(object); i++) {
            if (strcmp(object->names[i], name) == 0) {
                value->parent = json_object_get_wrapping_value(object);
                object->values[i] = value;
                return JSONSuccess;
            }
        }
    }
    /* add new key value pair */
    return json_object_add(object, name, value);
}

JSON_Status json_object_set_string(JSON_Object *object, const char *name, const char *string) {
    return json_object_set_value(object, name, json_value_init_string(string));
}

JSON_Status json_object_set_number(JSON_Object *object, const char *name, double number) {
    return json_object_set_value(object, name, json_value_init_number(number));
}

JSON_Status json_object_dotset_value(JSON_Object *object, const char *name, JSON_Value *value) {
    const char *dot_pos = NULL;
    char *current_name = NULL;
    JSON_Object *temp_obj = NULL;
    JSON_Value *new_value = NULL;
    if (object == NULL || name == NULL || value == NULL) {
        return JSONFailure;
    }
    dot_pos = XSTRCHR(name, '.');
    if (dot_pos == NULL) {
        return json_object_set_value(object, name, value);
    } else {
        current_name = parson_strndup(name, dot_pos - name);
        temp_obj = json_object_get_object(object, current_name);
        if (temp_obj == NULL) {
            new_value = json_value_init_object();
            if (new_value == NULL) {
                parson_free(current_name);
                return JSONFailure;
            }
            if (json_object_add(object, current_name, new_value) == JSONFailure) {
                json_value_free(new_value);
                parson_free(current_name);
                return JSONFailure;
            }
            temp_obj = json_object_get_object(object, current_name);
        }
        parson_free(current_name);
        return json_object_dotset_value(temp_obj, dot_pos + 1, value);
    }
}


JSON_Object *json_object(const JSON_Value *value) {
    return json_value_get_object(value);
}
