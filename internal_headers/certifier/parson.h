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

#ifndef parson_parson_h
#define parson_parson_h

#ifdef __cplusplus
extern "C"
{
#endif

#include "certifier/types.h"

/* Types and enums */
typedef struct json_object_t JSON_Object;
typedef struct json_array_t JSON_Array;
typedef struct json_value_t JSON_Value;

enum json_value_type {
    JSONError = -1,
    JSONNull = 1,
    JSONString = 2,
    JSONNumber = 3,
    JSONObject = 4,
    JSONArray = 5,
    JSONBoolean = 6
};
typedef int JSON_Value_Type;

enum json_result_t {
    JSONSuccess = 0,
    JSONFailure = -1
};
typedef int JSON_Status;

typedef void *(*JSON_Malloc_Function)(size_t);

typedef void   (*JSON_Free_Function)(void *);

/*  Parses first JSON value in a string, returns NULL in case of error */
JSON_Value *json_parse_string(const char *string);

/*  Parses first JSON value in a string and ignores comments (/ * * / and //),
    returns NULL in case of error */
JSON_Value *json_parse_string_with_comments(const char *string);

/* Serialization */
size_t json_serialization_size(const JSON_Value *value); /* returns 0 on fail */
JSON_Status json_serialize_to_buffer(const JSON_Value *value, char *buf, size_t buf_size_in_bytes);

JSON_Status json_serialize_to_file(const JSON_Value *value, const char *filename);

char *json_serialize_to_string(const JSON_Value *value);

/* Pretty serialization */
size_t json_serialization_size_pretty(const JSON_Value *value); /* returns 0 on fail */
JSON_Status json_serialize_to_buffer_pretty(const JSON_Value *value, char *buf, size_t buf_size_in_bytes);

JSON_Status json_serialize_to_file_pretty(const JSON_Value *value, const char *filename);

char *json_serialize_to_string_pretty(const JSON_Value *value);

void json_free_serialized_string(
        char *string); /* frees string from json_serialize_to_string and json_serialize_to_string_pretty */

/*
 * JSON Object
 */
JSON_Value *json_object_get_value(const JSON_Object *object, const char *name);

const char *json_object_get_string(const JSON_Object *object, const char *name);

JSON_Object *json_object_get_object(const JSON_Object *object, const char *name);

JSON_Array *json_object_get_array(const JSON_Object *object, const char *name);

double json_object_get_number(const JSON_Object *object, const char *name); /* returns 0 on fail */
int json_object_get_boolean(const JSON_Object *object, const char *name); /* returns -1 on fail */

/* dotget functions enable addressing values with dot notation in nested objects,
 just like in structs or c++/java/c# objects (e.g. objectA.objectB.value).
 Because valid names in JSON can contain dots, some values may be inaccessible
 this way. */
JSON_Value *json_object_dotget_value(const JSON_Object *object, const char *name);

/* Functions to get available names */
size_t json_object_get_count(const JSON_Object *object);

const char *json_object_get_name(const JSON_Object *object, size_t index);

JSON_Value *json_object_get_wrapping_value(const JSON_Object *object);

/* Creates new name-value pair or frees and replaces old value with a new one.
 * json_object_set_value does not copy passed value so it shouldn't be freed afterwards. */
JSON_Status json_object_set_value(JSON_Object *object, const char *name, JSON_Value *value);

JSON_Status json_object_set_string(JSON_Object *object, const char *name, const char *string);

JSON_Status json_object_set_number(JSON_Object *object, const char *name, double number);

/* Works like dotget functions, but creates whole hierarchy if necessary.
 * json_object_dotset_value does not copy passed value so it shouldn't be freed afterwards. */
JSON_Status json_object_dotset_value(JSON_Object *object, const char *name, JSON_Value *value);

/*
 *JSON Array
 */
JSON_Value *json_array_get_value(const JSON_Array *array, size_t index);

JSON_Object *json_array_get_object(const JSON_Array *array, size_t index);

size_t json_array_get_count(const JSON_Array *array);

JSON_Value *json_array_get_wrapping_value(const JSON_Array *array);

/* Appends new value at the end of array.
 * json_array_append_value does not copy passed value so it shouldn't be freed afterwards. */
JSON_Status json_array_append_value(JSON_Array *array, JSON_Value *value);

/*
 *JSON Value
 */
JSON_Value *json_value_init_object(void);

JSON_Value *json_value_init_array(void);

JSON_Value *json_value_init_string(const char *string); /* copies passed string */
JSON_Value *json_value_init_number(double number);

JSON_Value *json_value_init_boolean(int boolean);

JSON_Value *json_value_init_null(void);

void json_value_free(JSON_Value *value);

JSON_Value_Type json_value_get_type(const JSON_Value *value);

JSON_Object *json_value_get_object(const JSON_Value *value);

JSON_Array *json_value_get_array(const JSON_Value *value);

const char *json_value_get_string(const JSON_Value *value);

double json_value_get_number(const JSON_Value *value);

int json_value_get_boolean(const JSON_Value *value);

JSON_Object *json_object(const JSON_Value *value);

#ifdef __cplusplus
}
#endif

#endif
