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

#ifndef LIBLEDGER_PROPERTY_INTERNAL_H
#define LIBLEDGER_PROPERTY_INTERNAL_H

#include "certifier/property.h"
#include "certifier/types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CERTIFIER_ERR_PROPERTY_SET_1 1
#define CERTIFIER_ERR_PROPERTY_SET_2 2
#define CERTIFIER_ERR_PROPERTY_SET_3 3
#define CERTIFIER_ERR_PROPERTY_SET_4 4
#define CERTIFIER_ERR_PROPERTY_SET_5 5
#define CERTIFIER_ERR_PROPERTY_SET_6 6
#define CERTIFIER_ERR_PROPERTY_SET_7 7
#define CERTIFIER_ERR_PROPERTY_SET_8 8
#define CERTIFIER_ERR_PROPERTY_SET_9 9
#define CERTIFIER_ERR_PROPERTY_SET_10 10
#define CERTIFIER_ERR_PROPERTY_SET_11 11

#define CERTIFIER_ERR_PROPERTY_GET_1 "CERTIFIER_ERR_PROPERTY_GET_1"
#define CERTIFIER_ERR_PROPERTY_GET_2 "CERTIFIER_ERR_PROPERTY_GET_2"

typedef struct _PropMap CertifierPropMap;

/**
 * Create a new properties container with defaults set.
 * @return
 */
CertifierPropMap * property_new(void);

CertifierPropMap * property_new_sectigo(void);

CertifierPropMap * property_ext(void);

int property_destroy(CertifierPropMap * prop_map);

/**
 * Set a boolean option
 * @param prop_map
 * @param enable
 * @return 0 on success
 */
int property_set_option(CertifierPropMap * prop_map, CERTIFIER_OPT_OPTION option, bool enable);

/**
 * Convenience function to read a boolean option.
 * This is the equivalent to (ledger_property_get(prop_map, CERTIFIER_OPT_OPTIONS) & &lt;CERTIFIER_OPT_OPTION&gt;) != 0
 * @param map
 * @param option
 * @return
 */
bool property_is_option_set(CertifierPropMap * map, CERTIFIER_OPT_OPTION option);

int property_set_defaults(CertifierPropMap * prop_map);

int property_set_ext(CertifierPropMap * prop_map);

int property_set(CertifierPropMap * prop_map, CERTIFIER_OPT name, const void * value);

int sectigo_property_set(CertifierPropMap * prop_map, int name, const void * value);

int property_set_int(CertifierPropMap * prop_map, CERTIFIER_OPT name, int value);

void * property_get(CertifierPropMap * prop_map, CERTIFIER_OPT name);

int property_set_defaults_from_cfg_file(CertifierPropMap * propMap);

int property_set_sectigo_defaults_from_cfg_file(CertifierPropMap * propMap);

const char * get_default_cfg_filename();

const char * get_default_ca_path();

const char * get_default_ca_info();

/**
 * Validate if a key type string is a supported Sectigo key type.
 * @param key_type The key type string to validate
 * @return 1 if valid, 0 otherwise
 */
int is_valid_sectigo_key_type(const char * key_type);

#ifdef __cplusplus
}
#endif

#endif // LIBLEDGER_PROPERTY_INTERNAL_H
