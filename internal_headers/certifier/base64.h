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

#ifndef _BASE64_H_
#define _BASE64_H_

#include "certifier/types.h"

#ifdef __cplusplus
extern "C" {
#endif

int
base64_encode_len(int len);

int
base64_encode(char *coded_dst, const unsigned char *plain_src, int len_plain_src);

int
base64_decode_len(const char *coded_src);

int
base64_decode(unsigned char *plain_dst, const char *coded_src);

#ifdef __cplusplus
}
#endif

#endif