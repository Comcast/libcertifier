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

#ifndef C_CLIENT_TIMER_H
#define C_CLIENT_TIMER_H

#include "certifier/types.h"

#ifdef __cplusplus
extern "C" {
#endif

void timer_start_CPU_time(void);

void timer_end_CPU_time(void);

void timer_calculate_cpu_utilization(void);

void timer_get_secs(void);

void timer_start_time(void);

void timer_end_time(void);

void timer_reset(void);

double timer_get_these_secs(void);

double timer_get_start_secs(void);

double timer_get_secs_value(void);

double timer_get_cpu_secs(void);

double timer_get_cpu_utilization(void);

double timer_get_answer(void);

#ifdef __cplusplus
}
#endif

#endif //C_CLIENT_TIMER_H
