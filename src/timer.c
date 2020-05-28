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

#include "certifier/timer.h"
#include "certifier/types.h"

double timer_these_secs = 0.0;
double timer_start_secs = 0.0;
double timer_secs;
double timer_cpu_secs = 0.0;
double timer_cpu_utilization = 0.0;
double timer_answer = 0;

clock_t timer_starts;

struct timespec tp1;

void timer_start_CPU_time(void) {
    timer_starts = clock();;
}

void timer_end_CPU_time(void) {
    timer_cpu_secs = (double) (clock() - timer_starts) / (double) CLOCKS_PER_SEC;
}

void timer_calculate_cpu_utilization(void) {
    timer_cpu_utilization = timer_cpu_secs / timer_secs * 100.0;
}

void timer_get_secs(void) {
    clock_gettime(CLOCK_REALTIME, &tp1);
    timer_these_secs = tp1.tv_sec + tp1.tv_nsec / 1e9;
}

void timer_start_time(void) {
    timer_get_secs();
    timer_start_secs = timer_these_secs;
}

void timer_end_time(void) {
    timer_get_secs();
    timer_secs = timer_these_secs - timer_start_secs;
}

void timer_reset(void) {
    timer_these_secs = 0.0;
    timer_start_secs = 0.0;
    timer_secs = 0;
    timer_cpu_secs = 0.0;
    timer_cpu_utilization = 0.0;
    timer_answer = 0;
    tp1.tv_nsec = 0;
    tp1.tv_sec = 0;
}

double timer_get_these_secs(void) {
    return timer_these_secs;
}

double timer_get_start_secs(void) {
    return timer_start_secs;
}

double timer_get_secs_value(void) {
    return timer_secs;
}

double timer_get_cpu_secs(void) {
    return timer_cpu_secs;
}

double timer_get_cpu_utilization(void) {
    return timer_cpu_utilization;
}

double timer_get_answer(void) {
    return timer_answer;
}

