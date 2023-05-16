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

#include "certifier/system.h"
#include "certifier/types.h"

long int system_get_memory_used(void)
{
    XRUSAGE r_usage;
    XGETRUSAGE(RUSAGE_SELF, &r_usage);
    return r_usage.ru_maxrss;
}

// Time spent executing user instructions.
double system_user_cpu_time(void)
{
    XRUSAGE r_usage;
    XGETRUSAGE(RUSAGE_SELF, &r_usage);
    return (double) r_usage.ru_utime.tv_sec + (double) r_usage.ru_utime.tv_usec / (double) 1000000;
}

// Time spent in operating system code on behalf of processes.
double system_system_cpu_time(void)
{
    XRUSAGE r_usage;
    XGETRUSAGE(RUSAGE_SELF, &r_usage);
    return (double) r_usage.ru_stime.tv_sec + (double) r_usage.ru_stime.tv_usec / (double) 1000000;
}
