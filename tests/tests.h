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

#ifndef LIBLEDGER_TESTS_H
#define LIBLEDGER_TESTS_H

#include <setjmp.h>

#ifdef CMOCKA_ENABLED

#include <cmocka.h>

#endif

#include "certifier/log.h"

#define CREATE_TEST(test) cmocka_unit_test_setup_teardown(test, setUp, tearDown)
#define ASSERT_TRUE_MESSAGE(expr, msg_on_fail...)                              \
if (!(expr))                                                                   \
    fail_msg(msg_on_fail)                                                      \

#ifndef CMOCKA_ENABLED
#define assert_int_equal TEST_ASSERT_EQUAL_INT
#define assert_non_null TEST_ASSERT_NOT_NULL
#define assert_string_equal TEST_ASSERT_EQUAL_STRING
#define assert_null TEST_ASSERT_NULL
#define assert_int_not_equal(arg1, arg2)  TEST_ASSERT(arg1 != arg2)
#define fail_msg printf 
#define assert_true TEST_ASSERT_TRUE
#define assert_false TEST_ASSERT_FALSE
#define assert_memory_equal TEST_ASSERT_EQUAL_MEMORY
#define assert_ptr_equal TEST_ASSERT_EQUAL_PTR
#define assert_in_range TEST_ASSERT_INT_WITHIN
#endif

inline void delete_file(const char *path) {
    int rc = util_delete_file(path);
    if (rc != 0) {
        log_warn("delete_file %s failed: [%d]", path, rc);
    }
}

/* Test drivers */

int run_easy_api_tests(void);

#endif //LIBLEDGER_TESTS_H
