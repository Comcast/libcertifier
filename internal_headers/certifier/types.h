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

#ifndef LIBCERTIFIER_TYPES_H
#define LIBCERTIFIER_TYPES_H

#ifdef __cplusplus
extern "C" {
#endif

#ifndef IMPLEMENTOR_STRING
#include <string.h>
#define XSTRERROR strerror
#define XSTRDUP(s1) strdup((s1))
#define XMEMCPY(d, s, l) memcpy((d), (s), (l))
#define XMEMSET(b, c, l) memset((b), (c), (l))
#define XMEMCMP(s1, s2, n) memcmp((s1), (s2), (n))
#define XMEMMOVE(d, s, l) memmove((d), (s), (l))

#define XSTRLEN(s1) strlen((s1))
#define XSTRNCPY(s1, s2, n) strncpy((s1), (s2), (n))
#define XSTRCPY(s1, s2) strcpy((s1), (s2))
#define XSTRCHR(s1, s2) strchr((s1), (s2))
#define XSTRSTR(s1, s2) strstr((s1), (s2))
#define XSTRCMP(d, s) strcmp((d), (s))
#define XSTRNCMP(s1, s2, n) strncmp((s1), (s2), (n))
#define XSTRNCAT(s1, s2, n) strncat((s1), (s2), (n))
#endif
/* */

#ifndef IMPLEMENTOR_STDIO
#include <stdio.h>
#define XPUTS puts
#define XSNPRINTF snprintf
#endif

#ifndef IMPLEMENTOR_STDLIB
#include <stdlib.h>
#define XEXIT exit
#endif

#ifndef IMPLEMENTOR_MEMORY
#include <stdlib.h>
#define XCALLOC calloc
#define XMALLOC(s) malloc((s))

#define XFREE(p) free((p))
#define XREALLOC(p, n) realloc((p), (n))
#endif

#ifndef IMPLEMENTOR_STDLIB
#define XATOI(s) atoi((s))
#endif

#ifndef IMPLEMENTOR_CTYPE
#include <ctype.h>
#define XISSPACE(c) isspace((c))
#define XTOUPPER(c) toupper((c))
#define XISALPHA(c) isalpha((c))
#endif

#ifndef IMPLEMENTOR_FS
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>
#define XFILE FILE *
#define XFILENO fileno
#define XOPEN open
#define XCLOSE close
#define XREAD read
#define XREMOVE remove
#define XRENAME rename
#define XSTAT stat
#define XFDOPEN fdopen
#define XFOPEN fopen
#define XFSEEK fseek
#define XFTELL ftell
#define XREWIND rewind
#define XFREAD fread
#define XFWRITE fwrite
#define XFFLUSH fflush
#define XFSYNC fsync
#define XFSTAT fstat
#define XFCLOSE fclose
#define XSEEK_END SEEK_END
#define XERRNO errno
#define XBADFILE NULL
#define XFGETS fgets

#define XENOMEM ENOMEM
#define XEINTR EINTR

#define XO_RDONLY O_RDONLY
#define XO_CREAT O_CREAT
#define XO_APPEND O_APPEND
#define XO_WRONLY O_WRONLY
#define XS_IRUSR S_IRUSR
#define XS_IWUSR S_IWUSR
#define XS_IRGRP S_IRGRP
#define XS_IWGRP S_IWGRP
#define XS_IROTH S_IROTH
#define XS_IWOTH S_IWOTH

#endif

#ifndef IMPLEMENTOR_IO

// workaround
int vasprintf(char ** ret, const char * format, va_list ap);

#include <stdio.h>
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#define XFPRINTF(f, format, args...) fprintf(f, format, ##args)
#define XVFPRINTF(f, format, args...) vfprintf(f, format, ##args)
#define XVASPRINTF(f, format, args...) vasprintf(f, format, ##args)
#endif

#ifndef IMPLEMENTOR_STDARG
#include <stdarg.h>
#define XVA_START va_start
#define XVA_END va_end
#define XVA_LIST va_list
#endif

#ifndef IMPLEMENTOR_RESOURCE
#include <sys/resource.h>
typedef struct rusage XRUSAGE;
#define XGETRUSAGE getrusage
#endif

#ifndef IMPLEMENTOR_LIMITS
#include <limits.h>
#define XINT_MAX INT_MAX
#endif

#ifndef IMPLEMENTOR_ASSERT
#include <assert.h>
#define XASSERT assert
#endif

#ifndef IMPLEMENTOR_OPT
#include <getopt.h>
#include <unistd.h>
#define XGETOPT_LONG getopt_long
#define XOPTIND optind
#endif

#ifndef IMPLEMENTOR_TYPES
#include <inttypes.h>
#include <setjmp.h> // this is used by tests.c with CMOCKA enabled
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>

#endif

#ifdef USE_MBEDTLS

#include <mbedtls/pk.h>

typedef mbedtls_pk_context ECC_KEY;
typedef struct mbedtls_x509_crt X509_CERT;
typedef struct mbedtls_x509_crt X509_LIST;
#else
typedef struct ec_key_st ECC_KEY;
typedef struct x509_st X509_CERT;
typedef struct stack_st_X509 X509_LIST;
#endif

#ifdef __cplusplus
}
#endif

#endif // LIBCERTIFIER_TYPES_H
