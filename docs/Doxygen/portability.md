\page docs/Doxygen/portability.md Portability
[Back to Manual](docs/Doxygen/libcertifier.md) 

libcertifier could "potentially" be built without the C standard library
to provide a higher level of portability and flexibility to
implementors. To do this, the functions would have to be overridden
instead of the standard "C" ones.

See `internal_headers/certifier/types.h` for more details.

&lt;string.h&gt;
================

libcertifier uses several functions that behave like `<string.h>`
`memcpy()`, `memset()`, and `memcmp()` amongst others. They are
abstracted to `XMEMCPY()`, `XMEMSET()`, and `XMEMCMP()` respectively.
And by default, they point to the C standard library versions. Defining
`STRING_USER` allows the user to provide their own hooks in types.h. For
example, by default `XMEMCPY()` is:

    #define XMEMCPY(d,s,l)    memcpy((d),(s),(l))

After defining IMPLEMENTOR\_STRING you could do:

    define XMEMCPY(d,s,l)    my_memcpy((d),(s),(l))

Or if you prefer to avoid macros:

    external void* my_memcpy(void* d, const void* s, size_t n);

to set libcertifier’s abstraction layer to point to your version
my\_memcpy().

Memory Use
==========

Most C programs utilize `malloc()` and `free()` for dynamic memory
allocation. libcertifier utilizes `XMALLOC()` and `XFREE()` instead.

After defining IMPLEMENTOR\_MEMORY you could point to to your own
versions.
