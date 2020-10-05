\page docs/Doxygen/logging.md Logging
[Back to Manual](docs/Doxygen/libcertifier.md) 

Logging
=======

libLedger() supports logging diagnostic information to a file.

If using libcertifier.cfg (or equivalent), the following properties
could control logging -

       "libcertifier.log.level":0,
       "libcertifier.log.file":"/tmp/libcertifier.log",
       "libcertifier.log.max.size":5000000,

The configuration above specifies that verbose and above logging is
enabled. Append mode would be enabled and all diagnostic messages would
be written to /tmp/libcertifier.log.

> **Note**
>
> In the above example, 5 MB is the total max log size before
> /tmp/libcertifier.log gets renamed to /tmp/libcertifier.log.old

It you wanted to see HTTPS trace, do the following -

       "libcertifier.http.trace":1
