\page docs/Doxygen/libcertifier.md libCertifier()

libCertifier()
==============

-   Written in C for embedded devices.

-   Small binary size (less than 100 KB) that is ideal for embedded
    systems.

-   Tested on Arm (Raspberry Pi, Android, xCam, [i.MX](http://i.MX),
    Ambarella, iOS), x86\_64 (Ubuntu, MacOS, x86\_32 (Ubuntu).

-   Shared library and command-line executable.

-   Generates public/private key pairs, fetches x509 certificate from
    xPKI and renews certificate.

-   See [Open Source Dependencies](docs/Doxygen/open_source_dependencies.md)

**Integration Methods**

-   [Command line executable (CLI)](docs/Doxygen/cli_usage.md)

-   [Shared Library (API](docs/Doxygen/api_usage.md))

Overview
========


libCertifier() communicates with the following back-end service. TLS is
used.

\htmlonly

<table>
<colgroup>
<col width="33%" />
<col width="33%" />
<col width="33%" />
</colgroup>
<tbody>
<tr class="odd">
<td><p><strong>Service</strong></p></td>
<td><p><strong>Description</strong></p></td>
<td><p><strong>Mandatory</strong></p></td>
</tr>
<tr class="even">
<td><p>Certifier</p></td>
<td><p>Communicates with the xPKI Certificate Authority and used to generate the x509 certificate.<br />
Also handles authentication. The <a href="docs_2Doxygen_2anatomy_of_https_certifier_call_8md.html">Anatomy of an HTTPS call to Certifier page</a>) could be used as reference to better understand the interaction between client and server.</p></td>
<td><p>Yes</p></td>
</tr>
</tbody>
</table>

\endhtmlonly

**Project structure**

The table below describes th files in this project -

\htmlonly

<table>
<colgroup>
<col width="50%" />
<col width="50%" />
</colgroup>
<tbody>
<tr class="odd">
<td><p><strong>Folder/File Name</strong></p></td>
<td><p><strong>Description</strong></p></td>
</tr>
<tr class="even">
<td><p>CMakeLists.txt</p></td>
<td><p>CMake file</p></td>
</tr>
<tr class="odd">
<td><p><a href="index.html">README.adoc</a></p></td>
<td><p>Readme file</p></td>
</tr>
<tr class="even">
<td><p>include</p></td>
<td><p><strong>public</strong> source header files</p></td>
</tr>
<tr class="odd">
<td><p>internal_headers</p></td>
<td><p><strong>private</strong> source header files</p></td>
</tr>
<tr class="even">
<td><p>libcertifier-cert.crt</p></td>
<td><p>Certificates used by libcurl for HTTPS calls</p></td>
</tr>
<tr class="odd">
<td><p><a href="docs_2Doxygen_2configuration_8md.html">libcertifier.cfg.sample</a></p></td>
<td><p>Sample libcertifier configuration file</p></td>
</tr>
<tr class="even">
<td><p>resources</p></td>
<td><p>Device Attestation Certificate</p></td>
</tr>
<tr class="odd">
<td><p>src</p></td>
<td><p>Source files</p></td>
</tr>
<tr class="even">
<td><p>tests</p></td>
<td><p>Unit tests, as well as functional tests (shell scripts)</p></td>
</tr>
</tbody>
</table>

\endhtmlonly

Build
=====

libcertifier was written with [portability](docs/Doxygen/portability.md) and has
been tested to build on OSX and Linux systems. If you have difficulty
building libcertifier, please don’t hesitate to seek support through our
support forums or contact us directly.

This [section](docs/Doxygen/build.md) explains how to build libcertifier on
Linux and OSX.

**Binary Size**

libcertifier is less than 100KB in size (stripped).

libcertifier.so is around 95KB.

certifierUtil is around 3KB.

Memory Consumption (Heap) ignoring deallocations
================================================

See [Memory Consumption](docs/Doxygen/memory_consumption_by_function.md)

Error Codes
===========

See [Error Codes](docs/Doxygen/error_codes.md)

Configuration
=============

See [libcertifier.cfg](docs/Doxygen/configuration.md)

Logging
=======

See [Logging](docs/Doxygen/logging.md)


