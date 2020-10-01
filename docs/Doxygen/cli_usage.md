\page docs/Doxygen/cli_usage.md CLI usage
[Back to Manual](docs/Doxygen/libcertifier.md) 

Command Line Examples

**Create X509 CRT**

The command below assumes there is a file called `factory_lrg`, which is
the pre-existing PKCS12 with a password of `changeit` without the single
quotes.

    ./certifierUtil -m 128 -X X509 -k ./factory_lrg -p changeit

This command could also be invoked from
`./tests/functional/create_x509_crt.sh`. Example -

    cd ./tests/functional
    ./test-create-x509-crt.sh ../../factory_lrg changeit

Sample output -

    {
        "return_code": 0,
        "application_error_code": 0,
        "library_error_code": 0,
        "output": "<base64_data>"
    }

**Fetch a new certificate**

The command below , passes in the contents of the `base64_data` from the
command above (create x509 crt). This command will make an HTTPS call to
certifier and will create a brand new password-protected PKCS12 file
that contains the certificate chain returned and public/private key
pair. `libcertifier.cfg` must be present and have valid values.

    cd ./tests/functional
    ./test-device-reg.sh <base64_data>

**Fetch an X509 cert end-to-end**

The command below combines both examples above into a single script.
Python3 is required to run this script.

    cd ./tests/functional
    ././test-fetch-cert-e2e.sh ../../factory_lrg changeit

Other Examples
==============

**Get Certificate Status**

    ./certifierUtil -m 4096

**Renew Certificate**

    ./certifierUtil -m 8192

**Print Certificate (B64 of DER)**

    ./certifierUtil -m 16384

**Register an app**

    ./certifierUtil -c -f -S '<auth_token>'

**Create Node Address**

    ./certifierUtil -m 32 -O "<value>"

certifierUtil options
=====================

\htmlonly

<table>
<colgroup>
<col width="33%" />
<col width="33%" />
<col width="33%" />
</colgroup>
<tbody>
<tr class="odd">
<td><p><strong>Long Option</strong></p></td>
<td><p><strong>Short Option</strong></p></td>
<td><p><strong>Examples</strong></p></td>
</tr>
<tr class="even">
<td><p>help</p></td>
<td><p>h</p></td>
<td><p>-help* h</p></td>
</tr>
<tr class="odd">
<td><p>version</p></td>
<td><p>V</p></td>
<td><p>-version -V</p></td>
</tr>
<tr class="even">
<td><p>overwrite-p12-file</p></td>
<td><p>f</p></td>
<td><p>-overwrite-p12-file -f</p></td>
</tr>
<tr class="odd">
<td><p>client</p></td>
<td><p>c</p></td>
<td><p>-client -c</p></td>
</tr>
<tr class="even">
<td><p>pkcs12-password</p></td>
<td><p>p</p></td>
<td><p>-pkcs12-password [value]<br />
-p [value]<br />
(Defaults to <em>changeit</em> if not supplied)</p></td>
</tr>
<tr class="odd">
<td><p>config</p></td>
<td><p>L</p></td>
<td><p>-config [value]<br />
-L [value]<br />
(Defaults to <em>libcertifier.cfg</em> if not supplied)</p></td>
</tr>
<tr class="even">
<td><p>mode</p></td>
<td><p>m</p></td>
<td><p>-mode [integer value]<br />
-m [integer value]</p></td>
</tr>
<tr class="odd">
<td><p>crt</p></td>
<td><p>T</p></td>
<td><p>-crt &lt;crt&gt;</p></td>
</tr>
<tr class="even">
<td><p>crt-type</p></td>
<td><p>X</p></td>
<td><p>-crt-type &lt;crt-type&gt;</p></td>
</tr>
<tr class="odd">
<td><p>system-id</p></td>
<td><p>M</p></td>
<td><p>-system-id [id]<br />
<br />
* M [id]</p></td>
</tr>
<tr class="even">
<td><p>auth-token</p></td>
<td><p>S</p></td>
<td><p>-auth-token [value]<br />
<br />
-S [value]</p></td>
</tr>
<tr class="odd">
<td><p>output-node</p></td>
<td><p>O</p></td>
<td><p>-output-node [value]<br />
<br />
-O [value]</p></td>
</tr>
<tr class="even">
<td><p>target-node</p></td>
<td><p>t</p></td>
<td><p>-target-node [value]<br />
<br />
-t [value]</p></td>
</tr>
<tr class="odd">
<td><p>action</p></td>
<td><p>a</p></td>
<td><p>-action [value]<br />
<br />
-a [value]</p></td>
</tr>
<tr class="even">
<td><p>input-node</p></td>
<td><p>i</p></td>
<td><p>-input-node [value]<br />
-i [value]</p></td>
</tr>
<tr class="odd">
<td><p>pkcs12-path</p></td>
<td><p>k</p></td>
<td><p>-pkcs12-path [value]<br />
-k [value]</p></td>
</tr>
<tr class="even">
<td><p>custom-property</p></td>
<td><p>D</p></td>
<td><p>-custom-property [name=value,name=value]<br />
<br />
-D [name=value,name=value]</p></td>
</tr>
</tbody>
</table>

\endhtmlonly
