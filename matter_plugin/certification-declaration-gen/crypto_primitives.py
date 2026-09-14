# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

# Cryptographic primitives for Matter Certification Declaration test vector generation.
#
# Implements the CHIP crypto primitive API using standard Python libraries.
#
# WARNING: These primitives are for TEST VECTOR GENERATION ONLY.
#          The underlying libraries are NOT hardened against side-channel
#          attacks and must NOT be used in production firmware or services.
#
# Requirements:
#   pip install pycryptodome ecdsa cryptography

from binascii import hexlify, unhexlify
import enum
import hashlib
import sys
import tempfile
import subprocess
from typing import Optional, Tuple, TypeVar, Union

from Crypto.Protocol.KDF import HKDF, PBKDF2
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes

from ecdsa import NIST256p, ECDH, SigningKey, VerifyingKey
from ecdsa.curves import Curve
from ecdsa.keys import BadSignatureError
from ecdsa.util import (
    randrange_from_seed__trytryagain,
    sigencode_strings,
    bit_length,
    sigencode_der,
)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

class MappingsV1(enum.IntEnum):
    CHIP_CRYPTO_HASH_LEN_BITS = 256
    CHIP_CRYPTO_HASH_LEN_BYTES = 32
    CHIP_CRYPTO_HASH_BLOCK_LEN_BYTES = 64
    CHIP_CRYPTO_GROUP_SIZE_BITS = 256
    CHIP_CRYPTO_GROUP_SIZE_BYTES = 32
    CHIP_CRYPTO_PUBLIC_KEY_SIZE_BYTES = (2 * CHIP_CRYPTO_GROUP_SIZE_BYTES) + 1
    CHIP_CRYPTO_SYMMETRIC_KEY_LENGTH_BITS = 128
    CHIP_CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES = 16
    CHIP_CRYPTO_AEAD_MIC_LENGTH_BITS = 128
    CHIP_CRYPTO_AEAD_MIC_LENGTH_BYTES = 16
    CHIP_CRYPTO_AEAD_NONCE_LENGTH_BYTES = 13


# ---------------------------------------------------------------------------
# Encoding helpers
# ---------------------------------------------------------------------------

def bytes_from_hex(hex: str) -> bytes:
    """Convert any hex string (including colon-separated ``01:ab:cd``) to bytes.

    Strips all whitespace including newlines before decoding.
    """
    return unhexlify("".join(hex.replace(":", "").split()))


def to_octet_string(data: bytes) -> str:
    """Return a colon-separated lowercase hex representation of *data*."""
    return ":".join("%02x" % b for b in data)


def bits2int(data: bytes) -> int:
    """Decode a big-endian octet string to a Python integer."""
    return int(hexlify(data), 16)


def make_c_array(byte_string: bytes, name: str) -> str:
    """Render *byte_string* as a named C ``uint8_t`` array literal."""
    buf = bytearray(byte_string)
    lines = ["const uint8_t %s[%d] = {" % (name, len(buf))]
    while buf:
        chunk, buf = buf[:16], buf[16:]
        lines.append("  %s," % ", ".join("0x%02x" % b for b in chunk))
    lines.append("};")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Key-pair abstraction
# ---------------------------------------------------------------------------

class Keypair:
    """Thin wrapper around a NIST P-256 signing/verifying key pair."""

    Keypair = TypeVar("Keypair", bound="Keypair")

    def __init__(self, private_key: SigningKey, public_key: VerifyingKey) -> None:
        assert len(private_key.to_string()) == MappingsV1.CHIP_CRYPTO_GROUP_SIZE_BYTES
        assert (
            len(public_key.to_string("uncompressed"))
            == MappingsV1.CHIP_CRYPTO_PUBLIC_KEY_SIZE_BYTES
        )
        self._private_key = private_key
        self._public_key = public_key

    # -- properties ----------------------------------------------------------

    @property
    def public_key(self) -> VerifyingKey:
        """Native library public key object."""
        return self._public_key

    @property
    def uncompressed_public_key_bytes(self) -> bytes:
        """Uncompressed EC point per SEC1 §2.3.3 (04 || X || Y)."""
        return self._public_key.to_string("uncompressed")

    @property
    def private_key(self) -> SigningKey:
        """Native library private key object."""
        return self._private_key

    @property
    def private_key_bytes(self) -> bytes:
        """Raw 32-byte private key scalar."""
        return self._private_key.to_string()

    # -- constructors --------------------------------------------------------

    @staticmethod
    def generate(seed: Optional[bytes] = None) -> "Keypair":
        """Generate a fresh P-256 key pair.

        If *seed* is supplied the generation is deterministic (useful for
        reproducible test vectors only — never do this in production).
        """
        if seed is None:
            sk = SigningKey.generate(curve=NIST256p)
        else:
            secexp = randrange_from_seed__trytryagain(seed, NIST256p.order)
            sk = SigningKey.from_secret_exponent(secexp, NIST256p)
        return Keypair(sk, sk.verifying_key)

    @staticmethod
    def from_raw(
        private_key_bytes: bytes,
        uncompressed_public_key_bytes: Optional[bytes] = None,
    ) -> "Keypair":
        """Reconstruct a :class:`Keypair` from raw byte representations."""
        sk = SigningKey.from_string(private_key_bytes, curve=NIST256p)
        if uncompressed_public_key_bytes is not None:
            pk = VerifyingKey.from_string(uncompressed_public_key_bytes, curve=NIST256p)
            assert pk == sk.verifying_key
        else:
            pk = sk.verifying_key
        return Keypair(sk, pk)


# ---------------------------------------------------------------------------
# Signature abstraction
# ---------------------------------------------------------------------------

class Signature:
    """ECDSA signature over NIST P-256, stored as raw (r, s) byte components."""

    Signature = TypeVar("Signature", bound="Signature")

    def __init__(self, r: bytes, s: bytes, curve: Curve = NIST256p) -> None:
        assert len(r) == MappingsV1.CHIP_CRYPTO_GROUP_SIZE_BYTES
        assert len(s) == MappingsV1.CHIP_CRYPTO_GROUP_SIZE_BYTES
        self._r = bytes(r)
        self._s = bytes(s)
        self._curve = curve

    # -- properties ----------------------------------------------------------

    @property
    def r(self) -> bytes:
        return self._r

    @property
    def s(self) -> bytes:
        return self._s

    @property
    def order(self) -> int:
        return self._curve.order

    @property
    def curve(self) -> Curve:
        return self._curve

    @property
    def raw_signature(self) -> bytes:
        """Concatenated r || s representation."""
        return self._r + self._s

    @property
    def rs_tuple(self) -> Tuple[bytes, bytes]:
        return (self._r, self._s)

    @property
    def der(self) -> bytes:
        """DER-encoded ECDSA signature (X9.62)."""
        return sigencode_der(bits2int(self._r), bits2int(self._s), self._curve.order)

    # -- constructors --------------------------------------------------------

    @staticmethod
    def from_raw(signature_bytes: bytes, curve: Curve = NIST256p) -> "Signature":
        """Create from concatenated r || s bytes."""
        half = len(signature_bytes) // 2
        assert half == MappingsV1.CHIP_CRYPTO_GROUP_SIZE_BYTES
        return Signature(signature_bytes[:half], signature_bytes[half:], curve)

    @staticmethod
    def from_rs_tuple(rs_tuple: Tuple[bytes, bytes], curve: Curve = NIST256p) -> "Signature":
        """Create from an (r, s) tuple."""
        r, s = rs_tuple
        return Signature(r, s, curve)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Signature):
            return NotImplemented
        return self.raw_signature == other.raw_signature and self.curve == other.curve


# ---------------------------------------------------------------------------
# Internal key-conversion helpers
# ---------------------------------------------------------------------------

def _to_signing_key(key: Union[bytes, Keypair, SigningKey]) -> SigningKey:
    if isinstance(key, SigningKey):
        return key
    if isinstance(key, bytes):
        return Keypair.from_raw(key).private_key
    return key.private_key


def _to_verifying_key(key: Union[bytes, Keypair, VerifyingKey]) -> VerifyingKey:
    if isinstance(key, VerifyingKey):
        return key
    if isinstance(key, bytes):
        return VerifyingKey.from_string(key, curve=NIST256p)
    return key.public_key


# ---------------------------------------------------------------------------
# CHIP crypto primitive API
# ---------------------------------------------------------------------------

def CHIP_Crypto_Sign(
    private_key: Union[bytes, Keypair, SigningKey],
    message: bytes,
) -> Signature:
    """ECDSA-SHA256 signature with a random nonce *k* (non-deterministic)."""
    sk = _to_signing_key(private_key)
    assert sk.curve == NIST256p
    r, s = sk.sign(message, hashfunc=hashlib.sha256, sigencode=sigencode_strings)
    return Signature(r, s)


def CHIP_Crypto_Sign_Digest_With_Provided_K_For_Test_Vectors(
    private_key: Union[bytes, Keypair, SigningKey],
    digest: bytes,
    k: bytes,
) -> Signature:
    """ECDSA sign a pre-computed *digest* using a fixed nonce *k*.

    *** FOR TEST VECTOR GENERATION ONLY — never use a fixed k in production. ***
    """
    sk = _to_signing_key(private_key)
    assert sk.curve == NIST256p
    assert len(k) == MappingsV1.CHIP_CRYPTO_GROUP_SIZE_BYTES
    k_int = bits2int(k)
    r, s = sk.sign_digest(digest, sigencode=sigencode_strings, k=k_int)
    return Signature(r, s)


def CHIP_Crypto_Verify(
    public_key: Union[bytes, Keypair, VerifyingKey],
    message: bytes,
    signature: Signature,
) -> bool:
    """Verify an ECDSA-SHA256 *signature* over *message*. Returns True on success."""
    vk = _to_verifying_key(public_key)
    assert vk.curve == NIST256p
    try:
        return vk.verify(signature.raw_signature, message, hashfunc=hashlib.sha256)
    except BadSignatureError:
        return False


def CHIP_Crypto_Verify_Digest(
    public_key: Union[bytes, Keypair, VerifyingKey],
    digest: bytes,
    signature: Signature,
) -> bool:
    """Verify an ECDSA *signature* over a pre-computed *digest*. Returns True on success."""
    vk = _to_verifying_key(public_key)
    assert vk.curve == NIST256p
    try:
        return vk.verify_digest(signature.raw_signature, digest)
    except BadSignatureError:
        return False


def CHIP_Crypto_TRNG(length: int) -> bytes:
    """Return *length* random bits as bytes. *length* must be a multiple of 8."""
    assert length % 8 == 0
    return get_random_bytes(length // 8)


def CHIP_Crypto_Hash(message: bytes) -> bytes:
    """SHA-256 digest of *message* (FIPS 180-4 §6.2)."""
    return SHA256.new(data=message).digest()


def CHIP_Crypto_KDF(inputKey: bytes, salt: bytes, info: str, length: int) -> bytes:
    """HKDF-SHA256 key derivation. *length* must be a multiple of 8."""
    assert length % 8 == 0
    return HKDF(inputKey, length // 8, salt, SHA256, 1, info)


def CHIP_Crypto_HMAC(key: bytes, message: bytes) -> bytes:
    """HMAC-SHA256 of *message* under *key*."""
    return HMAC.new(key, digestmod=SHA256).update(message).digest()


def CHIP_Crypto_PBKDF(input: bytes, salt: bytes, iterations: int, length: int) -> bytes:
    """PBKDF2-HMAC-SHA256. *length* must be a multiple of 8."""
    assert length % 8 == 0
    return PBKDF2(input, salt, length // 8, count=iterations, hmac_hash_module=SHA256)


def CHIP_Crypto_ECDH(
    my_private_key: Union[bytes, Keypair, SigningKey],
    their_public_key: Union[bytes, Keypair, VerifyingKey],
) -> bytes:
    """ECDH shared secret (NIST SEC1 §3.3.1). Returns 32-byte shared secret."""
    pk = _to_verifying_key(their_public_key)
    sk = _to_signing_key(my_private_key)
    assert pk.curve == NIST256p
    assert sk.curve == NIST256p

    ecdh = ECDH(curve=NIST256p)
    ecdh.load_received_public_key(pk)
    ecdh.load_private_key(sk)

    shared = ecdh.generate_sharedsecret_bytes()
    assert len(shared) == MappingsV1.CHIP_CRYPTO_GROUP_SIZE_BYTES
    return shared


# ---------------------------------------------------------------------------
# CMS helpers (used only for Certification Declaration testing)
# ---------------------------------------------------------------------------

def CMS_Sign(
    payload: bytes,
    pem_certificate: bytes,
    pem_key_bytes: bytes,
    out_format: str = "DER",
) -> bytes:
    """Wrap *payload* in a CMS SignedData structure and sign it.

    Uses the Subject Key Identifier from *pem_certificate* as the key ID.
    *out_format* is either ``"DER"`` (default) or ``"PEM"``.

    *** Used only for Certification Declaration test vector generation. ***
    """
    file_mode = "w+b" if out_format == "DER" else "w+"

    with tempfile.NamedTemporaryFile(mode="w+b", delete=True) as payload_file, \
         tempfile.NamedTemporaryFile(mode="w+", delete=True, suffix=".pem") as cert_file, \
         tempfile.NamedTemporaryFile(mode="w+", delete=True, suffix=".pem") as key_file, \
         tempfile.NamedTemporaryFile(mode=file_mode, delete=True) as cms_file:

        payload_file.write(payload)
        payload_file.flush()

        cert_file.write(
            pem_certificate if isinstance(pem_certificate, str)
            else pem_certificate.decode()
        )
        cert_file.flush()

        key_file.write(
            pem_key_bytes if isinstance(pem_key_bytes, str)
            else pem_key_bytes.decode()
        )
        key_file.flush()

        result = subprocess.run(
            [
                "openssl", "cms", "-sign", "-binary", "-noattr", "-nocerts",
                "-keyid",
                "-in", payload_file.name,
                "-signer", cert_file.name,
                "-inkey", key_file.name,
                "-outform", out_format,
                "-out", cms_file.name,
                "-text", "-nodetach",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if result.returncode != 0:
            raise ValueError(
                "openssl cms -sign failed (return code %d)" % result.returncode
            )
        return cms_file.read()


def CMS_Sign_Verify(cms: bytes, pem_certificate: bytes) -> bool:
    """Verify the signature on a DER-encoded CMS SignedData structure.

    *** Used only for Certification Declaration test vector generation. ***
    """
    with tempfile.NamedTemporaryFile(delete=True) as cms_file, \
         tempfile.NamedTemporaryFile(mode="w+", delete=True, suffix=".pem") as cert_file:

        cms_file.write(cms)
        cms_file.flush()

        cert_file.write(
            pem_certificate if isinstance(pem_certificate, str)
            else pem_certificate.decode()
        )
        cert_file.flush()

        result = subprocess.run(
            [
                "openssl", "cms", "-verify", "-noverify",
                "-inform", "DER",
                "-in", cms_file.name,
                "-certfile", cert_file.name,
                "-nointern",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    return result.returncode == 0


def CMS_GetSignedData(cms_signed_data: bytes, pem_certificate: bytes) -> bytes:
    """Extract and return the payload from a DER-encoded CMS SignedData blob.

    *** Used only for Certification Declaration test vector generation. ***
    """
    with tempfile.NamedTemporaryFile(delete=True) as cms_file, \
         tempfile.NamedTemporaryFile(mode="w+", delete=True, suffix=".pem") as cert_file, \
         tempfile.NamedTemporaryFile(delete=True) as out_file:

        cms_file.write(cms_signed_data)
        cms_file.flush()

        cert_file.write(
            pem_certificate if isinstance(pem_certificate, str)
            else pem_certificate.decode()
        )
        cert_file.flush()

        result = subprocess.run(
            [
                "openssl", "cms", "-verify", "-noverify",
                "-inform", "DER",
                "-in", cms_file.name,
                "-out", out_file.name,
                "-certfile", cert_file.name,
                "-nointern",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if result.returncode != 0:
            raise ValueError(
                "openssl cms -verify failed (return code %d)" % result.returncode
            )
        return out_file.read()


# ---------------------------------------------------------------------------
# Display helper
# ---------------------------------------------------------------------------

def print_large_hex_payload(
    label: str,
    payload: bytes,
    as_hex_dump: Optional[bool] = False,
    indent: Optional[int] = 0,
) -> None:
    """Print *payload* in hex, prefixed by *label*.

    When *as_hex_dump* is True the output matches ``hexdump -C`` format;
    otherwise a colon-separated octet string is used.
    """
    pad = " " * indent

    if not as_hex_dump:
        print("%s%s: %s" % (pad, label, to_octet_string(payload)))
        return

    COLS = 16
    print("%s%s:" % (pad, label))

    for row_start in range(0, len(payload), COLS):
        row = payload[row_start : row_start + COLS]
        hex_left = " ".join("%02x" % b for b in row[:8])
        hex_right = " ".join("%02x" % b for b in row[8:])
        ascii_part = "".join(chr(b) if 0x20 <= b <= 0x7E else "." for b in row)

        # Pad short rows
        if len(row) < 8:
            hex_left = "%-23s" % hex_left
            hex_right = ""
        elif len(row) < COLS:
            hex_right = "%-23s" % hex_right

        print("%s%08x  %-23s  %-23s  |%s|" % (
            pad, row_start, hex_left, hex_right, ascii_part
        ))

    print("%s%08x" % (pad, len(payload)))


# ---------------------------------------------------------------------------
# CLI convenience
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    if len(sys.argv) > 1:
        cmd = sys.argv[1]

        if cmd == "random" and len(sys.argv) > 2:
            n = int(sys.argv[2])
            print("%d random bytes: %s" % (n, to_octet_string(CHIP_Crypto_TRNG(n * 8))))

        elif cmd == "p256keypair":
            seed = None
            if len(sys.argv) > 2:
                raw = sys.argv[2]
                if raw.startswith("hex:"):
                    seed = bytes_from_hex(raw[4:])
                else:
                    seed = raw.encode("utf-8")
                print('Seed = "%s"' % to_octet_string(seed))

            kp = Keypair.generate(seed)
            print('public_key = "%s"' % to_octet_string(kp.uncompressed_public_key_bytes))
            print("public_key_pem =")
            print(kp.public_key.to_pem().decode("US-ASCII"))
            print('private_key = "%s"' % to_octet_string(kp.private_key_bytes))
            print("private_key_pem =")
            print(kp.private_key.to_pem().decode("US-ASCII"))