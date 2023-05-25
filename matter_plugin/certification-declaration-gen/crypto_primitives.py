# Copyright (C) Zigbee Alliance (2021). All rights reserved. This
# information within this document is the property of the Zigbee
# Alliance and its use and disclosure are restricted.

# Elements of Zigbee Alliance specifications may be subject to third
# party intellectual property rights, including without limitation,
# patent, copyright or trademark rights (such a third party may or may
# not be a member of the Zigbee Alliance). The Zigbee Alliance is not
# responsible and shall not be held responsible in any manner for
# identifying or failing to identify any or all such third party
# intellectual property rights.

# This document and the information contained herein are provided on an
# "AS IS" basis and the Zigbee Alliance DISCLAIMS ALL WARRANTIES EXPRESS
# OR IMPLIED, INCLUDING BUT NOT LIMITED TO (A) ANY WARRANTY THAT THE USE
# OF THE INFORMATION HEREIN WILL NOT INFRINGE ANY RIGHTS OF THIRD
# PARTIES (INCLUDING WITHOUT LIMITATION ANY INTELLECTUAL PROPERTY RIGHTS
# INCLUDING PATENT, COPYRIGHT OR TRADEMARK RIGHTS) OR (B) ANY IMPLIED
# WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, TITLE
# OR NON-INFRINGEMENT. IN NO EVENT WILL THE ZIGBEE ALLIANCE BE LIABLE
# FOR ANY LOSS OF PROFITS, LOSS OF BUSINESS, LOSS OF USE OF DATA,
# INTERRUPTION OF BUSINESS, OR FOR ANY OTHER DIRECT, INDIRECT, SPECIAL
# OR EXEMPLARY, INCIDENTAL, PUNITIVE OR CONSEQUENTIAL DAMAGES OF ANY
# KIND, IN CONTRACT OR IN TORT, IN CONNECTION WITH THIS DOCUMENT OR THE
# INFORMATION CONTAINED HEREIN, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH LOSS OR DAMAGE.

# All company, brand and product names may be trademarks that are the
# sole property of their respective owners.

# This legal notice must be included on all copies of this document that
# are made.

# Zigbee Alliance
# 508 Second Street, Suite 206
# Davis, CA 95616, USA
# ------------------------------------------------------------------------

# CHIP Cryptographic Primitives reference implementation for test vector
# generation/validation.

# Requirements of underlying crypto libraries:
#  `pip install pycryptodome`
#  `pip install ecdsa`
#  `pip install cryptography`
#  `pip install ctypescrypto`

##########################################################################
# WARNING: These primitives are implemented for the sake of illustration.
#          The underlying crypto libraries are NOT safe for production
#          use, as they are not safe against many attacks including
#          side-channel attacks. Furthermore, key management
#          is done using known sample key pairs.
##########################################################################

from binascii import hexlify, unhexlify
import enum
import hashlib
import sys, tempfile
import subprocess
from typing import Optional, TypeVar, Union, Tuple

from Crypto.Protocol.KDF import HKDF, PBKDF2
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes

# For Elliptical curve primitives
from ecdsa import NIST256p, ECDH, SigningKey, VerifyingKey
from ecdsa.curves import Curve
from ecdsa.keys import BadSignatureError
from ecdsa.util import randrange_from_seed__trytryagain, sigencode_strings, bit_length, sigencode_der

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


def bytes_from_hex(hex: str) -> bytes:
  """Converts any `hex` string representation including `01:ab:cd` to bytes

  Handles any whitespace including newlines, which are all stripped.
  """
  return unhexlify("".join(hex.replace(":","").split()))


def to_octet_string(input: bytes) -> str:
  """Takes `input` bytes and convert to a colon-separated hex octet string representation."""
  return ":".join(["%02x" % b for b in input])


def bits2int(data: bytes) -> int:
  """Convert `data` from positive number octet string in big endian byte order to a large integer suitable for ECDSA operations"""
  return int(hexlify(data), 16)


def make_c_array(byte_string: bytes, name: str) -> str:
  """Convert a large byte string to a named constant C/C++ uint8_t array. """
  def _extract_front(b: bytes, length: int) -> bytes:
    to_extract = min(length, len(b))
    span = b[0:to_extract]
    del b[0:to_extract]

    return span

  byte_string = bytearray(byte_string)
  output = "const uint8_t %s[%d] = {\n" % (name, len(byte_string))
  while len(byte_string) > 0:
    current_line_bytes = _extract_front(byte_string, 16)
    output += "  %s,\n" % ", ".join(["0x%02x" % b for b in current_line_bytes])
  output += "};\n"

  return output


class Keypair:
  # Type hint so an inner staticmethod can refer to the outer type
  Keypair = TypeVar('Keypair', bound='Keypair')

  def __init__(self, private_key: SigningKey, public_key: VerifyingKey):
    assert len(private_key.to_string()) == MappingsV1.CHIP_CRYPTO_GROUP_SIZE_BYTES
    assert len(public_key.to_string("uncompressed")) == MappingsV1.CHIP_CRYPTO_PUBLIC_KEY_SIZE_BYTES
    self._public_key = public_key
    self._private_key = private_key
    self._additional_info = bytes()

  @property
  def public_key(self) -> VerifyingKey:
    """Get native library format of public key"""
    return self._public_key

  @property
  def uncompressed_public_key_bytes(self) -> bytes:
    """Get public key in uncompressed EC curve point format per SEC1 2.3.3"""
    return self._public_key.to_string("uncompressed")

  @property
  def private_key(self) -> SigningKey:
    """Get native library format of private key"""
    return self._private_key

  @property
  def private_key_bytes(self) -> bytes:
    """Get raw private key"""
    return self._private_key.to_string()

  @staticmethod
  def generate(seed: Optional[bytes]=None) -> Keypair:
    """Generate an ECDSA key pair, possibly deterministically using `seed`."""
    curve = NIST256p

    # Generate secret key. If a seed is present, use it
    # to deterministically generate a key (only useful for testing)
    if not seed:
      sk = SigningKey.generate(curve=curve)
    else:
      secexp = randrange_from_seed__trytryagain(seed, curve.order)
      sk = SigningKey.from_secret_exponent(secexp, curve)

    assert sk.curve == curve

    return Keypair(sk, sk.verifying_key)

  @staticmethod
  def from_raw(private_key_bytes: bytes, uncompressed_public_key_bytes: Optional[bytes]=None) -> Keypair:
    """Generate a Keypair object from raw private/public key bytes"""
    curve = NIST256p

    sk = SigningKey.from_string(private_key_bytes, curve=curve)
    if uncompressed_public_key_bytes:
      pk = VerifyingKey.from_string(uncompressed_public_key_bytes, curve=curve)
      assert pk == sk.verifying_key
    else:
      pk = sk.verifying_key

    return Keypair(sk, pk)


class Signature:
  # Type hint so an inner staticmethod can refer to the outer type
  Signature = TypeVar('Signature', bound='Signature')

  def __init__(self, r: bytes, s: bytes, curve:Curve=NIST256p) -> None:
    """Constructor for a Crypto primitives signature"""
    assert len(r) == MappingsV1.CHIP_CRYPTO_GROUP_SIZE_BYTES
    assert len(s) == MappingsV1.CHIP_CRYPTO_GROUP_SIZE_BYTES

    self._r = r[:]
    self._s = s[:]
    self._curve = curve

  @property
  def r(self) -> bytes:
    """Get "r" component of the signature"""
    assert len(self._r) == MappingsV1.CHIP_CRYPTO_GROUP_SIZE_BYTES
    return self._r[:]

  @property
  def s(self) -> bytes:
    """Get "s" component of the signature"""
    assert len(self._s) == MappingsV1.CHIP_CRYPTO_GROUP_SIZE_BYTES
    return self._s[:]

  @property
  def order(self) -> int:
    """Get order of signature's curve"""
    return self._curve.order

  @property
  def curve(self) -> Curve:
    """Get signature's elliptical curve"""
    return self._curve

  @property
  def raw_signature(self) -> bytes:
    """Get raw concatenated string version of the signature (r || s)"""
    assert len(self._r) == MappingsV1.CHIP_CRYPTO_GROUP_SIZE_BYTES
    assert len(self._s) == MappingsV1.CHIP_CRYPTO_GROUP_SIZE_BYTES

    return self._r + self._s

  @property
  def rs_tuple(self) -> Tuple[bytes, bytes]:
    """Get signature as a tuple of (r, s)"""
    r = self.r
    s = self.s

    return (r, s)

  @property
  def der(self) -> bytes:
    """Get DER formatted ECDSA signature (X9.62 format)"""
    return sigencode_der(bits2int(self.r), bits2int(self.s), self._curve.order)

  @staticmethod
  def from_raw(signature_bytes: bytes, curve:Curve=NIST256p) -> Signature:
    """Create a Signature object from concatenated r || s raw representation."""
    assert len(signature_bytes) == (2 * MappingsV1.CHIP_CRYPTO_GROUP_SIZE_BYTES)

    r = signature_bytes[0:(len(signature_bytes) // 2)]
    s = signature_bytes[(len(signature_bytes) // 2):]

    return Signature(r, s, curve)

  @staticmethod
  def from_rs_tuple(rs_tuple: Tuple[bytes, bytes], curve:Curve=NIST256p) -> Signature:
    """Create a Signature object from a tuple of (r, s)"""
    r, s = rs_tuple
    assert len(r) == MappingsV1.CHIP_CRYPTO_GROUP_SIZE_BYTES
    assert len(s) == MappingsV1.CHIP_CRYPTO_GROUP_SIZE_BYTES

    return Signature(r, s, curve)

  def __eq__(self, o: object) -> bool:
    """Equality predicate for signature is bit-for-bit equivalence of raw version"""
    return (o.raw_signature == self.raw_signature) and (o.curve == self.curve)


def _convert_signing_key(private_key: Union[bytes, Keypair, SigningKey]) -> SigningKey:
  """Utility to take many different versions of private key representation and return a usable pyecdsa SigningKey"""
  if isinstance(private_key, SigningKey):
    signing_key = private_key
  elif isinstance(private_key, bytes):
    signing_key: SigningKey = Keypair.from_raw(private_key_bytes=private_key).private_key
  else:
    # Input is a Keypair
    signing_key: SigningKey = private_key.private_key

  return signing_key


def _convert_verifying_key(public_key: Union[bytes, Keypair, VerifyingKey]) -> VerifyingKey:
  """Utility to take many different versions of public key representation and return a usable pyecdsa VerifyingKey"""
  if isinstance(public_key, VerifyingKey):
    verifying_key = public_key
  elif isinstance(public_key, bytes):
    verifying_key: VerifyingKey = VerifyingKey.from_string(public_key, curve=NIST256p)
  else:
    # Input is a Keypair
    verifying_key: VerifyingKey = public_key.public_key

  return verifying_key


def CHIP_Crypto_Sign(private_key: Union[bytes, Keypair, SigningKey], message: bytes) -> Signature:
  """Sign message using ECDSA with SHA256, using given `private_key` and `message`.

  The SEC1 signing algorithm with random `k` will be used. Signature generated
  is not deterministic.
  """
  signing_key = _convert_signing_key(private_key)

  assert signing_key.curve == NIST256p

  r, s = signing_key.sign(message, hashfunc=hashlib.sha256, sigencode=sigencode_strings)

  assert len(r) == MappingsV1.CHIP_CRYPTO_GROUP_SIZE_BYTES
  assert len(s) == MappingsV1.CHIP_CRYPTO_GROUP_SIZE_BYTES

  return Signature(r, s)


def CHIP_Crypto_Sign_Digest_With_Provided_K_For_Test_Vectors(private_key: Union[bytes, Keypair, SigningKey], digest: bytes, k:bytes) -> Signature:
  """Sign `digest` using ECDSA with SHA256, using given `private_key`, and with the given nonce value `k`.

  *** THIS VERSION IS ONLY FOR DETERMINISTIC GENERATION OF TEST VECTORS ***

  This allows setting the `k` value to a non-random value, so that test
  vectors can be generated deterministically. The `k` has to be passed
  as a big-endian octet string.

  *** THIS VERSION IS ONLY FOR DETERMINISTIC GENERATION OF TEST VECTORS ***
  """
  signing_key = _convert_signing_key(private_key)

  assert signing_key.curve == NIST256p
  assert len(k) == MappingsV1.CHIP_CRYPTO_GROUP_SIZE_BYTES
  assert (len(k) * 8) == bit_length(signing_key.curve.order)
  k = bits2int(k)

  r, s = signing_key.sign_digest(digest, sigencode=sigencode_strings, k=k)

  assert len(r) == MappingsV1.CHIP_CRYPTO_GROUP_SIZE_BYTES
  assert len(s) == MappingsV1.CHIP_CRYPTO_GROUP_SIZE_BYTES

  return Signature(r, s)


def CHIP_Crypto_Verify(public_key: Union[bytes, Keypair, VerifyingKey], message: bytes, signature: Signature) -> bool:
  """Verify a `signature` on the given `message` using `public_key`. Returns True on success."""
  verifying_key = _convert_verifying_key(public_key)

  assert verifying_key.curve == NIST256p

  try:
    return verifying_key.verify(signature.raw_signature, message, hashfunc=hashlib.sha256)
  except BadSignatureError:
    return False

def CHIP_Crypto_Verify_Digest(public_key: Union[bytes, Keypair, VerifyingKey], digest: bytes, signature: Signature) -> bool:
  """Verify a `signature` on the given `digest` using `public_key`. Returns True on success."""
  verifying_key = _convert_verifying_key(public_key)

  assert verifying_key.curve == NIST256p

  try:
    return verifying_key.verify_digest(signature.raw_signature, digest)
  except BadSignatureError:
    return False


def CHIP_Crypto_TRNG(len: int) -> bytes:
  """Returns an array of `len` random bits."""
  assert (len % 8 == 0)
  return get_random_bytes(len // 8)


def CHIP_Crypto_Hash(message: bytes) -> bytes:
  """Returns the cryptographic hash digest of the `message`.

  CHIP_Crypto_Hash(message) :=
      byte[CHIP_CRYPTO_HASH_LEN_BYTES] SHA-256(M := message)

  `SHA-256()` SHALL be computed as defined in Section 6.2 of <<FIPS1804>>.
  """
  return SHA256.new(data=message).digest()


def CHIP_Crypto_KDF(inputKey: bytes, salt: bytes, info: str, len: int) -> bytes:
  """
  Returns the key of `len` bits derived from `inputKey` using the `salt` and the `info`; `len` SHALL be a multiple of 8.

  CHIP_Crypto_KDF(inputKey, salt, info, len) :=
     bit[len] KDM(Z := inputKey, OtherInput := {salt := salt, L := len, FixedInfo := info})
  ----
  `KDM()` SHALL be the HMAC-based KDF function with `CHIP_Crypto_HMAC(key := salt, message := x)`
   as the auxiliary function `H` as defined in Section 4.1 Option 2 of <<NIST80056C>>;
   it returns a bit array of `len` bits.
  """
  assert (len % 8 == 0)

  key = HKDF(inputKey, len // 8, salt, SHA256, 1, info)
  return key


def CHIP_Crypto_HMAC(key: bytes, message: bytes) -> bytes:
  """
  Returns the cryptographic keyed-hash message authentication code of a `message` using the given `key`.

  CHIP_Crypto_HMAC(key, message) :=
      byte[CHIP_CRYPTO_HASH_LEN_BYTES] HMAC(K := key, text := message)
  ----
  `HMAC()` SHALL be computed as defined in <<FIPS1981>> using `CHIP_Crypto_Hash()` as the
  underlying hash function `H` (this is also referred to as `HMAC-SHA256()`) and
  `CHIP_CRYPTO_HASH_LEN_BYTES` is defined in <<ref_HASH>>.
  """
  return HMAC.new(key, digestmod=SHA256).update(message).digest()


def CHIP_Crypto_PBKDF(input: bytes, salt: bytes, iterations: int, len: int) -> bytes:
  """
  Returns `length` bits of PBKDF2 w/ SHA256 of `input` against `salt` using `iterations` of the function.

  Crypto_PBKDF(input, salt, iterations, len) :=
      bit[len] PBKDF2(P := input, S := salt, C := iterations, kLen := len)
  """
  assert (len % 8 == 0)
  return PBKDF2(input, salt, len // 8, count=iterations, hmac_hash_module=SHA256)


def CHIP_Crypto_ECDH(my_private_key: Union[bytes, Keypair, SigningKey], their_public_key: Union[bytes, Keypair, VerifyingKey]) -> bytes:
  """Performs Elliptical Curve Diffie-Hellman (ECDH) key agreement algorithm per NIST SEC1 Section 3.3.1.

  Uses local `my_private_key`. Uses received `their_public_key`.
  """
  public_key = _convert_verifying_key(their_public_key)
  assert public_key.curve == NIST256p

  private_key = _convert_signing_key(my_private_key)
  assert private_key.curve == NIST256p

  ecdh = ECDH(curve=NIST256p)

  ecdh.load_received_public_key(public_key)
  ecdh.load_private_key(private_key)

  shared_secret = ecdh.generate_sharedsecret_bytes()
  assert len(shared_secret) == MappingsV1.CHIP_CRYPTO_GROUP_SIZE_BYTES

  return shared_secret


def CMS_Sign(payload: bytes, pem_certificate: bytes, pem_key_bytes: bytes, out_format="DER"):
  """Sign `payload` in a CMS SignedData Structure.
  Signs with with given `private_key_bytes`
  `certificate`'s 'kid' will be used for the Key ID in the SignedData Structure.
  *** This is only used to test Certification Declaration generation
      and is not described in the Matter spec's Core crypto primitives. ***
  """
  if out_format == 'DER':
    file_open_mode = 'w+b'
  else:
    file_open_mode = 'w+'

  with tempfile.NamedTemporaryFile(mode='w+b', delete=True) as payload_file:
    payload_file.write(payload)
    payload_file.flush()

    with tempfile.NamedTemporaryFile(mode='w+', delete=True) as cert_file:
      cert_file.write(pem_certificate)
      cert_file.flush()

      with tempfile.NamedTemporaryFile(mode='w+', delete=True) as key_file:
        key_file.write(pem_key_bytes)
        key_file.flush()

        with tempfile.NamedTemporaryFile(mode=file_open_mode, delete=True) as cms_file:
          res = subprocess.run(['openssl', 'cms', '-sign', '-binary', '-noattr', '-nocerts', '-keyid',
                                '-in', payload_file.name, '-signer', cert_file.name,
                                '-inkey', key_file.name, '-outform', out_format,
                                '-out', cms_file.name, '-text', '-nodetach'],
                                stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL)
          if res.returncode == 0:
            cms_bytes = cms_file.read()
          else:
            raise ValueError("Failed to sign CMS payload, openssl return code: %d" % res.returncode)

  return cms_bytes


def CMS_Sign_Verify(cms: bytes, pem_certificate: bytes) -> bool:
  """Verify signature on a CMS SignedData structure, returning CMS SignedData on success.

  *** This is only used to test Certification Declaration generation
      and is not described in the Matter spec's Core crypto primitives. ***
  """

  with tempfile.NamedTemporaryFile(delete=True) as cms_file:
    cms_file.write(cms)
    cms_file.flush()

    with tempfile.NamedTemporaryFile(mode='w+',delete=True) as cert_file:
      cert_file.write(pem_certificate)
      cert_file.flush()

      res = subprocess.run(['openssl', 'cms', '-verify', '-noverify', '-inform', 'DER', '-in', cms_file.name, '-certfile', cert_file.name, '-nointern'],
                           stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)

  return res.returncode == 0


def CMS_GetSignedData(cms_signed_data: bytes, pem_certificate: bytes) -> bytes:
  """Retrieve signeddata/payload from a CMS SignedData structure.

  Due to OpenSSL limitations, the `pem_certificate` associated with
  the signing key must be passed.
  """

  with tempfile.NamedTemporaryFile(delete=True) as cms_file:
    cms_file.write(cms_signed_data)
    cms_file.flush()

    with tempfile.NamedTemporaryFile(mode='w+', delete=True) as cert_file:
      cert_file.write(pem_certificate)
      cert_file.flush()

      with tempfile.NamedTemporaryFile(delete=True) as signeddata_file:
        res = subprocess.run(['openssl', 'cms', '-verify', '-noverify', '-inform', 'DER', '-in', cms_file.name, '-out',
                              signeddata_file.name, '-certfile', cert_file.name, '-nointern'],
                             stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
        if res.returncode == 0:
          payload_bytes = signeddata_file.read()
        else:
          raise ValueError("Failed to extract CMS payload, openssl return code: %d" % res.returncode)

  return payload_bytes


def print_large_hex_payload(label:str, payload:bytes, as_hex_dump: Optional[bool]=False, indent: Optional[int]=0):
  """Print a large `payload` in hex for display, prefixed with a  `label`.

  If `as_hex_dump` is True, format will be a canonical hex dump (equal to
  `hexdump -C` on *NIX), otherwise format is an octet string with colons.

  If `indent` is non-zero, that number of spaces prefixes each line.
  """
  if not as_hex_dump:
    print((" " * indent) + label + ": " + to_octet_string(payload))
    return

  BYTES_PER_LINE = 16

  addr = 0
  byte_count = 0
  line_buf = []
  ascii_buf = ["|"]

  def flush() -> str:
    if len(line_buf) == 0:
      return ""

    ascii_buf.append("|")
    line = "".join(line_buf)

    half_line = (BYTES_PER_LINE // 2)
    unfilled = (BYTES_PER_LINE - byte_count) % BYTES_PER_LINE


    if unfilled >= half_line:
      # Handle left-half pan with extra space in the middle
      line += "   " * half_line
      line += " "
      unfilled -= half_line

    if unfilled > 0:
      line += "   " * unfilled

    line += "".join(ascii_buf)

    return line

  print((" " * indent) + label + ": ")
  while True:
    if byte_count % BYTES_PER_LINE == 0:
      byte_count = 0

      # Flush on line boundary
      line = flush()
      if len(line) > 0:
        print(line)

      # Reset accumulators
      line_buf = []
      ascii_buf = ["|"]

      line_buf.append(" " * indent)
      line_buf.append("%08x " % addr)

    # Add extra space after half the width, and after address
    if byte_count % (BYTES_PER_LINE // 2) == 0:
      line_buf.append(" ")

    curr_byte = payload[addr]
    line_buf.append("%02x " % payload[addr])
    if curr_byte < 0x20 or curr_byte > 0x7E:
      ascii_buf.append(".")
    else:
      ascii_buf.append(chr(curr_byte))

    addr += 1
    byte_count += 1

    if addr == len(payload):
      break

  # Done: do final flush and print final address (the length)
  line = flush()
  if len(line) > 0:
    print(line)

  print((" " * indent) + ("%08x" % addr))


if __name__ == "__main__":
  # Very rough utilities
  if len(sys.argv) > 1:
    if len(sys.argv) > 2 and sys.argv[1] == "random":
      # Generate a random octet string of 32 bytes: `python crypto_primitives.py random 32`
      n_bytes = int(sys.argv[2])
      print("%d random bytes: %s" % (n_bytes, to_octet_string(CHIP_Crypto_TRNG(n_bytes * 8))))
    elif sys.argv[1] == "p256keypair":
      # Generate a secp256r1 key pair: `python crypto_primitives.py p256keypair`
      # Generate a secp256r1 key pair from hex string seed 00112233: `python crypto_primitives.py p256keypair hex:00112233`
      # Generate a secp256r1 key pair from seed string "roboto": `python crypto_primitives.py p256keypair roboto`
      seed = None
      if len(sys.argv) > 2:
        if sys.argv[2].startswith("hex:"):
          seed = bytes_from_hex(sys.argv[2][len("hex:"):])
        else:
          seed = sys.argv[2].encode("utf-8")

        print('Seed = "%s"' % to_octet_string(seed))

      key_pair = Keypair.generate(seed)
      print('public_key = "%s"' % to_octet_string(key_pair.uncompressed_public_key_bytes))
      print('public_key_pem =')
      print(key_pair.public_key.to_pem().decode('US-ASCII'))
      print('private_key = "%s"' % to_octet_string(key_pair.private_key_bytes))
      print('private_key_pem =')
      print(key_pair.private_key.to_pem().decode('US-ASCII'))
