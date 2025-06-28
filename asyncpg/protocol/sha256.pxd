
# Copyright (C) 2016-present the asyncpg authors and contributors
# <see AUTHORS file>
#
# This module is part of asyncpg and is released under
# the Apache 2.0 License: http://www.apache.org/licenses/LICENSE-2.0


@cython.final
cdef class RFC5802Authentication:
    """Cython header declarations for RFC5802 SCRAM authentication mechanism.

    This header file defines the interface for the RFC5802Authentication class
    which implements the RFC5802 SCRAM authentication mechanism for secure
    password authentication.

    The class provides cryptographic operations for:
    - PBKDF2 key derivation
    - HMAC-based key generation
    - SHA256/SM3 hash computation
    - Hexadecimal encoding/decoding
    - XOR operations for password proofs

    All methods follow the RFC5802 specification for SCRAM authentication.
    """

    # Class constants
    cdef readonly int DEFAULT_ITERATIONS
    cdef readonly int DEFAULT_KEY_LENGTH
    cdef readonly list SUPPORTED_METHODS
    cdef readonly str HEX_CHARS
    cdef readonly bytes HEX_LOOKUP

    # Hexadecimal conversion methods
    cdef bytes hex_string_to_bytes(self, str hex_string)
    cdef str _bytes_to_hex_string(self, bytes src)
    cdef bytes _bytes_to_hex(self, bytes source_bytes, bytearray result_array=*, 
                            int start_pos=*, int length=*)

    # Cryptographic key generation methods
    cdef bytes _generate_k_from_pbkdf2(self, str password, str random64code, 
                                      int server_iteration)
    cdef bytes _get_key_from_hmac(self, bytes key, bytes data)

    # Hash computation methods
    cdef bytes _get_sha256(self, bytes message)
    cdef bytes _get_sm3(self, bytes message)

    # Password operation methods
    cdef bytes _xor_between_password(self, bytes password1, bytes password2, int length)

    # Main authentication method
    cpdef bytes authenticate(self, str password, str random64code, str token, 
                           str server_signature=*, int server_iteration=*, 
                           str method=*)
