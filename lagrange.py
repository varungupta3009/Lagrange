#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Lagrange: unify, repair, and manage Antigravity conversations, workspaces,
and projects across the Hub, IDE, and CLI surfaces.

Lagrange is an offline reconciler. It treats the trajectory files
(``<id>.db`` SQLite stores and legacy ``<id>.pb`` encrypted protobufs) as the
source of truth, and rebuilds every derived index from them:

* ``~/.gemini/antigravity/agyhub_summaries_proto.pb`` (Hub summary store)
* ``state.vscdb`` (IDE unified state sync topics)
* ``~/.gemini/config/projects/<uuid>.json`` (project registry)
* CLI caches under ``~/.gemini/antigravity-cli/cache/``

It needs only the Python 3.9+ standard library. The optional
``cryptography`` package makes ``.pb`` decryption faster. Without it,
Lagrange uses the system OpenSSL library through ``ctypes``, and as a last
resort a pure-Python AES-256-GCM implementation.

Close every Antigravity window, language server, and CLI session before
running a mutating command.
"""

from __future__ import annotations

import argparse
import base64
import ctypes
import ctypes.util
import datetime as _dt
import hmac
import json
import os
import posixpath
import re
import shutil
import sqlite3
import struct
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path
from urllib.parse import quote, unquote

__version__ = "1.0.0"

# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class LagrangeError(Exception):
    """A user-facing error. The message is printed without a traceback."""


class ProtoError(ValueError):
    """Raised when bytes are not a well-formed protobuf message."""


class InvalidTag(Exception):
    """Raised when AES-GCM authentication fails."""


# ---------------------------------------------------------------------------
# Protobuf wire codec
# ---------------------------------------------------------------------------

WT_VARINT, WT_I64, WT_LEN, WT_SGROUP, WT_EGROUP, WT_I32 = 0, 1, 2, 3, 4, 5
_MAX_FIELD = (1 << 29) - 1


def encode_varint(value):
    """Encode an int as a protobuf varint (negatives use 64-bit two's complement)."""
    value = int(value)
    if value < 0:
        value += 1 << 64
    if value < 0 or value >= 1 << 64:
        raise ProtoError("varint out of range: %r" % value)
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def decode_varint(data, pos):
    """Decode a varint at ``pos``. Returns ``(value, new_pos)``."""
    result = 0
    shift = 0
    n = len(data)
    while True:
        if pos >= n:
            raise ProtoError("truncated varint")
        byte = data[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            break
        shift += 7
        if shift >= 70:
            raise ProtoError("varint too long")
    if result >= 1 << 64:
        raise ProtoError("varint overflow")
    return result, pos


def to_signed64(value):
    return value - (1 << 64) if value >= 1 << 63 else value


def encode_tag(num, wire_type):
    return encode_varint((num << 3) | wire_type)


def _skip_group(data, pos, group_num, depth=0):
    if depth > 64:
        raise ProtoError("group nesting too deep")
    n = len(data)
    while True:
        if pos >= n:
            raise ProtoError("unterminated group")
        key, pos = decode_varint(data, pos)
        num, wt = key >> 3, key & 7
        if num < 1:
            raise ProtoError("invalid field number in group")
        if wt == WT_EGROUP:
            if num != group_num:
                raise ProtoError("mismatched end group")
            return pos
        if wt == WT_VARINT:
            _, pos = decode_varint(data, pos)
        elif wt == WT_I64:
            pos += 8
        elif wt == WT_I32:
            pos += 4
        elif wt == WT_LEN:
            length, pos = decode_varint(data, pos)
            pos += length
        elif wt == WT_SGROUP:
            pos = _skip_group(data, pos, num, depth + 1)
        else:
            raise ProtoError("invalid wire type in group")
        if pos > n:
            raise ProtoError("truncated group")


class Field(object):
    """One wire-level field. ``raw`` holds the exact original bytes, if any."""

    __slots__ = ("num", "wt", "value", "raw")

    def __init__(self, num, wt, value, raw=None):
        self.num = num
        self.wt = wt
        self.value = value
        self.raw = raw

    def __repr__(self):
        return "Field(%d, %d, %r)" % (self.num, self.wt, self.value)


def _encode_field(num, wt, value):
    if wt == WT_VARINT:
        return encode_tag(num, wt) + encode_varint(value)
    if wt == WT_LEN:
        return encode_tag(num, wt) + encode_varint(len(value)) + value
    if wt == WT_I64:
        if isinstance(value, int):
            value = struct.pack("<Q", value & 0xFFFFFFFFFFFFFFFF)
        if len(value) != 8:
            raise ProtoError("fixed64 needs 8 bytes")
        return encode_tag(num, wt) + value
    if wt == WT_I32:
        if isinstance(value, int):
            value = struct.pack("<I", value & 0xFFFFFFFF)
        if len(value) != 4:
            raise ProtoError("fixed32 needs 4 bytes")
        return encode_tag(num, wt) + value
    raise ProtoError("cannot encode wire type %d" % wt)


class ProtoFields(object):
    """
    A schema-less, tag-verified protobuf message.

    Parsing keeps every field (known or unknown) together with its original
    bytes. Serializing an unmodified message reproduces the input exactly.
    Only fields changed through ``set``/``set_all``/``append`` are re-encoded.
    """

    __slots__ = ("fields",)

    def __init__(self, fields=None):
        self.fields = list(fields or [])

    # -- parsing ----------------------------------------------------------
    @classmethod
    def parse(cls, data):
        if data is None:
            return cls()
        if isinstance(data, ProtoFields):
            return cls.parse(data.serialize())
        data = bytes(data)
        fields = []
        pos = 0
        n = len(data)
        while pos < n:
            start = pos
            key, pos = decode_varint(data, pos)
            num, wt = key >> 3, key & 7
            if num < 1 or num > _MAX_FIELD:
                raise ProtoError("invalid field number %d" % num)
            if wt == WT_VARINT:
                value, pos = decode_varint(data, pos)
            elif wt == WT_I64:
                if pos + 8 > n:
                    raise ProtoError("truncated fixed64")
                value = data[pos:pos + 8]
                pos += 8
            elif wt == WT_LEN:
                length, pos = decode_varint(data, pos)
                if pos + length > n:
                    raise ProtoError("truncated length-delimited field")
                value = data[pos:pos + length]
                pos += length
            elif wt == WT_I32:
                if pos + 4 > n:
                    raise ProtoError("truncated fixed32")
                value = data[pos:pos + 4]
                pos += 4
            elif wt == WT_SGROUP:
                pos = _skip_group(data, pos, num)
                value = data[start:pos]
            else:
                raise ProtoError("unexpected wire type %d" % wt)
            fields.append(Field(num, wt, value, data[start:pos]))
        return cls(fields)

    @classmethod
    def try_parse(cls, data):
        try:
            return cls.parse(data)
        except (ProtoError, TypeError, ValueError):
            return None

    def copy(self):
        return ProtoFields.parse(self.serialize())

    # -- serialization ----------------------------------------------------
    def serialize(self):
        out = bytearray()
        for f in self.fields:
            if f.raw is not None:
                out += f.raw
            else:
                out += _encode_field(f.num, f.wt, f.value)
        return bytes(out)

    __bytes__ = serialize

    def __len__(self):
        return len(self.fields)

    def __iter__(self):
        return iter(self.fields)

    def __repr__(self):
        return "ProtoFields(%r)" % (self.fields,)

    # -- accessors --------------------------------------------------------
    def has(self, num):
        return any(f.num == num for f in self.fields)

    def get_all(self, num, wt=None):
        return [f.value for f in self.fields
                if f.num == num and (wt is None or f.wt == wt)]

    def get(self, num, default=None, wt=None):
        for f in self.fields:
            if f.num == num and (wt is None or f.wt == wt):
                return f.value
        return default

    def get_int(self, num, default=0):
        """Last varint occurrence wins, matching protobuf merge semantics."""
        values = self.get_all(num, WT_VARINT)
        return values[-1] if values else default

    def get_str(self, num, default=""):
        """Return field ``num`` as text only if its wire type is LEN and it is valid UTF-8."""
        values = self.get_all(num, WT_LEN)
        if not values:
            return default
        try:
            return values[-1].decode("utf-8")
        except UnicodeDecodeError:
            return default

    def get_strs(self, num):
        out = []
        for value in self.get_all(num, WT_LEN):
            try:
                out.append(value.decode("utf-8"))
            except UnicodeDecodeError:
                continue
        return out

    def get_msg(self, num):
        values = self.get_all(num, WT_LEN)
        if not values:
            return None
        return ProtoFields.try_parse(values[-1])

    def get_msgs(self, num):
        out = []
        for value in self.get_all(num, WT_LEN):
            msg = ProtoFields.try_parse(value)
            if msg is not None:
                out.append(msg)
        return out

    # -- mutation ---------------------------------------------------------
    @staticmethod
    def _coerce(value, wt):
        if isinstance(value, bool):
            return int(value), WT_VARINT if wt is None else wt
        if isinstance(value, int):
            return value, WT_VARINT if wt is None else wt
        if isinstance(value, str):
            return value.encode("utf-8"), WT_LEN
        if isinstance(value, ProtoFields):
            return value.serialize(), WT_LEN
        if isinstance(value, (bytes, bytearray, memoryview)):
            return bytes(value), WT_LEN if wt is None else wt
        raise TypeError("unsupported protobuf value: %r" % type(value))

    def _make(self, num, value, wt):
        value, wt = self._coerce(value, wt)
        if wt == WT_VARINT and value < 0:
            value += 1 << 64
        return Field(num, wt, value, None)

    def set(self, num, value, wt=None):
        """Replace field ``num`` in place (first position kept). ``None`` removes it."""
        if value is None:
            self.remove(num)
            return self
        return self.set_all(num, [value], wt)

    def set_all(self, num, values, wt=None):
        """Replace every occurrence of ``num`` with ``values`` at the first position."""
        new = [self._make(num, v, wt) for v in values]
        out = []
        inserted = False
        for f in self.fields:
            if f.num == num:
                if not inserted:
                    out.extend(new)
                    inserted = True
                continue
            out.append(f)
        if not inserted:
            out.extend(new)
        self.fields = out
        return self

    def append(self, num, value, wt=None):
        self.fields.append(self._make(num, value, wt))
        return self

    def remove(self, num):
        self.fields = [f for f in self.fields if f.num != num]
        return self


def map_entries(msg, num):
    """Yield ``(key, value, entry)`` for a ``map<string, ...>`` field."""
    out = []
    if msg is None:
        return out
    for raw in msg.get_all(num, WT_LEN):
        entry = ProtoFields.try_parse(raw)
        if entry is None:
            continue
        key = entry.get_str(1, None)
        if key is None:
            continue
        out.append((key, entry.get(2), entry))
    return out


def make_map_entry(key, value, wt=None):
    entry = ProtoFields().append(1, key)
    if value is not None:
        entry.append(2, value, wt)
    return entry


def ts_to_float(msg):
    if msg is None:
        return None
    if not isinstance(msg, ProtoFields):
        msg = ProtoFields.try_parse(msg)
        if msg is None:
            return None
    if not msg.has(1) and not msg.has(2):
        return None
    seconds = to_signed64(msg.get_int(1, 0))
    nanos = msg.get_int(2, 0)
    return seconds + nanos / 1e9


def ts_from_float(value):
    seconds = int(value)
    nanos = int(round((value - seconds) * 1e9))
    if nanos >= 1000000000:
        seconds += 1
        nanos -= 1000000000
    msg = ProtoFields()
    if seconds:
        msg.append(1, seconds)
    if nanos:
        msg.append(2, nanos)
    return msg


# ---------------------------------------------------------------------------
# Schema field numbers (external-facing names)
# ---------------------------------------------------------------------------


class TrajectoryF:
    TRAJECTORY_ID = 1
    STEPS = 2
    TRAJECTORY_TYPE = 4
    CASCADE_ID = 6
    METADATA = 7
    SOURCE = 8


class StepF:
    TYPE = 1
    METADATA = 5
    USER_INPUT = 19
    CHECKPOINT = 30


STEP_TYPE_USER_INPUT = 14
STEP_TYPE_CHECKPOINT = 23
USER_INPUT_RESPONSE = 2
CHECKPOINT_USER_INTENT = 4
STEP_META_TIMESTAMPS = (1, 6, 7, 8)  # created, viewable, finished, completed

TRAJECTORY_TYPE_MAIN = 1
TRAJECTORY_TYPE_SUBAGENT = 16
SOURCE_UNSPECIFIED = 0
SOURCE_CLI = 17


class MetaF:  # TrajectoryMetadata
    WORKSPACES = 1
    CREATED_AT = 2
    PARENT_CONVERSATION_ID = 5
    ROOT_CONVERSATION_ID = 6
    WORKSPACE_URIS = 7
    NESTING_DEPTH = 17
    PROJECT_ID = 18


class WsF:  # WorkspaceMetadata
    FOLDER_URI = 1
    GIT_ROOT_URI = 2
    REPOSITORY = 3
    BRANCH_NAME = 4


class SummaryF:  # TrajectorySummary
    SUMMARY = 1
    STEP_COUNT = 2
    LAST_MODIFIED_TIME = 3
    TRAJECTORY_ID = 4
    STATUS = 5
    CREATED_TIME = 7
    WORKSPACES = 9
    LAST_USER_INPUT_TIME = 10
    ANNOTATIONS = 15
    LAST_USER_INPUT_STEP_INDEX = 16
    TRAJECTORY_METADATA = 17
    SOURCE = 20
    TRAJECTORY_TYPE = 22


STATUS_IDLE = 1


class AnnF:  # ConversationAnnotations
    TITLE = 1
    TAGS = 3
    ARCHIVED = 4
    STARRED = 6
    PINNED = 12
    CONVERSATION_GROUP_ID = 15


class StateF:  # SummariesState
    SUMMARIES = 1
    FILE_MOD_TIMES = 2


USS_TOPIC_DATA = 1
USS_ROW_VALUE = 1
# Observed on disk: SidebarWorkspace stores its URI in field 4 and the
# display state in field 5 (fields 1-3 are reserved). Field 1 is read as a
# fallback for older writers.
SIDEBAR_URI = 4
SIDEBAR_URI_LEGACY = 1
SIDEBAR_DISPLAY_STATE = 5
SIDEBAR_ORDER = 3
INIT_STATE_SUMMARIES = 1  # -> TrajectorySummaries { map summaries = 1 }
INIT_STATE_SIDEBAR_URIS = 13
INIT_STATE_SIDEBAR_WORKSPACES = 14

USS_TRAJECTORY_KEY = "antigravityUnifiedStateSync.trajectorySummaries"
USS_SIDEBAR_KEY = "antigravityUnifiedStateSync.sidebarWorkspaces"
LEGACY_INIT_STATE_KEY = bytes.fromhex(
    "6a6574736b69537461746553796e632e6167656e744d616e61676572496e69745374617465"
).decode("ascii")

OUTSIDE_PROJECT = "outside-of-project"
HUB_SUMMARIES_FILE = "agyhub_summaries_proto.pb"
SUMMARIES_DB_FILE = "conversation_summaries.db"

# ---------------------------------------------------------------------------
# AES-256-GCM for legacy .pb trajectories
# ---------------------------------------------------------------------------

DEFAULT_PB_KEY = bytes.fromhex(
    "73616665436f646569756d776f726c644b655973656372657442616c6c6f6f6e")
GCM_NONCE_SIZE = 12
GCM_TAG_SIZE = 16


class _CryptographyBackend(object):
    name = "cryptography"

    def __init__(self):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa
        from cryptography.exceptions import InvalidTag as _CInvalidTag  # noqa
        self._aesgcm = AESGCM
        self._invalid = _CInvalidTag

    def encrypt(self, key, nonce, plaintext):
        return self._aesgcm(key).encrypt(nonce, plaintext, None)

    def decrypt(self, key, nonce, data):
        try:
            return self._aesgcm(key).decrypt(nonce, data, None)
        except self._invalid:
            raise InvalidTag()


def _libcrypto_candidates():
    env = os.environ.get("LAGRANGE_LIBCRYPTO")
    if env:
        yield env
    if sys.platform == "darwin":
        # Never load the unversioned system libcrypto.dylib: macOS aborts the
        # process when it is loaded directly. Versioned copies are safe.
        for prefix in ("/opt/homebrew", "/usr/local"):
            for ver in ("openssl@3", "openssl@1.1", "openssl"):
                yield "%s/opt/%s/lib/libcrypto.dylib" % (prefix, ver)
            yield prefix + "/lib/libcrypto.3.dylib"
        for base in (sys.base_prefix, sys.prefix):
            for name in ("libcrypto.3.dylib", "libcrypto.1.1.dylib"):
                yield os.path.join(base, "lib", name)
        for ver in (56, 55, 54, 52, 50, 48, 46, 44, 42, 41, 39, 38, 35):
            yield "/usr/lib/libcrypto.%d.dylib" % ver
        return
    if os.name == "nt":
        for base in (sys.base_prefix, sys.prefix, os.path.dirname(sys.executable)):
            for name in ("libcrypto-3-x64.dll", "libcrypto-3.dll",
                         "libcrypto-1_1-x64.dll", "libcrypto-1_1.dll"):
                yield os.path.join(base, "DLLs", name)
                yield os.path.join(base, name)
    found = ctypes.util.find_library("crypto")
    if found:
        yield found
    for name in ("libcrypto.so.3", "libcrypto.so.1.1", "libcrypto.so"):
        yield name


class _LibcryptoBackend(object):
    name = "libcrypto"
    _SET_IVLEN, _GET_TAG, _SET_TAG = 0x9, 0x10, 0x11

    def __init__(self):
        lib = None
        last = None
        for cand in _libcrypto_candidates():
            if os.path.isabs(cand) and not os.path.exists(cand):
                if not (sys.platform == "darwin" and cand.startswith("/usr/lib/")):
                    continue
            try:
                lib = ctypes.CDLL(cand)
                lib.EVP_aes_256_gcm  # noqa: B018 -- probe symbol
                break
            except (OSError, AttributeError) as exc:
                last = exc
                lib = None
        if lib is None:
            raise OSError("libcrypto not found (%s)" % last)
        c_void_p, c_int, c_char_p = ctypes.c_void_p, ctypes.c_int, ctypes.c_char_p
        lib.EVP_CIPHER_CTX_new.restype = c_void_p
        lib.EVP_CIPHER_CTX_free.argtypes = [c_void_p]
        lib.EVP_aes_256_gcm.restype = c_void_p
        for fn in ("EVP_EncryptInit_ex", "EVP_DecryptInit_ex"):
            getattr(lib, fn).argtypes = [c_void_p, c_void_p, c_void_p, c_char_p, c_char_p]
        for fn in ("EVP_EncryptUpdate", "EVP_DecryptUpdate"):
            getattr(lib, fn).argtypes = [c_void_p, c_void_p, ctypes.POINTER(c_int), c_char_p, c_int]
        for fn in ("EVP_EncryptFinal_ex", "EVP_DecryptFinal_ex"):
            getattr(lib, fn).argtypes = [c_void_p, c_void_p, ctypes.POINTER(c_int)]
        lib.EVP_CIPHER_CTX_ctrl.argtypes = [c_void_p, c_int, c_int, c_void_p]
        self.lib = lib

    def _run(self, encrypt, key, nonce, data, tag=None):
        lib = self.lib
        ctx = lib.EVP_CIPHER_CTX_new()
        if not ctx:
            raise OSError("EVP_CIPHER_CTX_new failed")
        try:
            init = lib.EVP_EncryptInit_ex if encrypt else lib.EVP_DecryptInit_ex
            update = lib.EVP_EncryptUpdate if encrypt else lib.EVP_DecryptUpdate
            final = lib.EVP_EncryptFinal_ex if encrypt else lib.EVP_DecryptFinal_ex
            if init(ctx, lib.EVP_aes_256_gcm(), None, None, None) != 1:
                raise OSError("EVP init failed")
            if lib.EVP_CIPHER_CTX_ctrl(ctx, self._SET_IVLEN, len(nonce), None) != 1:
                raise OSError("set IV length failed")
            if init(ctx, None, None, key, nonce) != 1:
                raise OSError("EVP key init failed")
            out = ctypes.create_string_buffer(len(data) + 32)
            outl = ctypes.c_int(0)
            if data and update(ctx, out, ctypes.byref(outl), data, len(data)) != 1:
                raise OSError("EVP update failed")
            total = outl.value
            if not encrypt:
                tag_buf = ctypes.create_string_buffer(tag, len(tag))
                if lib.EVP_CIPHER_CTX_ctrl(ctx, self._SET_TAG, len(tag), tag_buf) != 1:
                    raise OSError("set tag failed")
            fin = ctypes.c_int(0)
            tail = ctypes.create_string_buffer(32)
            if final(ctx, tail, ctypes.byref(fin)) != 1:
                if encrypt:
                    raise OSError("EVP final failed")
                raise InvalidTag()
            result = out.raw[:total] + tail.raw[:fin.value]
            if encrypt:
                tag_out = ctypes.create_string_buffer(GCM_TAG_SIZE)
                if lib.EVP_CIPHER_CTX_ctrl(ctx, self._GET_TAG, GCM_TAG_SIZE, tag_out) != 1:
                    raise OSError("get tag failed")
                result += tag_out.raw
            return result
        finally:
            lib.EVP_CIPHER_CTX_free(ctx)

    def encrypt(self, key, nonce, plaintext):
        return self._run(True, key, nonce, plaintext)

    def decrypt(self, key, nonce, data):
        if len(data) < GCM_TAG_SIZE:
            raise InvalidTag()
        return self._run(False, key, nonce, data[:-GCM_TAG_SIZE], data[-GCM_TAG_SIZE:])


def _build_aes_tables():
    def rotl8(x, s):
        return ((x << s) | (x >> (8 - s))) & 0xFF

    sbox = [0] * 256
    p = q = 1
    while True:
        p = p ^ ((p << 1) & 0xFF) ^ (0x1B if p & 0x80 else 0)
        q ^= q << 1
        q ^= q << 2
        q ^= q << 4
        q &= 0xFF
        if q & 0x80:
            q ^= 0x09
        x = q ^ rotl8(q, 1) ^ rotl8(q, 2) ^ rotl8(q, 3) ^ rotl8(q, 4)
        sbox[p] = x ^ 0x63
        if p == 1:
            break
    sbox[0] = 0x63

    def xtime(a):
        a <<= 1
        return (a ^ 0x1B) & 0xFF if a & 0x100 else a

    t0 = []
    for i in range(256):
        s = sbox[i]
        s2 = xtime(s)
        s3 = s2 ^ s
        t0.append((s2 << 24) | (s << 16) | (s << 8) | s3)
    t1 = [((t >> 8) | (t << 24)) & 0xFFFFFFFF for t in t0]
    t2 = [((t >> 16) | (t << 16)) & 0xFFFFFFFF for t in t0]
    t3 = [((t >> 24) | (t << 8)) & 0xFFFFFFFF for t in t0]
    return sbox, t0, t1, t2, t3, xtime


class _PurePythonBackend(object):
    """Slow but dependency-free AES-256-GCM (fallback of last resort)."""

    name = "pure-python"
    _tables = None

    def __init__(self):
        if _PurePythonBackend._tables is None:
            _PurePythonBackend._tables = _build_aes_tables()

    def _expand(self, key):
        sbox, _, _, _, _, xtime = self._tables
        nk = len(key) // 4
        if len(key) not in (16, 24, 32):
            raise ValueError("AES key must be 16, 24, or 32 bytes")
        nr = nk + 6
        w = [int.from_bytes(key[4 * i:4 * i + 4], "big") for i in range(nk)]
        rcon = 1

        def subword(t):
            return ((sbox[t >> 24] << 24) | (sbox[(t >> 16) & 255] << 16)
                    | (sbox[(t >> 8) & 255] << 8) | sbox[t & 255])

        for i in range(nk, 4 * (nr + 1)):
            t = w[i - 1]
            if i % nk == 0:
                t = ((t << 8) & 0xFFFFFFFF) | (t >> 24)
                t = subword(t) ^ (rcon << 24)
                rcon = xtime(rcon)
            elif nk > 6 and i % nk == 4:
                t = subword(t)
            w.append(w[i - nk] ^ t)
        return w, nr

    def _encrypt_block_fn(self, key):
        sbox, T0, T1, T2, T3, _ = self._tables
        w, nr = self._expand(key)

        def enc(block_int):
            s0 = (block_int >> 96) ^ w[0]
            s1 = ((block_int >> 64) & 0xFFFFFFFF) ^ w[1]
            s2 = ((block_int >> 32) & 0xFFFFFFFF) ^ w[2]
            s3 = (block_int & 0xFFFFFFFF) ^ w[3]
            k = 4
            for _ in range(nr - 1):
                t0 = T0[s0 >> 24] ^ T1[(s1 >> 16) & 255] ^ T2[(s2 >> 8) & 255] ^ T3[s3 & 255] ^ w[k]
                t1 = T0[s1 >> 24] ^ T1[(s2 >> 16) & 255] ^ T2[(s3 >> 8) & 255] ^ T3[s0 & 255] ^ w[k + 1]
                t2 = T0[s2 >> 24] ^ T1[(s3 >> 16) & 255] ^ T2[(s0 >> 8) & 255] ^ T3[s1 & 255] ^ w[k + 2]
                t3 = T0[s3 >> 24] ^ T1[(s0 >> 16) & 255] ^ T2[(s1 >> 8) & 255] ^ T3[s2 & 255] ^ w[k + 3]
                s0, s1, s2, s3 = t0, t1, t2, t3
                k += 4
            o0 = ((sbox[s0 >> 24] << 24) | (sbox[(s1 >> 16) & 255] << 16)
                  | (sbox[(s2 >> 8) & 255] << 8) | sbox[s3 & 255]) ^ w[k]
            o1 = ((sbox[s1 >> 24] << 24) | (sbox[(s2 >> 16) & 255] << 16)
                  | (sbox[(s3 >> 8) & 255] << 8) | sbox[s0 & 255]) ^ w[k + 1]
            o2 = ((sbox[s2 >> 24] << 24) | (sbox[(s3 >> 16) & 255] << 16)
                  | (sbox[(s0 >> 8) & 255] << 8) | sbox[s1 & 255]) ^ w[k + 2]
            o3 = ((sbox[s3 >> 24] << 24) | (sbox[(s0 >> 16) & 255] << 16)
                  | (sbox[(s1 >> 8) & 255] << 8) | sbox[s2 & 255]) ^ w[k + 3]
            return (o0 << 96) | (o1 << 64) | (o2 << 32) | o3

        return enc

    @staticmethod
    def _gf_mult(x, y):
        r = 0xE1 << 120
        z = 0
        v = y
        for i in range(127, -1, -1):
            if (x >> i) & 1:
                z ^= v
            v = (v >> 1) ^ r if v & 1 else v >> 1
        return z

    def _ghash_tables(self, h):
        tables = []
        for j in range(16):
            shift = 8 * (15 - j)
            tables.append([self._gf_mult(b << shift, h) for b in range(256)])
        return tables

    def _ghash(self, tables, data):
        y = 0
        n = len(data)
        for off in range(0, n, 16):
            chunk = data[off:off + 16]
            if len(chunk) < 16:
                chunk = chunk + b"\x00" * (16 - len(chunk))
            x = (y ^ int.from_bytes(chunk, "big")).to_bytes(16, "big")
            y = 0
            for j in range(16):
                y ^= tables[j][x[j]]
        length_block = (0).to_bytes(8, "big") + (n * 8).to_bytes(8, "big")
        x = (y ^ int.from_bytes(length_block, "big")).to_bytes(16, "big")
        y = 0
        for j in range(16):
            y ^= tables[j][x[j]]
        return y

    def _ctr(self, enc, j0, data):
        out = bytearray(len(data))
        prefix = j0 >> 32 << 32
        counter = j0 & 0xFFFFFFFF
        for off in range(0, len(data), 16):
            counter = (counter + 1) & 0xFFFFFFFF
            ks = enc(prefix | counter).to_bytes(16, "big")
            chunk = data[off:off + 16]
            m = len(chunk)
            val = int.from_bytes(chunk, "big") ^ int.from_bytes(ks[:m], "big")
            out[off:off + m] = val.to_bytes(m, "big")
        return bytes(out)

    def _setup(self, key, nonce):
        if len(nonce) != GCM_NONCE_SIZE:
            raise ValueError("only 96-bit nonces are supported")
        enc = self._encrypt_block_fn(key)
        h = enc(0)
        j0 = int.from_bytes(nonce + b"\x00\x00\x00\x01", "big")
        return enc, self._ghash_tables(h), j0

    def encrypt(self, key, nonce, plaintext):
        enc, tables, j0 = self._setup(key, nonce)
        ct = self._ctr(enc, j0, plaintext)
        tag = enc(j0) ^ self._ghash(tables, ct)
        return ct + tag.to_bytes(16, "big")

    def decrypt(self, key, nonce, data):
        if len(data) < GCM_TAG_SIZE:
            raise InvalidTag()
        ct, tag = data[:-GCM_TAG_SIZE], data[-GCM_TAG_SIZE:]
        enc, tables, j0 = self._setup(key, nonce)
        expect = (enc(j0) ^ self._ghash(tables, ct)).to_bytes(16, "big")
        if not hmac.compare_digest(expect, tag):
            raise InvalidTag()
        return self._ctr(enc, j0, ct)


_BACKEND_FACTORIES = (
    ("cryptography", _CryptographyBackend),
    ("libcrypto", _LibcryptoBackend),
    ("pure-python", _PurePythonBackend),
)
_backend_cache = {}


def get_crypto_backend(name=None):
    """Return the best available AES-GCM backend, or the named one."""
    order = [(n, f) for n, f in _BACKEND_FACTORIES if name in (None, n)]
    if not order:
        raise LagrangeError("unknown crypto backend: %s" % name)
    errors = []
    for n, factory in order:
        if n in _backend_cache:
            if _backend_cache[n] is not None:
                return _backend_cache[n]
            continue
        try:
            _backend_cache[n] = factory()
            return _backend_cache[n]
        except Exception as exc:  # noqa: BLE001 -- probe optional backends
            _backend_cache[n] = None
            errors.append("%s: %s" % (n, exc))
    raise LagrangeError("no AES-GCM backend available: " + "; ".join(errors))


def available_crypto_backends():
    out = []
    for n, _ in _BACKEND_FACTORIES:
        try:
            get_crypto_backend(n)
            out.append(n)
        except LagrangeError:
            pass
    return out


def encrypt_pb(plaintext, key=DEFAULT_PB_KEY, nonce=None, backend=None):
    nonce = nonce or os.urandom(GCM_NONCE_SIZE)
    backend = backend or get_crypto_backend()
    return nonce + backend.encrypt(key, nonce, plaintext)


def decrypt_pb(data, key=DEFAULT_PB_KEY, backend=None):
    """
    Decrypt a legacy trajectory file. Returns ``(plaintext, encrypted)``.
    Falls back to treating the file as an unencrypted protobuf when GCM
    authentication fails, mirroring the reference loader.
    """
    data = bytes(data)
    if len(data) >= GCM_NONCE_SIZE + GCM_TAG_SIZE:
        backend = backend or get_crypto_backend()
        try:
            return backend.decrypt(key, data[:GCM_NONCE_SIZE], data[GCM_NONCE_SIZE:]), True
        except InvalidTag:
            pass
    if ProtoFields.try_parse(data) is not None:
        return data, False
    raise LagrangeError("cannot decode .pb file (not AES-GCM and not protobuf)")


# ---------------------------------------------------------------------------
# URI and path normalization
# ---------------------------------------------------------------------------

_URI_CANDIDATE_RE = re.compile(r"(?:file|vscode-remote)://[^\x00-\x1f\x7f\"]*")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_DRIVE_RE = re.compile(r"^/?([A-Za-z]):(.*)$")


def _unquote_fully(text):
    for _ in range(4):
        if "%" not in text:
            break
        nxt = unquote(text)
        if nxt == text:
            break
        text = nxt
    return text


def _clean_path(path):
    path = path.replace("\\", "/")
    m = _DRIVE_RE.match(path)
    if m:
        rest = posixpath.normpath("/" + m.group(2).lstrip("/")) if m.group(2) else "/"
        return "/" + m.group(1).lower() + ":" + (rest if rest != "/" else "/")
    if not path.startswith("/"):
        path = "/" + path
    path = posixpath.normpath(path)
    if path.startswith("//"):
        path = "/" + path.lstrip("/")
    return path


def _encode_path(path):
    return quote(path, safe="/")


def normalize_uri(uri):
    """Return a canonical, single-encoded URI (``file:///a/b%20c``)."""
    if not uri:
        return ""
    uri = uri.strip()
    low = uri.lower()
    if low.startswith("file:"):
        rest = uri[5:]
        authority = ""
        if rest.startswith("//"):
            rest = rest[2:]
            slash = rest.find("/")
            if slash < 0:
                authority, rest = rest, "/"
            else:
                authority, rest = rest[:slash], rest[slash:]
        path = _clean_path(_unquote_fully(rest))
        return "file://" + authority.lower() + _encode_path(path)
    if low.startswith("vscode-remote://"):
        rest = uri[len("vscode-remote://"):]
        slash = rest.find("/")
        authority, path = (rest, "") if slash < 0 else (rest[:slash], rest[slash:])
        if path:
            path = posixpath.normpath(_unquote_fully(path))
            path = "" if path == "/" else _encode_path(path)
        return "vscode-remote://" + authority + path
    return uri


def is_local_path(text):
    return bool(text) and (text.startswith("/") or text.startswith("~")
                           or bool(re.match(r"^[A-Za-z]:[\\/]", text)))


def path_to_file_uri(path):
    """Convert a filesystem path (or an existing URI) to a canonical file URI."""
    if path is None:
        return ""
    path = str(path).strip()
    if not path:
        return ""
    if "://" in path:
        return normalize_uri(path)
    path = _unquote_fully(path)
    if path.startswith("~"):
        path = os.path.expanduser(path)
    if not is_local_path(path):
        path = os.path.abspath(path)
    return "file://" + _encode_path(_clean_path(path))


def file_uri_to_path(uri):
    """Convert a file URI to a path string. Returns ``None`` for other schemes."""
    if not uri:
        return None
    uri = normalize_uri(uri)
    if not uri.lower().startswith("file://"):
        return None
    rest = uri[7:]
    slash = rest.find("/")
    authority, path = (rest, "/") if slash < 0 else (rest[:slash], rest[slash:])
    path = _unquote_fully(path)
    m = re.match(r"^/([A-Za-z]):(.*)$", path)
    if m:
        path = m.group(1).upper() + ":" + (m.group(2) or "/")
    if authority:
        path = "//" + authority + path
    return path


def scrub_uri(value):
    """
    Recover a clean workspace URI from a possibly corrupted value.

    Older tools wrote raw protobuf bytes into URI strings, for example
    ``'file:///\\n#file:///Users/u/My Project\\x12\\x08file:///\\x1a\\x00'``.
    This returns the first non-root URI candidate, normalized, or ``""``.
    """
    if value is None:
        return ""
    if isinstance(value, (bytes, bytearray, memoryview)):
        value = bytes(value).decode("utf-8", "replace")
    value = value.strip()
    if not value:
        return ""
    candidates = _URI_CANDIDATE_RE.findall(value)
    if not candidates:
        if not _CONTROL_RE.search(value) and is_local_path(value):
            return path_to_file_uri(value)
        return ""
    for cand in candidates:
        cand = cand.strip()
        norm = normalize_uri(cand)
        if norm.lower().startswith("file://"):
            path = file_uri_to_path(norm)
            if not path or path == "/":
                continue
        elif norm.lower().startswith("vscode-remote://"):
            if norm.count("/") < 3:
                continue
        return norm
    return ""


def is_valid_workspace_uri(uri):
    if not uri or _CONTROL_RE.search(uri):
        return False
    low = uri.lower()
    if low.startswith("file://"):
        path = file_uri_to_path(uri)
        return bool(path) and path != "/"
    return low.startswith("vscode-remote://") and uri.count("/") >= 3


def path_is_under(path, root):
    if path is None or root is None:
        return False
    if root == "/":
        return path.startswith("/")
    return path == root or path.startswith(root.rstrip("/") + "/")


def find_git_root(path):
    """Return the nearest folder (``path`` or an ancestor) that contains ``.git``."""
    if not path:
        return None
    try:
        p = Path(path)
        if not p.exists():
            return None
        for d in [p] + list(p.parents):
            if (d / ".git").exists():
                return str(d)
    except OSError:
        return None
    return None


def read_git_branch(root):
    try:
        git = Path(root) / ".git"
        if git.is_file():
            text = git.read_text("utf-8", "replace").strip()
            if text.startswith("gitdir:"):
                gitdir = Path(text[7:].strip())
                if not gitdir.is_absolute():
                    gitdir = Path(root) / gitdir
                git = gitdir
        head = (git / "HEAD").read_text("utf-8", "replace").strip()
    except OSError:
        return ""
    if head.startswith("ref:"):
        ref = head[4:].strip()
        return ref[len("refs/heads/"):] if ref.startswith("refs/heads/") else ref
    return ""


# ---------------------------------------------------------------------------
# Path remapping (moved folders)
# ---------------------------------------------------------------------------

_BOUNDARY = r"(?=$|[/\\\s\"'<>()\[\]{}`,;|?#*:\x00-\x1f])"


class Remapper(object):
    """Applies ``old path -> new path`` rules to URIs, paths, and free text."""

    def __init__(self, rules=None):
        self.rules = []
        for old, new in rules or []:
            self.add(old, new)

    def add(self, old, new):
        old_p = file_uri_to_path(path_to_file_uri(old))
        new_p = file_uri_to_path(path_to_file_uri(new))
        if not old_p or not new_p or old_p == new_p:
            raise LagrangeError("invalid remap rule: %s -> %s" % (old, new))
        self.rules.append((old_p, new_p))
        self.rules.sort(key=lambda r: len(r[0]), reverse=True)
        self._text = None

    def __bool__(self):
        return bool(self.rules)

    __nonzero__ = __bool__

    def path(self, path):
        if not path:
            return path
        for old, new in self.rules:
            if path_is_under(new, old) and path_is_under(path, new):
                return path  # already remapped (new lives inside old)
            if path_is_under(path, old):
                return new + path[len(old):]
        return path

    def uri(self, uri):
        if not uri or not self.rules:
            return uri
        path = file_uri_to_path(uri)
        if path is None:
            return uri
        mapped = self.path(path)
        return uri if mapped == path else path_to_file_uri(mapped)

    def _text_rules(self):
        if self._text is None:
            self._text = []
            for old, new in self.rules:
                for o, n in ((old, new), (_encode_path(old), _encode_path(new))):
                    guard = ""
                    if path_is_under(n, o) and n != o:
                        guard = "(?!" + re.escape(n[len(o):]) + _BOUNDARY + ")"
                    pat = re.compile(re.escape(o) + guard + _BOUNDARY)
                    self._text.append((pat, n))
                    if o == n:
                        break
        return self._text

    def text(self, text):
        if not self.rules or not text:
            return text
        for pat, rep in self._text_rules():
            text = pat.sub(lambda _m, r=rep: r, text)
        return text

    def json_value(self, value):
        """Remap URIs/paths in a JSON value (keys and string values)."""
        if isinstance(value, dict):
            out = {}
            for k, v in value.items():
                nk = self.json_value(k) if isinstance(k, str) else k
                if nk in out:
                    continue
                out[nk] = self.json_value(v)
            return out
        if isinstance(value, list):
            return [self.json_value(v) for v in value]
        if isinstance(value, str):
            if value.lower().startswith("file://"):
                return self.uri(value)
            if is_local_path(value):
                return self.path(value)
            return self.text(value) if "file://" in value else value
        return value


def _is_printable_text(data):
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if re.search(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", text):
        return None
    return text


def rewrite_proto_strings(data, fn, depth=0):
    """
    Apply ``fn`` to every string inside a protobuf blob while keeping all
    length prefixes consistent. Returns the new bytes (or the input when
    nothing changed).
    """
    data = bytes(data)
    if depth > 40:
        return data
    msg = ProtoFields.try_parse(data) if data else None
    text = _is_printable_text(data)
    if msg is not None and len(msg) and (text is None or data[0] < 0x20):
        changed = False
        for f in msg.fields:
            if f.wt != WT_LEN or not f.value:
                continue
            new = rewrite_proto_strings(f.value, fn, depth + 1)
            if new != f.value:
                f.value, f.raw = new, None
                changed = True
        return msg.serialize() if changed else data
    if text is None:
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            return data
    new_text = fn(text)
    return data if new_text == text else new_text.encode("utf-8")


# ---------------------------------------------------------------------------
# Annotations (.pbtxt)
# ---------------------------------------------------------------------------

_PBTXT_TITLE_RE = re.compile(r'(^|[\s{])title\s*:\s*"((?:[^"\\\n]|\\.)*)"')
_PBTXT_ESCAPES = {"n": b"\n", "t": b"\t", "r": b"\r", '"': b'"', "'": b"'",
                  "\\": b"\\", "a": b"\a", "b": b"\b", "f": b"\f", "v": b"\v",
                  "?": b"?"}


def pbtxt_unescape(text):
    out = bytearray()
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch != "\\" or i + 1 >= n:
            out += ch.encode("utf-8")
            i += 1
            continue
        nxt = text[i + 1]
        if nxt in _PBTXT_ESCAPES:
            out += _PBTXT_ESCAPES[nxt]
            i += 2
        elif nxt in "01234567":
            j = i + 1
            while j < n and j < i + 4 and text[j] in "01234567":
                j += 1
            out.append(int(text[i + 1:j], 8) & 0xFF)
            i = j
        elif nxt in "xX":
            j = i + 2
            while j < n and j < i + 4 and text[j] in "0123456789abcdefABCDEF":
                j += 1
            out.append(int(text[i + 2:j] or "0", 16))
            i = j
        elif nxt in "uU":
            width = 4 if nxt == "u" else 8
            out += chr(int(text[i + 2:i + 2 + width], 16)).encode("utf-8")
            i += 2 + width
        else:
            out += nxt.encode("utf-8")
            i += 2
    return out.decode("utf-8", "replace")


def pbtxt_escape(text):
    out = []
    for ch in text:
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif ord(ch) < 0x20 or ord(ch) == 0x7F:
            out.append("\\%03o" % ord(ch))
        else:
            out.append(ch)
    return "".join(out)


def pbtxt_get_title(text):
    m = _PBTXT_TITLE_RE.search(text or "")
    return pbtxt_unescape(m.group(2)) if m else ""


def pbtxt_set_title(text, title):
    text = text or ""
    field = 'title:"%s"' % pbtxt_escape(title)
    m = _PBTXT_TITLE_RE.search(text)
    if m:
        return text[:m.start()] + m.group(1) + field + text[m.end():]
    rest = text.strip()
    return field + ("  " + rest if rest else "") + "\n"


def pbtxt_get_bool(text, name):
    m = re.search(r"(?:^|[\s{])" + re.escape(name) + r"\s*:\s*(true|false)\b", text or "")
    if not m:
        return None
    return m.group(1) == "true"


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def _now():
    return time.time()


def fmt_time(ts):
    if ts is None:
        return "-"
    try:
        return _dt.datetime.fromtimestamp(ts, _dt.timezone.utc).strftime("%Y-%m-%d %H:%M")
    except (OverflowError, OSError, ValueError):
        return "-"


def file_mtime(path):
    try:
        return os.stat(str(path)).st_mtime
    except OSError:
        return None


def trajectory_mtime(path):
    """Newer of ``<id>.db`` and ``<id>.db-wal`` (or the ``.pb`` mtime)."""
    best = file_mtime(path)
    if str(path).endswith(".db"):
        wal = file_mtime(str(path) + "-wal")
        if wal is not None and (best is None or wal > best):
            best = wal
    return best


def _snapshot_times(paths):
    snap = []
    for p in paths:
        try:
            st = os.stat(str(p))
            snap.append((str(p), st.st_atime, st.st_mtime))
        except OSError:
            pass
    return snap


def _restore_times(snap, extra_paths=(), fallback=None):
    done = set()
    for p, at, mt in snap:
        try:
            if os.path.exists(p):
                os.utime(p, (at, mt))
                done.add(p)
        except OSError:
            pass
    if fallback is not None:
        for p in extra_paths:
            p = str(p)
            if p not in done and os.path.exists(p):
                try:
                    os.utime(p, (fallback, fallback))
                except OSError:
                    pass


def atomic_write_bytes(path, data, mode=None, keep_times=False):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    snap = _snapshot_times([path]) if keep_times else []
    old_mode = None
    try:
        old_mode = os.stat(str(path)).st_mode & 0o777
    except OSError:
        pass
    fd, tmp = tempfile.mkstemp(prefix="." + path.name + ".", suffix=".lagrange-tmp",
                               dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        final_mode = old_mode if old_mode is not None else mode
        if final_mode is not None:
            os.chmod(tmp, final_mode)
        os.replace(tmp, str(path))
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    if snap:
        _restore_times(snap)


def atomic_write_text(path, text, mode=None):
    atomic_write_bytes(path, text.encode("utf-8"), mode=mode)


def b64decode_loose(text):
    if isinstance(text, (bytes, bytearray, memoryview)):
        text = bytes(text).decode("ascii", "ignore")
    text = "".join(text.split())
    pad = "=" * (-len(text) % 4)
    try:
        return base64.b64decode(text + pad, validate=True)
    except (ValueError, TypeError):
        try:
            return base64.urlsafe_b64decode(text + pad)
        except (ValueError, TypeError):
            return None


def b64encode_str(data):
    return base64.b64encode(data).decode("ascii")


def clean_title(text, limit=80):
    text = re.sub(r"\s+", " ", text or "").strip()
    if len(text) <= limit:
        return text
    cut = text[:limit - 1]
    space = cut.rfind(" ")
    if space > limit // 2:
        cut = cut[:space]
    return cut.rstrip(" ,;:.-") + "\u2026"


def is_valid_title(text):
    if not text or not text.strip():
        return False
    if len(text) > 500:
        return False
    return not re.search(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\ufffd]", text)


def short_id(cid):
    return cid[:8]


def _sqlite_open_ro(path):
    """Open SQLite read-only. Falls back to a temp copy for WAL databases."""
    path = Path(path)
    try:
        conn = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True, timeout=5)
        conn.execute("SELECT name FROM sqlite_master LIMIT 1").fetchall()
        return conn, None
    except sqlite3.Error:
        pass
    tmpdir = tempfile.mkdtemp(prefix="lagrange-ro-")
    for suffix in ("", "-wal", "-shm"):
        src = str(path) + suffix
        if os.path.exists(src):
            shutil.copy2(src, os.path.join(tmpdir, path.name + suffix))
    conn = sqlite3.connect(os.path.join(tmpdir, path.name), timeout=5)
    return conn, tmpdir


def _sqlite_close(conn, tmpdir):
    try:
        conn.close()
    finally:
        if tmpdir:
            shutil.rmtree(tmpdir, ignore_errors=True)


def _sqlite_tables(conn):
    return {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}


# ---------------------------------------------------------------------------
# Trajectory loading
# ---------------------------------------------------------------------------


class TrajectoryInfo(object):
    def __init__(self, path, kind):
        self.path = Path(path)
        self.kind = kind
        self.trajectory_id = ""
        self.cascade_id = ""
        self.trajectory_type = 0
        self.source = 0
        self.metadata = ProtoFields()
        self.metadata_raw = b""
        self.step_count = 0
        self.last_user_input_index = None
        self.last_user_input_time = None
        self.first_step_time = None
        self.last_step_time = None
        self.checkpoint_intent = ""
        self.first_prompt = ""
        self.user_texts = []
        self.pb_encrypted = None
        self.pb_trajectory = None
        self.error = None


def _step_times(meta_msg):
    times = []
    if meta_msg is None:
        return times
    for num in STEP_META_TIMESTAMPS:
        t = ts_to_float(meta_msg.get_msg(num))
        if t:
            times.append(t)
    return times


def _user_text_from_step(step):
    ui = step.get_msg(StepF.USER_INPUT)
    if ui is None:
        return ""
    return ui.get_str(USER_INPUT_RESPONSE).strip()


def _intent_from_step(step):
    cp = step.get_msg(StepF.CHECKPOINT)
    if cp is None:
        return ""
    return cp.get_str(CHECKPOINT_USER_INTENT).strip()


def _first_multiword(texts):
    for t in texts:
        if len(t.split()) >= 2:
            return t
    return texts[0] if texts else ""


def load_db_info(path):
    info = TrajectoryInfo(path, "db")
    try:
        if os.path.getsize(str(path)) == 0:
            info.error = "empty file"
            return info
    except OSError as exc:
        info.error = str(exc)
        return info
    try:
        conn, tmp = _sqlite_open_ro(path)
    except sqlite3.Error as exc:
        info.error = "sqlite: %s" % exc
        return info
    try:
        tables = _sqlite_tables(conn)
        if "trajectory_meta" in tables:
            row = conn.execute("SELECT trajectory_id, cascade_id, trajectory_type, source "
                               "FROM trajectory_meta LIMIT 1").fetchone()
            if row:
                info.trajectory_id = row[0] or ""
                info.cascade_id = row[1] or ""
                info.trajectory_type = int(row[2] or 0)
                info.source = int(row[3] or 0)
        if "trajectory_metadata_blob" in tables:
            row = conn.execute("SELECT data FROM trajectory_metadata_blob WHERE id='main'").fetchone()
            if row and row[0] is not None:
                info.metadata_raw = bytes(row[0])
                parsed = ProtoFields.try_parse(info.metadata_raw)
                if parsed is None:
                    info.error = "unparseable trajectory metadata"
                else:
                    info.metadata = parsed
        if "steps" in tables:
            row = conn.execute("SELECT COUNT(*) FROM steps").fetchone()
            info.step_count = int(row[0] or 0)
            row = conn.execute("SELECT metadata FROM steps ORDER BY idx ASC LIMIT 1").fetchone()
            if row and row[0]:
                t = _step_times(ProtoFields.try_parse(bytes(row[0])))
                info.first_step_time = min(t) if t else None
            for row in conn.execute("SELECT metadata FROM steps WHERE step_type != ? "
                                    "ORDER BY idx DESC LIMIT 3", (STEP_TYPE_CHECKPOINT,)):
                t = _step_times(ProtoFields.try_parse(bytes(row[0] or b"")))
                if t:
                    info.last_step_time = max(t)
                    break
            row = conn.execute("SELECT idx, metadata FROM steps WHERE step_type=? "
                               "ORDER BY idx DESC LIMIT 1", (STEP_TYPE_USER_INPUT,)).fetchone()
            if row:
                info.last_user_input_index = int(row[0])
                meta = ProtoFields.try_parse(bytes(row[1] or b""))
                if meta is not None:
                    info.last_user_input_time = ts_to_float(meta.get_msg(1))
            for row in conn.execute("SELECT step_payload FROM steps WHERE step_type=? "
                                    "ORDER BY idx LIMIT 40", (STEP_TYPE_USER_INPUT,)):
                step = ProtoFields.try_parse(bytes(row[0] or b""))
                if step is not None:
                    text = _user_text_from_step(step)
                    if text:
                        info.user_texts.append(text)
            for row in conn.execute("SELECT step_payload FROM steps WHERE step_type=? "
                                    "ORDER BY idx LIMIT 5", (STEP_TYPE_CHECKPOINT,)):
                step = ProtoFields.try_parse(bytes(row[0] or b""))
                if step is not None:
                    intent = _intent_from_step(step)
                    if intent:
                        info.checkpoint_intent = intent
                        break
        info.first_prompt = _first_multiword(info.user_texts)
    except sqlite3.Error as exc:
        info.error = "sqlite: %s" % exc
    finally:
        _sqlite_close(conn, tmp)
    return info


def load_pb_info(path, keep_trajectory=False):
    info = TrajectoryInfo(path, "pb")
    try:
        data = Path(path).read_bytes()
        plain, encrypted = decrypt_pb(data)
        traj = ProtoFields.parse(plain)
    except (OSError, LagrangeError, ProtoError) as exc:
        info.error = str(exc)
        return info
    info.pb_encrypted = encrypted
    if keep_trajectory:
        info.pb_trajectory = traj
    info.trajectory_id = traj.get_str(TrajectoryF.TRAJECTORY_ID)
    info.cascade_id = traj.get_str(TrajectoryF.CASCADE_ID)
    info.trajectory_type = traj.get_int(TrajectoryF.TRAJECTORY_TYPE)
    info.source = traj.get_int(TrajectoryF.SOURCE)
    meta_raw = traj.get(TrajectoryF.METADATA, None, WT_LEN)
    if meta_raw is not None:
        info.metadata_raw = bytes(meta_raw)
        info.metadata = ProtoFields.try_parse(meta_raw) or ProtoFields()
    steps = traj.get_all(TrajectoryF.STEPS, WT_LEN)
    info.step_count = len(steps)
    for idx, raw in enumerate(steps):
        step = ProtoFields.try_parse(raw)
        if step is None:
            continue
        stype = step.get_int(StepF.TYPE)
        meta = step.get_msg(StepF.METADATA)
        times = _step_times(meta)
        if times:
            if info.first_step_time is None:
                info.first_step_time = min(times)
            if stype != STEP_TYPE_CHECKPOINT:
                info.last_step_time = max(times)
        if stype == STEP_TYPE_USER_INPUT or step.has(StepF.USER_INPUT):
            info.last_user_input_index = idx
            if meta is not None:
                info.last_user_input_time = ts_to_float(meta.get_msg(1))
            text = _user_text_from_step(step)
            if text and len(info.user_texts) < 40:
                info.user_texts.append(text)
        if not info.checkpoint_intent and (stype == STEP_TYPE_CHECKPOINT or step.has(StepF.CHECKPOINT)):
            info.checkpoint_intent = _intent_from_step(step)
    info.first_prompt = _first_multiword(info.user_texts)
    return info


def load_trajectory(path, kind, keep_trajectory=False):
    if kind == "db":
        return load_db_info(path)
    return load_pb_info(path, keep_trajectory=keep_trajectory)


def db_step_count(path):
    try:
        if os.path.getsize(str(path)) == 0:
            return -1
        conn, tmp = _sqlite_open_ro(path)
    except (OSError, sqlite3.Error):
        return -1
    try:
        return int(conn.execute("SELECT COUNT(*) FROM steps").fetchone()[0] or 0)
    except sqlite3.Error:
        return -1
    finally:
        _sqlite_close(conn, tmp)


# ---------------------------------------------------------------------------
# Environment
# ---------------------------------------------------------------------------

SURFACES = ("hub", "ide", "cli")
SURFACE_DIR_NAMES = {"hub": "antigravity", "ide": "antigravity-ide", "cli": "antigravity-cli"}
APP_SURFACES = (("Antigravity", "hub"), ("Antigravity IDE", "ide"))
LINKABLE_SUBDIRS = ("conversations", "brain", "annotations")


class Env(object):
    """Resolved locations of every store Lagrange reads or writes."""

    def __init__(self, home=None, platform=None, config_root=None):
        explicit_home = home is not None or bool(os.environ.get("LAGRANGE_HOME"))
        self.home = Path(home or os.environ.get("LAGRANGE_HOME") or Path.home())
        self.platform = platform or sys.platform
        self.gemini = self.home / ".gemini"
        self.surface_dirs = {s: self.gemini / d for s, d in SURFACE_DIR_NAMES.items()}
        self.projects_dir = self.gemini / "config" / "projects"
        self.backup_root = self.gemini / "lagrange_backups"
        if config_root is not None:
            self.config_root = Path(config_root)
        elif self.platform == "darwin":
            self.config_root = self.home / "Library" / "Application Support"
        elif self.platform.startswith("win"):
            appdata = os.environ.get("APPDATA")
            self.config_root = Path(appdata) if appdata and not explicit_home \
                else self.home / "AppData" / "Roaming"
        else:
            xdg = os.environ.get("XDG_CONFIG_HOME")
            self.config_root = Path(xdg) if xdg and not explicit_home else self.home / ".config"

    @property
    def hub(self):
        return self.surface_dirs["hub"]

    def conv_dir(self, surface):
        return self.surface_dirs[surface] / "conversations"

    def brain_dir(self, surface):
        return self.surface_dirs[surface] / "brain"

    def ann_dir(self, surface):
        return self.surface_dirs[surface] / "annotations"

    def app_user_dir(self, app_name):
        return self.config_root / app_name / "User"

    def state_db(self, app_name):
        return self.app_user_dir(app_name) / "globalStorage" / "state.vscdb"

    def cli_cache(self):
        return self.surface_dirs["cli"] / "cache"


PROCESS_HINTS = ("antigravity", "language_server")


def find_running_processes():
    """Return ``[(pid, name)]`` for running Antigravity apps, servers, and CLIs."""
    me = os.getpid()
    found = []
    try:
        if os.name == "nt":
            out = subprocess.run(["tasklist", "/fo", "csv", "/nh"], capture_output=True,
                                 text=True, timeout=15).stdout
            for line in out.splitlines():
                parts = [p.strip('"') for p in line.split('","')]
                if len(parts) >= 2:
                    name = parts[0].strip('"')
                    if any(h in name.lower() for h in PROCESS_HINTS):
                        found.append((int(parts[1]) if parts[1].isdigit() else 0, name))
        else:
            out = subprocess.run(["ps", "-axo", "pid=,comm="], capture_output=True,
                                 text=True, timeout=15).stdout
            for line in out.splitlines():
                line = line.strip()
                if not line:
                    continue
                pid_s, _, comm = line.partition(" ")
                base = os.path.basename(comm.strip()).lower()
                if not pid_s.isdigit() or int(pid_s) == me:
                    continue
                if "lagrange" in base or base.startswith("python"):
                    continue
                if any(h in comm.lower() for h in PROCESS_HINTS):
                    found.append((int(pid_s), comm.strip()))
    except (OSError, subprocess.SubprocessError):
        return []
    return found


# ---------------------------------------------------------------------------
# Model objects
# ---------------------------------------------------------------------------


class TrajFile(object):
    def __init__(self, surface, kind, path):
        self.surface = surface
        self.kind = kind
        self.path = Path(path)
        try:
            self.size = os.path.getsize(str(path))
        except OSError:
            self.size = 0
        self.mtime = trajectory_mtime(path) or 0.0
        self._steps = None

    @property
    def steps(self):
        if self._steps is None:
            self._steps = db_step_count(self.path) if self.kind == "db" else -1
        return self._steps

    def companions(self):
        if self.kind != "db":
            return [self.path]
        return [Path(str(self.path) + s) for s in ("", "-wal", "-shm")
                if os.path.exists(str(self.path) + s)]

    def __repr__(self):
        return "TrajFile(%s, %s, %s)" % (self.surface, self.kind, self.path)


class Conversation(object):
    def __init__(self, cid):
        self.id = cid
        self.files = []
        self.brains = {}
        self.annotations = {}
        self.chosen = None
        self.info = None
        # Resolved state
        self.workspace_uri = ""
        self.workspace_source = ""
        self.extra_workspaces = []
        self.project_id = ""
        self.title = ""
        self.title_source = ""
        self.override_workspace = None
        self.override_project = None
        self.override_title = None
        self.new_metadata = None

    @property
    def metadata(self):
        return self.info.metadata if self.info else ProtoFields()

    @property
    def parent_id(self):
        return self.metadata.get_str(MetaF.PARENT_CONVERSATION_ID)

    @property
    def is_subagent(self):
        if self.parent_id:
            return True
        if self.info and self.info.trajectory_type == TRAJECTORY_TYPE_SUBAGENT:
            return True
        return self.metadata.get_int(MetaF.NESTING_DEPTH) > 0

    @property
    def surfaces(self):
        out = []
        for f in self.files:
            if f.surface not in out:
                out.append(f.surface)
        return out

    def file_in(self, surface):
        for f in self.files:
            if f.surface == surface and f is self.chosen:
                return f
        for f in self.files:
            if f.surface == surface and f.size > 0:
                return f
        return None

    def current_workspaces(self):
        md = self.metadata
        uris = list(md.get_strs(MetaF.WORKSPACE_URIS))
        for ws in md.get_msgs(MetaF.WORKSPACES):
            uris.append(ws.get_str(WsF.FOLDER_URI))
        return uris


class Project(object):
    def __init__(self, path, data):
        self.path = Path(path)
        self.data = data
        self.id = data.get("id") or self.path.stem
        self.removed = False
        self.dirty = False
        self.created = False

    @property
    def name(self):
        return self.data.get("name") or ""

    @name.setter
    def name(self, value):
        self.data["name"] = value
        self.dirty = True

    def resources(self):
        res = (self.data.get("projectResources") or {}).get("resources") or []
        return res if isinstance(res, list) else []

    def folder_uris(self):
        out = []
        for r in self.resources():
            if not isinstance(r, dict):
                continue
            uri = r.get("folderUri")
            if not isinstance(uri, str):
                gf = r.get("gitFolder")
                uri = gf.get("folderUri") if isinstance(gf, dict) else None
            if isinstance(uri, str) and uri:
                norm = scrub_uri(uri) or normalize_uri(uri)
                if norm and norm not in out:
                    out.append(norm)
        return out

    @property
    def primary_uri(self):
        uris = self.folder_uris()
        return uris[0] if uris else ""

    def map_resource_uris(self, fn):
        changed = False
        for r in self.resources():
            if not isinstance(r, dict):
                continue
            holder, key = (r, "folderUri") if isinstance(r.get("folderUri"), str) else (
                (r.get("gitFolder"), "folderUri") if isinstance(r.get("gitFolder"), dict) else (None, None))
            if holder is None or not isinstance(holder.get(key), str):
                continue
            new = fn(holder[key])
            if new and new != holder[key]:
                holder[key] = new
                changed = True
        if changed:
            self.dirty = True
        return changed

    def add_resource(self, uri):
        path = file_uri_to_path(uri)
        git = find_git_root(path) if path else None
        entry = {"gitFolder": {"folderUri": uri}} if git == path and path else {"folderUri": uri}
        self.data.setdefault("projectResources", {}).setdefault("resources", []).append(entry)
        self.dirty = True

    def _find_key(self, obj, key):
        if isinstance(obj, dict):
            for k, v in obj.items():
                if k == key and v:
                    return True
                if self._find_key(v, key):
                    return True
        elif isinstance(obj, list):
            return any(self._find_key(v, key) for v in obj)
        return False

    def richness(self):
        score = 0
        if self._find_key(self.data, "allowWrite"):
            score += 4
        if self._find_key(self.data.get("permissionGrants") or {}, "v2Migrated"):
            score += 2
        if self.data.get("settings"):
            score += 2
        return score

    def name_is_pathlike(self):
        return is_local_path(self.name) or "://" in self.name or not self.name

    def to_json(self):
        return json.dumps(self.data, indent=2, ensure_ascii=False) + "\n"


def new_project_data(name, uri):
    path = file_uri_to_path(uri)
    git = find_git_root(path) if path else None
    resource = {"gitFolder": {"folderUri": uri}} if git and git == path else {"folderUri": uri}
    return {
        "id": str(uuid.uuid4()),
        "name": name,
        "projectResources": {"resources": [resource]},
        "settings": {},
        "isWorkspaceOnly": False,
    }


def clean_project_name(name, uri, home):
    """Turn path-like project names into readable names."""
    path = file_uri_to_path(uri) or (name if is_local_path(name) else "")
    if path and os.path.normpath(path) == os.path.normpath(str(home)):
        return "Home"
    base = posixpath.basename((path or name).rstrip("/"))
    return base or name


# ---------------------------------------------------------------------------
# State databases (state.vscdb)
# ---------------------------------------------------------------------------


def parse_topic(value):
    """Decode ``base64(UssTopic)``. Returns ``[(key, row)]`` or ``None``."""
    if value is None:
        return None
    raw = b64decode_loose(value)
    if raw is None:
        return None
    topic = ProtoFields.try_parse(raw)
    if topic is None:
        return None
    rows = []
    for key, _, entry in map_entries(topic, USS_TOPIC_DATA):
        row = entry.get_msg(2) or ProtoFields()
        rows.append((key, row))
    return rows


def build_topic(rows):
    topic = ProtoFields()
    for key, row in rows:
        topic.append(USS_TOPIC_DATA, make_map_entry(key, row))
    return b64encode_str(topic.serialize())


def row_inner(row):
    inner_b64 = row.get_str(USS_ROW_VALUE, None)
    if not inner_b64:
        return None
    raw = b64decode_loose(inner_b64)
    return ProtoFields.try_parse(raw) if raw is not None else None


def row_with_inner(row, inner):
    row = row.copy() if row is not None else ProtoFields()
    row.set(USS_ROW_VALUE, b64encode_str(inner.serialize()))
    return row


class StateDb(object):
    def __init__(self, app_name, surface, path):
        self.app_name = app_name
        self.surface = surface
        self.path = Path(path)
        self.items = {}
        self.error = None
        self._load()

    def _load(self):
        try:
            conn, tmp = _sqlite_open_ro(self.path)
        except sqlite3.Error as exc:
            self.error = str(exc)
            return
        try:
            for key in (USS_TRAJECTORY_KEY, USS_SIDEBAR_KEY, LEGACY_INIT_STATE_KEY):
                row = conn.execute("SELECT value FROM ItemTable WHERE key=?", (key,)).fetchone()
                if row is not None:
                    val = row[0]
                    if isinstance(val, (bytes, memoryview)):
                        val = bytes(val).decode("utf-8", "replace")
                    self.items[key] = val
        except sqlite3.Error as exc:
            self.error = str(exc)
        finally:
            _sqlite_close(conn, tmp)

    def summaries(self):
        out = {}
        for key, row in parse_topic(self.items.get(USS_TRAJECTORY_KEY)) or []:
            inner = row_inner(row)
            if inner is not None:
                out[key] = inner
        return out

    def init_state(self):
        val = self.items.get(LEGACY_INIT_STATE_KEY)
        if not val:
            return None
        raw = b64decode_loose(val)
        return ProtoFields.try_parse(raw) if raw else None

    def init_state_summaries(self):
        st = self.init_state()
        out = {}
        if st is None:
            return out
        container = st.get_msg(INIT_STATE_SUMMARIES)
        for key, val, _ in map_entries(container, 1):
            msg = ProtoFields.try_parse(val) if isinstance(val, bytes) else None
            if msg is not None:
                out[key] = msg
        return out

    def write_items(self, updates):
        conn = sqlite3.connect(str(self.path), timeout=10)
        try:
            with conn:
                for key, value in updates.items():
                    cur = conn.execute("UPDATE ItemTable SET value=? WHERE key=?", (value, key))
                    if cur.rowcount == 0:
                        conn.execute("INSERT INTO ItemTable (key, value) VALUES (?, ?)", (key, value))
        finally:
            conn.close()
        self.items.update(updates)


# ---------------------------------------------------------------------------
# The reconciler
# ---------------------------------------------------------------------------


class SyncOptions(object):
    def __init__(self, **kw):
        self.remaps = kw.get("remaps") or []
        self.assign = kw.get("assign") or {}
        self.merge_projects = kw.get("merge_projects") or []
        self.rename_projects = kw.get("rename_projects") or []
        self.auto_create_projects = kw.get("auto_create_projects", False)
        self.prune_empty = kw.get("prune_empty", False)
        self.link_surfaces = kw.get("link_surfaces", True)
        self.link_cli = kw.get("link_cli", False)
        self.rewrite_deep_paths = kw.get("rewrite_deep_paths", False)
        self.write_annotations = kw.get("write_annotations", False)
        self.backfill_annotations = kw.get("backfill_annotations", True)
        self.clean_project_names = kw.get("clean_project_names", True)
        self.merge_stale_subprojects = kw.get("merge_stale_subprojects", False)
        self.consolidate = kw.get("consolidate", True)


class Lagrange(object):
    def __init__(self, env=None, out=None, dry_run=False, force=False, verbose=False):
        self.env = env or Env()
        self._out = out or (lambda s: print(s))
        self.dry_run = dry_run
        self.force = force
        self.verbose = verbose
        self.actions = []
        self.warnings = []
        self.backup_dir = None
        self.manifest = []
        self.remap = Remapper()
        self.convs = {}
        self.projects = {}
        self.merge_map = {}
        self.state_dbs = []
        self.hub_summaries = {}
        self.hub_file_mod_times = {}
        self.cli_summaries = {}
        self.symlinked = {}
        self.surface_alias = {}
        self.anomalies = []

    # -- output -----------------------------------------------------------
    def say(self, msg=""):
        self._out(msg)

    def act(self, desc, fn=None):
        prefix = "[dry-run] " if self.dry_run else ""
        self.actions.append(desc)
        if self.verbose or self.dry_run:
            self.say("  " + prefix + desc)
        if not self.dry_run and fn is not None:
            return fn()
        return None

    def warn(self, msg):
        self.warnings.append(msg)
        self.say("  ! " + msg)

    # -- safety -----------------------------------------------------------
    def ensure_safe(self):
        if self.dry_run or self.force:
            return
        procs = find_running_processes()
        if procs:
            listing = ", ".join("%s (pid %s)" % (n, p) for p, n in procs[:8])
            raise LagrangeError(
                "Antigravity appears to be running: %s.\nClose every Antigravity window, "
                "language server, and CLI session, or pass --force." % listing)

    def ensure_backup_dir(self):
        if self.backup_dir is None:
            stamp = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
            base = self.env.backup_root / stamp
            path = base
            i = 1
            while path.exists():
                path = Path("%s-%d" % (base, i))
                i += 1
            self.backup_dir = path
            if not self.dry_run:
                path.mkdir(parents=True, exist_ok=True)
        return self.backup_dir

    def _backup_rel(self, path):
        path = Path(path)
        try:
            rel = path.resolve().relative_to(self.env.home.resolve())
        except ValueError:
            rel = Path(*[p for p in path.parts if p not in (os.sep, "/")]) \
                if path.is_absolute() else path
            rel = Path("_abs") / rel
        return self.ensure_backup_dir() / rel

    def backup_file(self, path):
        path = Path(path)
        if self.dry_run or not path.exists() or path.is_dir():
            return None
        dest = self._backup_rel(path)
        if dest.exists():
            return dest
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(str(path), str(dest))
        return dest

    def stash(self, path, reason=""):
        """Move a file or directory into the backup folder instead of deleting it."""
        path = Path(path)
        if not os.path.lexists(str(path)):
            return None
        dest = self._backup_rel(path)

        def run():
            if dest.exists():
                alt = Path(str(dest) + ".%d" % int(_now() * 1000))
                target = alt
            else:
                target = dest
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(path), str(target))
            self.manifest.append({"op": "stash", "src": str(path), "dst": str(target),
                                  "reason": reason})
            return target

        return self.act("stash %s%s" % (path, (" (%s)" % reason) if reason else ""), run)

    def write_manifest(self):
        if self.dry_run or self.backup_dir is None:
            return
        data = {"version": __version__, "time": _dt.datetime.now().isoformat(),
                "actions": self.actions, "operations": self.manifest,
                "warnings": self.warnings}
        try:
            self.backup_dir.mkdir(parents=True, exist_ok=True)
            atomic_write_text(self.backup_dir / "manifest.json", json.dumps(data, indent=2))
        except OSError:
            pass

    def backup_indexes(self):
        """Back up every index store before any write."""
        targets = []
        for s in SURFACES:
            root = self.env.surface_dirs[s]
            for name in (HUB_SUMMARIES_FILE, SUMMARIES_DB_FILE, SUMMARIES_DB_FILE + "-wal",
                         SUMMARIES_DB_FILE + "-shm"):
                targets.append(root / name)
        if self.env.projects_dir.is_dir():
            targets.extend(sorted(self.env.projects_dir.glob("*.json")))
        for app, _ in APP_SURFACES:
            user = self.env.app_user_dir(app)
            targets.append(user / "globalStorage" / "state.vscdb")
            targets.append(user / "globalStorage" / "storage.json")
        cache = self.env.cli_cache()
        if cache.is_dir():
            targets.extend(sorted(cache.glob("*.json")))
        count = 0
        for t in targets:
            if t.exists():
                count += 1
                self.backup_file(t)
        if not self.dry_run:
            self.say("Backup: %s (%d index files)" % (self.ensure_backup_dir(), count))
        else:
            self.say("[dry-run] would back up %d index files to %s" % (count, self.ensure_backup_dir()))

    # -- scanning ---------------------------------------------------------
    def scan(self):
        self.convs = {}
        self.symlinked = {}
        self.anomalies = []
        seen_real = {}
        for surface in SURFACES:
            root = self.env.surface_dirs[surface]
            for sub in LINKABLE_SUBDIRS:
                d = root / sub
                if d.is_symlink():
                    self.symlinked[(surface, sub)] = os.path.realpath(str(d))
            if surface != "hub" and self.symlinked.get((surface, "conversations")) == \
                    os.path.realpath(str(self.env.conv_dir("hub"))):
                self.surface_alias[surface] = "hub"
            cdir = self.env.conv_dir(surface)
            if not cdir.is_dir():
                continue
            for p in sorted(cdir.iterdir()):
                name = p.name
                if name.endswith(".db"):
                    kind, cid = "db", name[:-3]
                elif name.endswith(".pb"):
                    kind, cid = "pb", name[:-3]
                else:
                    continue
                if not cid or "." in cid or not p.is_file():
                    continue
                real = os.path.realpath(str(p))
                if real in seen_real:
                    continue
                seen_real[real] = surface
                conv = self.convs.setdefault(cid, Conversation(cid))
                conv.files.append(TrajFile(surface, kind, p))
        for surface in SURFACES:
            bdir = self.env.brain_dir(surface)
            if bdir.is_dir():
                for p in bdir.iterdir():
                    if p.is_dir() and p.name in self.convs:
                        real = os.path.realpath(str(p))
                        if real not in [os.path.realpath(str(x)) for x in self.convs[p.name].brains.values()]:
                            self.convs[p.name].brains[surface] = p
            adir = self.env.ann_dir(surface)
            if adir.is_dir():
                for p in adir.glob("*.pbtxt"):
                    cid = p.name[:-len(".pbtxt")]
                    if cid in self.convs:
                        real = os.path.realpath(str(p))
                        if real not in [os.path.realpath(str(x)) for x in self.convs[cid].annotations.values()]:
                            self.convs[cid].annotations[surface] = p
        for conv in self.convs.values():
            conv.chosen = self.choose_file(conv)
            if conv.chosen is not None:
                conv.info = load_trajectory(conv.chosen.path, conv.chosen.kind)
                if conv.info.error:
                    self.anomalies.append("%s: cannot read %s (%s)" % (
                        short_id(conv.id), conv.chosen.path.name, conv.info.error))
        self.load_projects()
        self.load_indexes()

    @staticmethod
    def choose_file(conv):
        dbs = [f for f in conv.files if f.kind == "db" and f.size > 0]
        if dbs:
            return max(dbs, key=lambda f: (f.steps, f.mtime, f.surface == "hub"))
        pbs = [f for f in conv.files if f.kind == "pb" and f.size > 0]
        if pbs:
            return max(pbs, key=lambda f: (f.size, f.mtime, f.surface == "hub"))
        return None

    def load_projects(self):
        self.projects = {}
        pdir = self.env.projects_dir
        if not pdir.is_dir():
            return
        for p in sorted(pdir.glob("*.json")):
            try:
                data = json.loads(p.read_text("utf-8"))
                if not isinstance(data, dict):
                    raise ValueError("not an object")
            except (OSError, ValueError) as exc:
                self.anomalies.append("project file %s is unreadable (%s)" % (p.name, exc))
                continue
            proj = Project(p, data)
            self.projects[proj.id] = proj

    def load_indexes(self):
        self.hub_summaries = {}
        self.hub_file_mod_times = {}
        path = self.env.hub / HUB_SUMMARIES_FILE
        self.hub_summaries, self.hub_file_mod_times = self._read_summaries_state(path)
        self.cli_summaries, _ = self._read_summaries_state(
            self.env.surface_dirs["cli"] / HUB_SUMMARIES_FILE)
        self.state_dbs = []
        for app, surface in APP_SURFACES:
            p = self.env.state_db(app)
            if p.exists():
                db = StateDb(app, surface, p)
                if db.error:
                    self.anomalies.append("%s state.vscdb unreadable: %s" % (app, db.error))
                self.state_dbs.append(db)

    def _read_summaries_state(self, path):
        sums, mods = {}, {}
        if not path.exists():
            return sums, mods
        try:
            state = ProtoFields.parse(path.read_bytes())
        except (OSError, ProtoError) as exc:
            self.anomalies.append("%s is unreadable (%s)" % (path, exc))
            return sums, mods
        for key, val, _ in map_entries(state, StateF.SUMMARIES):
            msg = ProtoFields.try_parse(val) if isinstance(val, bytes) else ProtoFields()
            if msg is not None:
                sums[key] = msg
        for key, val, _ in map_entries(state, StateF.FILE_MOD_TIMES):
            if isinstance(val, int):
                mods[key] = to_signed64(val)
        return sums, mods

    # -- lookups ----------------------------------------------------------
    def active_projects(self):
        return [p for p in self.projects.values() if not p.removed]

    def resolve_conversation(self, token):
        token = token.strip()
        if token in self.convs:
            return self.convs[token]
        matches = [c for c in self.convs.values() if c.id.startswith(token)]
        if len(matches) == 1:
            return matches[0]
        if not matches:
            low = token.lower()
            matches = [c for c in self.convs.values() if (c.title or self.peek_title(c)).lower() == low]
            if len(matches) == 1:
                return matches[0]
        if not matches:
            raise LagrangeError("no conversation matches %r" % token)
        raise LagrangeError("%r is ambiguous: %s" % (token, ", ".join(short_id(c.id) for c in matches[:10])))

    def resolve_project(self, token, allow_none=False):
        token = token.strip()
        projs = self.active_projects()
        for p in projs:
            if p.id == token:
                return p
        cands = [p for p in projs if len(token) >= 4 and p.id.startswith(token)]
        if len(cands) == 1:
            return cands[0]
        if not cands:
            cands = [p for p in projs if p.name.lower() == token.lower()]
            if len(cands) == 1:
                return cands[0]
        if not cands:
            if allow_none:
                return None
            raise LagrangeError("no project matches %r" % token)
        raise LagrangeError("%r matches several projects: %s" % (
            token, ", ".join("%s (%s)" % (p.name, p.id[:8]) for p in cands)))

    def project_for_uri(self, uri):
        path = file_uri_to_path(uri)
        home = os.path.normpath(str(self.env.home))
        best, best_len = None, -1
        for proj in self.active_projects():
            for fu in proj.folder_uris():
                fp = file_uri_to_path(fu)
                if path is None or fp is None:
                    if fu == uri and len(fu) > best_len:
                        best, best_len = proj, len(fu)
                    continue
                exact = path == fp
                # The home folder and the filesystem root only match exactly:
                # they are catch-all folders, not project roots.
                catch_all = fp in ("/",) or os.path.normpath(fp) == home or re.match(r"^[A-Za-z]:/?$", fp)
                if exact or (not catch_all and path_is_under(path, fp)):
                    if len(fp) > best_len:
                        best, best_len = proj, len(fp)
        return best

    def follow_merge(self, pid):
        seen = set()
        while pid in self.merge_map and pid not in seen:
            seen.add(pid)
            pid = self.merge_map[pid]
        return pid

    def resolve_project_id(self, uri, existing, explicit=False):
        proj = self.project_for_uri(uri) if uri else None
        if proj is not None:
            return proj.id
        if explicit:
            return OUTSIDE_PROJECT
        mapped = self.follow_merge(existing)
        if mapped in self.projects and not self.projects[mapped].removed:
            return mapped
        if existing in ("", OUTSIDE_PROJECT):
            return existing
        return ""

    def children_of(self, cid):
        out = []
        frontier = [cid]
        seen = {cid}
        while frontier:
            cur = frontier.pop()
            for c in self.convs.values():
                if c.id not in seen and c.parent_id == cur:
                    seen.add(c.id)
                    out.append(c)
                    frontier.append(c.id)
        return out

    def root_of(self, conv):
        seen = set()
        cur = conv
        while cur.parent_id and cur.parent_id in self.convs and cur.id not in seen:
            seen.add(cur.id)
            cur = self.convs[cur.parent_id]
        return cur

    # -- existing index data ----------------------------------------------
    def existing_summaries(self, cid):
        """Existing summaries, best first: Hub, CLI, IDE state databases."""
        out = []
        if cid in self.hub_summaries:
            out.append(("hub", self.hub_summaries[cid]))
        if cid in self.cli_summaries:
            out.append(("cli", self.cli_summaries[cid]))
        for db in self.state_dbs:
            s = db.summaries().get(cid)
            if s is not None:
                out.append((db.app_name, s))
        return out

    def annotation_text(self, conv):
        for surface in ("hub", "ide", "cli"):
            p = conv.annotations.get(surface)
            if p is not None:
                try:
                    return p.read_text("utf-8")
                except OSError:
                    continue
        return ""

    def brain_heading(self, conv):
        for surface in ("hub", "ide", "cli"):
            bdir = conv.brains.get(surface)
            if bdir is None:
                continue
            for name in ("task.md", "implementation_plan.md", "walkthrough.md"):
                p = bdir / name
                if not p.is_file():
                    continue
                try:
                    with p.open("r", encoding="utf-8", errors="replace") as fh:
                        for _ in range(60):
                            line = fh.readline()
                            if not line:
                                break
                            m = re.match(r"^#\s+(.+?)\s*#*\s*$", line)
                            if m:
                                return m.group(1).strip()
                except OSError:
                    continue
        return ""

    def peek_title(self, conv):
        title, _ = self.resolve_title(conv)
        return title

    def resolve_title(self, conv):
        if conv.override_title:
            return conv.override_title, "override"
        ann = pbtxt_get_title(self.annotation_text(conv))
        if is_valid_title(ann):
            return ann, "annotations"
        existing = self.existing_summaries(conv.id)
        for _, s in existing:
            a = s.get_msg(SummaryF.ANNOTATIONS)
            t = a.get_str(AnnF.TITLE) if a is not None else ""
            if is_valid_title(t):
                return t, "summary-annotation"
        for _, s in existing:
            t = s.get_str(SummaryF.SUMMARY)
            if is_valid_title(t):
                return t, "summary"
        for db in self.state_dbs:
            s = db.init_state_summaries().get(conv.id)
            t = s.get_str(SummaryF.SUMMARY) if s is not None else ""
            if is_valid_title(t):
                return t, "summary"
        info = conv.info
        if info and info.checkpoint_intent:
            first = re.split(r"(?<=[.!?])\s|\n", info.checkpoint_intent.strip(), maxsplit=1)[0]
            first = clean_title(first)
            if is_valid_title(first):
                return first, "checkpoint"
        heading = clean_title(self.brain_heading(conv), 120)
        if is_valid_title(heading):
            return heading, "brain"
        if info and info.first_prompt:
            prompt = clean_title(info.first_prompt)
            if is_valid_title(prompt):
                return prompt, "prompt"
        created = self.created_time(conv)
        return "Conversation %s %s" % (fmt_time(created)[:10], short_id(conv.id)), "fallback"

    def created_time(self, conv):
        info = conv.info
        if info is not None:
            t = ts_to_float(info.metadata.get_msg(MetaF.CREATED_AT))
            if t:
                return t
        for _, s in self.existing_summaries(conv.id):
            t = ts_to_float(s.get_msg(SummaryF.CREATED_TIME))
            if t:
                return t
        if info is not None and info.first_step_time:
            return info.first_step_time
        return conv.chosen.mtime if conv.chosen else None

    def last_modified(self, conv):
        candidates = []
        if conv.chosen is not None and conv.chosen.mtime:
            candidates.append(conv.chosen.mtime)
        if conv.info is not None and conv.info.last_step_time:
            candidates.append(conv.info.last_step_time)
        for _, s in self.existing_summaries(conv.id)[:1]:
            t = ts_to_float(s.get_msg(SummaryF.LAST_MODIFIED_TIME))
            if t:
                candidates.append(t)
        created = self.created_time(conv)
        if created:
            candidates.append(created)
        return max(candidates) if candidates else _now()

    # -- workspace resolution --------------------------------------------
    def known_roots(self):
        roots = set()
        for p in self.active_projects():
            for u in p.folder_uris():
                path = file_uri_to_path(u)
                if path and path != "/":
                    roots.add(path)
        for c in self.convs.values():
            if c.workspace_uri:
                path = file_uri_to_path(c.workspace_uri)
                if path:
                    roots.add(path)
        return roots

    def infer_workspace(self, conv):
        roots = sorted(self.known_roots(), key=len, reverse=True)
        if not roots:
            return ""
        texts = []
        budget = 4 * 1024 * 1024
        for surface in ("hub", "ide", "cli"):
            bdir = conv.brains.get(surface)
            if bdir is None or not bdir.is_dir():
                continue
            for p in sorted(bdir.rglob("*.md"))[:200]:
                try:
                    t = p.read_text("utf-8", "replace")
                except OSError:
                    continue
                texts.append(t[:200000])
                budget -= len(texts[-1])
                if budget <= 0:
                    break
        if conv.info is not None:
            texts.extend(conv.info.user_texts)
        texts.append(self._step_text_sample(conv))
        alternatives = []
        for r in roots:
            alternatives.append(re.escape(r))
            enc = _encode_path(r)
            if enc != r:
                alternatives.append(re.escape(enc))
        pattern = re.compile("(" + "|".join(alternatives) + ")" + _BOUNDARY)
        counts = {}
        home_data = os.path.join(str(self.env.home), ".gemini")
        for text in texts:
            for m in pattern.finditer(text):
                path = _unquote_fully(m.group(1))
                if text[m.end():m.end() + 8] == "/.gemini" or path_is_under(path, home_data):
                    continue
                counts[path] = counts.get(path, 0) + 1
        if not counts:
            return ""
        best = max(counts.items(), key=lambda kv: (kv[1], len(kv[0])))[0]
        return path_to_file_uri(best)

    def _step_text_sample(self, conv):
        if conv.chosen is None or conv.chosen.kind != "db":
            return ""
        try:
            conn, tmp = _sqlite_open_ro(conv.chosen.path)
        except sqlite3.Error:
            return ""
        chunks = []
        try:
            for row in conn.execute("SELECT step_payload, metadata FROM steps ORDER BY idx LIMIT 200"):
                for blob in row:
                    if blob:
                        chunks.append(bytes(blob).decode("utf-8", "ignore"))
        except sqlite3.Error:
            pass
        finally:
            _sqlite_close(conn, tmp)
        return "\n".join(chunks)[:4 * 1024 * 1024]

    def _clean_ws(self, uri):
        uri = scrub_uri(uri)
        uri = self.remap.uri(uri) if uri else uri
        return uri if is_valid_workspace_uri(uri) else ""

    def resolve_workspace(self, conv, infer=True):
        if conv.override_workspace:
            return conv.override_workspace, [], "override"
        found = [u for u in (self._clean_ws(x) for x in conv.current_workspaces()) if u]
        uniq = []
        for u in found:
            if u not in uniq:
                uniq.append(u)
        if uniq:
            return uniq[0], uniq[1:], "trajectory"
        for _, s in self.existing_summaries(conv.id):
            cands = []
            md = s.get_msg(SummaryF.TRAJECTORY_METADATA)
            if md is not None:
                cands.extend(md.get_strs(MetaF.WORKSPACE_URIS))
            for ws in s.get_msgs(SummaryF.WORKSPACES):
                cands.append(ws.get_str(WsF.FOLDER_URI))
            for c in cands:
                u = self._clean_ws(c)
                if u:
                    return u, [], "summary"
        if infer and not conv.is_subagent:
            u = self._clean_ws(self.infer_workspace(conv))
            if u:
                return u, [], "inferred"
        return "", [], "none"

    # -- metadata building ------------------------------------------------
    def build_workspace_meta(self, uri, existing=None):
        path = file_uri_to_path(uri)
        same = existing is not None and scrub_uri(existing.get_str(WsF.FOLDER_URI)) == uri \
            and existing.get_str(WsF.FOLDER_URI) == uri
        ws = existing.copy() if same else ProtoFields()
        ws.set(WsF.FOLDER_URI, uri)
        git = find_git_root(path) if path else None
        if git:
            ws.set(WsF.GIT_ROOT_URI, path_to_file_uri(git))
            if not same or not ws.get_str(WsF.BRANCH_NAME):
                branch = read_git_branch(git)
                if branch:
                    ws.set(WsF.BRANCH_NAME, branch)
        elif path and os.path.isdir(path):
            ws.remove(WsF.GIT_ROOT_URI)
        elif not same:
            ws.remove(WsF.GIT_ROOT_URI)
        else:
            root = scrub_uri(ws.get_str(WsF.GIT_ROOT_URI))
            root_path = file_uri_to_path(root) if root else None
            if not root_path or not path_is_under(path or "", root_path):
                ws.remove(WsF.GIT_ROOT_URI)
        return ws

    def build_metadata(self, conv):
        md = conv.metadata.copy()
        uris = [conv.workspace_uri] + [u for u in conv.extra_workspaces if u != conv.workspace_uri] \
            if conv.workspace_uri else []
        if uris:
            existing = md.get_msgs(MetaF.WORKSPACES)
            new_ws = []
            for u in uris:
                match = None
                for e in existing:
                    if scrub_uri(e.get_str(WsF.FOLDER_URI)) == u:
                        match = e
                        break
                new_ws.append(self.build_workspace_meta(u, match))
            md.set_all(MetaF.WORKSPACES, new_ws)
            md.set_all(MetaF.WORKSPACE_URIS, uris)
        if conv.project_id:
            md.set(MetaF.PROJECT_ID, conv.project_id)
        elif conv.project_id == "" and md.has(MetaF.PROJECT_ID):
            md.remove(MetaF.PROJECT_ID)
        return md

    # -- resolution pass --------------------------------------------------
    def resolve_all(self, repair_ids=None, infer=True):
        """Resolve workspace, project, and title for every conversation."""
        order = sorted(self.convs.values(), key=lambda c: (c.is_subagent, c.id))
        for conv in order:
            if conv.info is None:
                continue
            repair = repair_ids is None or conv.id in repair_ids
            if repair:
                uri, extra, src = self.resolve_workspace(conv, infer=infer)
            else:
                cur = [scrub_uri(u) for u in conv.current_workspaces()]
                cur = [u for u in cur if is_valid_workspace_uri(u)]
                uri, extra, src = (cur[0], cur[1:], "trajectory") if cur else ("", [], "none")
            conv.workspace_uri, conv.extra_workspaces, conv.workspace_source = uri, extra, src
        for conv in order:
            if conv.info is None:
                continue
            repair = repair_ids is None or conv.id in repair_ids
            if repair and conv.is_subagent and not conv.override_workspace:
                root = self.root_of(conv)
                if root is not conv and root.workspace_uri and (
                        not conv.workspace_uri or conv.workspace_source != "trajectory"):
                    conv.workspace_uri = root.workspace_uri
                    conv.workspace_source = "parent"
            existing_pid = conv.metadata.get_str(MetaF.PROJECT_ID)
            if conv.override_project is not None:
                conv.project_id = conv.override_project
            elif repair:
                conv.project_id = self.resolve_project_id(conv.workspace_uri, existing_pid)
                if conv.is_subagent:
                    root = self.root_of(conv)
                    if root is not conv and root.project_id and root.project_id != OUTSIDE_PROJECT:
                        conv.project_id = root.project_id
            else:
                conv.project_id = existing_pid
            conv.title, conv.title_source = self.resolve_title(conv)

    # -- summaries --------------------------------------------------------
    def base_summary(self, conv):
        existing = self.existing_summaries(conv.id)
        return existing[0][1].copy() if existing else None

    def build_summary(self, conv, metadata=None):
        md = metadata if metadata is not None else (conv.new_metadata or conv.metadata)
        s = self.base_summary(conv) or ProtoFields()
        info = conv.info
        title = conv.title
        if conv.is_subagent and conv.title_source not in ("override", "annotations"):
            current = s.get_str(SummaryF.SUMMARY)
            title = current if is_valid_title(current) else title
        s.set(SummaryF.SUMMARY, title or None)
        step_count = info.step_count if info else 0
        s.set(SummaryF.STEP_COUNT, step_count or None)
        s.set(SummaryF.LAST_MODIFIED_TIME, ts_from_float(self.last_modified(conv)))
        s.set(SummaryF.TRAJECTORY_ID, (info.trajectory_id if info and info.trajectory_id else
                                       s.get_str(SummaryF.TRAJECTORY_ID) or conv.id))
        s.set(SummaryF.STATUS, STATUS_IDLE)
        created = self.created_time(conv)
        if created:
            s.set(SummaryF.CREATED_TIME, ts_from_float(created))
        s.set_all(SummaryF.WORKSPACES, md.get_msgs(MetaF.WORKSPACES))
        if info and info.last_user_input_time:
            s.set(SummaryF.LAST_USER_INPUT_TIME, ts_from_float(info.last_user_input_time))
        if not conv.is_subagent:
            ann = s.get_msg(SummaryF.ANNOTATIONS) or ProtoFields()
            if title:
                ann.set(AnnF.TITLE, title)
            text = self.annotation_text(conv)
            for name, num in (("archived", AnnF.ARCHIVED), ("starred", AnnF.STARRED),
                              ("pinned", AnnF.PINNED)):
                val = pbtxt_get_bool(text, name)
                if val is not None:
                    ann.set(num, 1 if val else None)
            if len(ann):
                s.set(SummaryF.ANNOTATIONS, ann)
        if info and info.last_user_input_index is not None:
            s.set(SummaryF.LAST_USER_INPUT_STEP_INDEX, info.last_user_input_index)
        s.set(SummaryF.TRAJECTORY_METADATA, md)
        s.remove(SummaryF.SOURCE)  # 0 = UNSPECIFIED, listed as a local conversation
        if info and info.trajectory_type:
            s.set(SummaryF.TRAJECTORY_TYPE, info.trajectory_type)
        return s

    # -- writers ----------------------------------------------------------
    def write_trajectory_metadata(self, conv, md, deep=False):
        f = conv.chosen
        if f is None:
            return False
        new_raw = md.serialize()
        need_meta = new_raw != (conv.info.metadata_raw if conv.info else b"")
        need_source = bool(conv.info and conv.info.source != SOURCE_UNSPECIFIED)
        if not (need_meta or need_source or deep):
            return False
        what = []
        if need_meta:
            what.append("metadata")
        if need_source:
            what.append("source=0")
        if deep:
            what.append("deep paths")
        desc = "update %s (%s): %s" % (f.path.name, f.surface, ", ".join(what))
        if f.kind == "db":
            return self.act(desc, lambda: self._write_db(conv, new_raw, need_meta, need_source, deep)) or True
        return self.act(desc, lambda: self._write_pb(conv, md, deep)) or True

    def _write_db(self, conv, new_raw, need_meta, need_source, deep):
        f = conv.chosen
        if self.backup_dir is not None or True:
            dest = self._backup_rel(f.path).with_name(conv.id + ".metadata.bin")
            dest.parent.mkdir(parents=True, exist_ok=True)
            if conv.info and conv.info.metadata_raw and not dest.exists():
                dest.write_bytes(conv.info.metadata_raw)
        if deep:
            for comp in f.companions():
                self.backup_file(comp)
        snap = _snapshot_times(f.companions())
        orig_mtime = f.mtime
        conn = sqlite3.connect(str(f.path), timeout=15)
        try:
            tables = _sqlite_tables(conn)
            with conn:
                if need_meta and "trajectory_metadata_blob" in tables:
                    cur = conn.execute("UPDATE trajectory_metadata_blob SET data=? WHERE id='main'",
                                       (new_raw,))
                    if cur.rowcount == 0:
                        conn.execute("INSERT INTO trajectory_metadata_blob (id, data) VALUES ('main', ?)",
                                     (new_raw,))
                if need_source and "trajectory_meta" in tables:
                    conn.execute("UPDATE trajectory_meta SET source=0 WHERE source != 0")
                if deep and "steps" in tables:
                    self._deep_rewrite_db(conn)
        finally:
            conn.close()
        _restore_times(snap, [Path(str(f.path) + s) for s in ("", "-wal", "-shm")], orig_mtime)
        if conv.info:
            conv.info.metadata_raw = new_raw
            conv.info.source = 0
        return True

    def _deep_rewrite_db(self, conn):
        fn = self.remap.text
        rows = conn.execute("SELECT idx, step_payload, metadata FROM steps").fetchall()
        changed = 0
        for idx, payload, meta in rows:
            new_payload = rewrite_proto_strings(payload, fn) if payload else payload
            new_meta = rewrite_proto_strings(meta, fn) if meta else meta
            if new_payload != (bytes(payload) if payload else payload) or \
                    new_meta != (bytes(meta) if meta else meta):
                conn.execute("UPDATE steps SET step_payload=?, metadata=? WHERE idx=?",
                             (new_payload, new_meta, idx))
                changed += 1
        return changed

    def _write_pb(self, conv, md, deep):
        f = conv.chosen
        self.backup_file(f.path)
        info = load_pb_info(f.path, keep_trajectory=True)
        if info.error or info.pb_trajectory is None:
            raise LagrangeError("cannot rewrite %s: %s" % (f.path, info.error))
        traj = info.pb_trajectory
        traj.set(TrajectoryF.METADATA, md)
        traj.remove(TrajectoryF.SOURCE)
        if deep:
            fn = self.remap.text
            for fld in traj.fields:
                if fld.num == TrajectoryF.STEPS and fld.wt == WT_LEN:
                    new = rewrite_proto_strings(fld.value, fn)
                    if new != fld.value:
                        fld.value, fld.raw = new, None
        plain = traj.serialize()
        data = encrypt_pb(plain) if info.pb_encrypted else plain
        atomic_write_bytes(f.path, data, keep_times=True)
        if conv.info:
            conv.info.metadata_raw = md.serialize()
            conv.info.source = 0
        return True

    def write_annotation_title(self, conv, title, surfaces=None, overwrite=True):
        targets = []
        hub_ann = self.env.ann_dir("hub") / (conv.id + ".pbtxt")
        targets.append(conv.annotations.get("hub", hub_ann))
        for s in surfaces or ():
            if s in conv.annotations and conv.annotations[s] not in targets:
                targets.append(conv.annotations[s])
        for path in targets:
            try:
                text = path.read_text("utf-8") if path.exists() else ""
            except OSError:
                text = ""
            current = pbtxt_get_title(text)
            if current == title or (current and not overwrite):
                continue
            new_text = pbtxt_set_title(text, title)

            def run(p=path, t=new_text):
                self.backup_file(p)
                atomic_write_text(p, t)
            self.act("set title of %s in %s" % (short_id(conv.id), path), run)
        conv.annotations.setdefault("hub", hub_ann)

    def write_hub_summaries(self, scope=None):
        path = self.env.hub / HUB_SUMMARIES_FILE
        visible = self.visible_in("hub")
        entries = {}
        mods = {}
        if scope is not None:
            for k, v in self.hub_summaries.items():
                if k in self.convs and self.convs[k].info is not None:
                    entries[k] = v
            mods = {k: v for k, v in self.hub_file_mod_times.items() if k in entries}
        for conv in visible:
            if scope is not None and conv.id not in scope:
                continue
            entries[conv.id] = self.build_summary(conv)
            mtime = conv.file_in("hub").mtime if conv.file_in("hub") else None
            if mtime:
                mods[conv.id] = int(mtime)
        dropped = sorted(set(self.hub_summaries) - set(entries))
        state = ProtoFields()
        order = sorted(entries, key=lambda k: -(ts_to_float(entries[k].get_msg(SummaryF.LAST_MODIFIED_TIME)) or 0))
        for k in order:
            state.append(StateF.SUMMARIES, make_map_entry(k, entries[k]))
        for k in order:
            if k in mods:
                state.append(StateF.FILE_MOD_TIMES, make_map_entry(k, mods[k]))
        data = state.serialize()
        old = path.read_bytes() if path.exists() else None
        if data == old:
            return False
        desc = "write %s (%d summaries%s)" % (path, len(entries),
                                             ", dropped %d orphans" % len(dropped) if dropped else "")

        def run():
            self.backup_file(path)
            atomic_write_bytes(path, data, mode=0o600)
            self.hub_summaries = entries
            self.hub_file_mod_times = mods
        self.act(desc, run)
        return True

    def reset_summary_databases(self):
        for surface in ("hub", "cli"):
            root = self.env.surface_dirs[surface]
            for name in (SUMMARIES_DB_FILE, SUMMARIES_DB_FILE + "-wal", SUMMARIES_DB_FILE + "-shm"):
                p = root / name
                if p.exists() and not p.is_symlink():
                    self.stash(p, "rebuilt from summaries on next start")

    def visible_in(self, surface):
        """Conversations whose trajectory file lives in ``surface``."""
        surface = self.surface_alias.get(surface, surface)
        out = []
        for conv in self.convs.values():
            if conv.info is None:
                continue
            f = conv.file_in(surface)
            if f is not None:
                out.append(conv)
        return out

    def update_state_dbs(self, scope=None, sidebar=True):
        for db in self.state_dbs:
            if db.error:
                continue
            updates = {}
            visible = {c.id: c for c in self.visible_in(db.surface)}
            old_rows = parse_topic(db.items.get(USS_TRAJECTORY_KEY)) or []
            old_map = dict(old_rows)
            rows = []
            if scope is None:
                for cid, conv in sorted(visible.items(),
                                        key=lambda kv: -self.last_modified(kv[1])):
                    rows.append((cid, row_with_inner(old_map.get(cid), self.build_summary(conv))))
            else:
                for cid, row in old_rows:
                    if cid in scope and cid in self.convs and self.convs[cid].info is not None:
                        row = row_with_inner(row, self.build_summary(self.convs[cid]))
                    rows.append((cid, row))
                for cid in scope:
                    if cid in visible and cid not in old_map:
                        rows.append((cid, row_with_inner(None, self.build_summary(visible[cid]))))
            new_val = build_topic(rows)
            if db.items.get(USS_TRAJECTORY_KEY) != new_val:
                updates[USS_TRAJECTORY_KEY] = new_val
            if sidebar:
                side = self._rebuild_sidebar(db, visible)
                if side is not None and db.items.get(USS_SIDEBAR_KEY) != side:
                    updates[USS_SIDEBAR_KEY] = side
            init = self._rebuild_init_state(db)
            if init is not None and db.items.get(LEGACY_INIT_STATE_KEY) != init:
                updates[LEGACY_INIT_STATE_KEY] = init
            if updates:
                def run(d=db, u=updates):
                    self.backup_file(d.path)
                    d.write_items(u)
                self.act("update %s state.vscdb (%s)" % (db.app_name, ", ".join(
                    k.split(".")[-1] for k in updates)), run)

    def _clean_sidebar_uri(self, value):
        uri = scrub_uri(value)
        uri = self.remap.uri(uri) if uri else uri
        return uri if is_valid_workspace_uri(uri) else ""

    def _rebuild_sidebar(self, db, visible):
        old = parse_topic(db.items.get(USS_SIDEBAR_KEY))
        rows = []
        seen = {}
        orders = []
        for key, row in old or []:
            inner = row_inner(row) or ProtoFields()
            raw_uri = inner.get_str(SIDEBAR_URI) or inner.get_str(SIDEBAR_URI_LEGACY) or key
            uri = self._clean_sidebar_uri(raw_uri) or self._clean_sidebar_uri(key)
            if not uri:
                continue
            ds = inner.get_msg(SIDEBAR_DISPLAY_STATE)
            if ds is not None and ds.has(SIDEBAR_ORDER):
                orders.append(to_signed64(ds.get_int(SIDEBAR_ORDER)))
            if uri in seen:
                continue
            if inner.has(SIDEBAR_URI_LEGACY) and not inner.has(SIDEBAR_URI):
                inner.remove(SIDEBAR_URI_LEGACY)
            inner.set(SIDEBAR_URI, uri)
            seen[uri] = True
            rows.append((uri, row_with_inner(row, inner)))
        next_order = (min(orders) if orders else 0) - 1
        wanted = []
        for conv in sorted(visible.values(), key=lambda c: -self.last_modified(c)):
            if conv.is_subagent or not conv.workspace_uri:
                continue
            if conv.workspace_uri not in wanted:
                wanted.append(conv.workspace_uri)
        for uri in wanted:
            if uri in seen:
                continue
            ds = ProtoFields().append(SIDEBAR_ORDER, next_order)
            next_order -= 1
            inner = ProtoFields().append(SIDEBAR_URI, uri).append(SIDEBAR_DISPLAY_STATE, ds)
            rows.append((uri, row_with_inner(None, inner)))
            seen[uri] = True
        if old is None and not rows:
            return None
        return build_topic(rows)

    def _rebuild_init_state(self, db):
        st = db.init_state()
        if st is None:
            return None
        changed = False
        container = st.get_msg(INIT_STATE_SUMMARIES)
        if container is not None:
            new_container = ProtoFields()
            for f in container.fields:
                if f.num != 1 or f.wt != WT_LEN:
                    new_container.fields.append(f)
                    continue
                entry = ProtoFields.try_parse(f.value)
                key = entry.get_str(1, None) if entry is not None else None
                if key is None:
                    new_container.fields.append(f)
                    continue
                conv = self.convs.get(key)
                if conv is None or conv.info is None:
                    changed = True
                    continue
                new_entry = make_map_entry(key, self.build_summary(conv))
                if new_entry.serialize() != f.value:
                    changed = True
                new_container.append(1, new_entry)
            if changed:
                st.set(INIT_STATE_SUMMARIES, new_container)
        new_ws = []
        seen = set()
        ws_changed = False
        for raw in st.get_all(INIT_STATE_SIDEBAR_WORKSPACES, WT_LEN):
            inner = ProtoFields.try_parse(raw)
            if inner is None:
                continue
            uri = self._clean_sidebar_uri(inner.get_str(SIDEBAR_URI) or inner.get_str(SIDEBAR_URI_LEGACY))
            if not uri or uri in seen:
                ws_changed = True
                continue
            seen.add(uri)
            if inner.get_str(SIDEBAR_URI) != uri:
                inner.set(SIDEBAR_URI, uri)
                ws_changed = True
            new_ws.append(inner)
        if ws_changed:
            st.set_all(INIT_STATE_SIDEBAR_WORKSPACES, new_ws)
            changed = True
        uris = st.get_strs(INIT_STATE_SIDEBAR_URIS)
        if uris:
            cleaned = []
            for u in uris:
                c = self._clean_sidebar_uri(u)
                if c and c not in cleaned:
                    cleaned.append(c)
            if cleaned != uris:
                st.set_all(INIT_STATE_SIDEBAR_URIS, cleaned)
                changed = True
        return b64encode_str(st.serialize()) if changed else None

    def save_projects(self):
        for proj in list(self.projects.values()):
            if proj.removed:
                if proj.path.exists():
                    self.stash(proj.path, "merged project %s" % proj.id[:8])
                continue
            if proj.dirty or proj.created:
                verb = "create" if proj.created else "update"

                def run(p=proj):
                    self.backup_file(p.path)
                    atomic_write_text(p.path, p.to_json(), mode=0o644)
                    p.dirty = p.created = False
                self.act("%s project %s (%s)" % (verb, proj.name, proj.path.name), run)

    def update_cli_caches(self, clear_metadata=True, scope=None):
        cache = self.env.cli_cache()
        if not cache.is_dir():
            return
        last = cache / "last_conversations.json"
        if last.exists():
            try:
                data = json.loads(last.read_text("utf-8"))
            except (OSError, ValueError):
                data = None
            if isinstance(data, dict):
                cli_ids = {c.id for c in self.visible_in("cli")}
                new = {}
                for k, v in data.items():
                    nk = self.remap.path(k) if is_local_path(k) else self.remap.uri(k)
                    if isinstance(v, str) and v not in cli_ids:
                        continue
                    new.setdefault(nk, v)
                if new != data:
                    self.act("update %s" % last, lambda: (self.backup_file(last), atomic_write_text(
                        last, json.dumps(new, indent=2) + "\n", mode=0o600)))
        meta = cache / "conversation_metadata.json"
        if meta.exists():
            if clear_metadata and scope is None:
                self.stash(meta, "CLI rebuilds this cache")
            else:
                try:
                    data = json.loads(meta.read_text("utf-8"))
                except (OSError, ValueError):
                    data = None
                if isinstance(data, dict) and isinstance(data.get("conversations"), dict):
                    convs = data["conversations"]
                    drop = [k for k in convs if scope is None or k in scope]
                    if drop:
                        for k in drop:
                            convs.pop(k, None)
                        self.act("invalidate %d entries in %s" % (len(drop), meta),
                                 lambda: (self.backup_file(meta), atomic_write_text(
                                     meta, json.dumps(data, indent=2) + "\n", mode=0o600)))
        projs = cache / "projects.json"
        if projs.exists():
            try:
                data = json.loads(projs.read_text("utf-8"))
            except (OSError, ValueError):
                return
            new = self._update_project_refs(data)
            if new != data:
                self.act("update %s" % projs, lambda: (self.backup_file(projs), atomic_write_text(
                    projs, json.dumps(new, indent=2) + "\n", mode=0o600)))

    def _update_project_refs(self, obj):
        if isinstance(obj, dict):
            out = {}
            for k, v in obj.items():
                nk = self.follow_merge(k) if isinstance(k, str) and k in self.merge_map else k
                out.setdefault(nk, self._update_project_refs(v))
            pid = out.get("id")
            if isinstance(pid, str):
                target = self.follow_merge(pid)
                if target != pid:
                    out["id"] = target
                proj = self.projects.get(out["id"])
                if proj is not None and "name" in out and not proj.removed:
                    out["name"] = proj.name
            return out
        if isinstance(obj, list):
            return [self._update_project_refs(v) for v in obj]
        if isinstance(obj, str):
            if obj in self.merge_map:
                return self.follow_merge(obj)
            if obj.lower().startswith("file://"):
                return self.remap.uri(obj)
            if is_local_path(obj):
                return self.remap.path(obj)
        return obj

    def remap_ide_storage(self):
        if not self.remap:
            return
        for app, _ in APP_SURFACES:
            user = self.env.app_user_dir(app)
            files = [user / "globalStorage" / "storage.json"]
            ws_root = user / "workspaceStorage"
            if ws_root.is_dir():
                files.extend(sorted(ws_root.glob("*/workspace.json")))
            for p in files:
                if not p.is_file():
                    continue
                try:
                    data = json.loads(p.read_text("utf-8"))
                except (OSError, ValueError):
                    continue
                new = self.remap.json_value(data)
                if new != data:
                    self.act("remap paths in %s" % p, lambda p=p, new=new: (
                        self.backup_file(p), atomic_write_text(p, json.dumps(new, indent=4) + "\n")))

    def rewrite_brain_paths(self, conv):
        if not self.remap:
            return
        for surface, bdir in conv.brains.items():
            if not bdir.is_dir():
                continue
            for p in sorted(bdir.rglob("*")):
                if not p.is_file() or p.suffix.lower() not in (".md", ".resolved", ".json", ".txt"):
                    continue
                try:
                    text = p.read_text("utf-8")
                except (OSError, UnicodeDecodeError):
                    continue
                new = self.remap.text(text)
                if new != text:
                    self.act("remap paths in %s" % p, lambda p=p, new=new: (
                        self.backup_file(p), atomic_write_text(p, new)))

    # -- consolidation ----------------------------------------------------
    def consolidate(self, opts):
        hub_conv = self.env.conv_dir("hub")
        link_ide = opts.link_surfaces
        for conv in sorted(self.convs.values(), key=lambda c: c.id):
            for f in list(conv.files):
                if f.kind == "db" and f.size == 0 and f is not conv.chosen:
                    if f.surface == "hub" or (f.surface == "ide" and link_ide) or f.surface == "cli":
                        self.stash(f.path, "empty database")
                        conv.files.remove(f)
            if conv.chosen is None:
                continue
            has_real_brain = any(
                p.is_file()
                for b in conv.brains.values()
                if b.is_dir()
                for p in b.rglob("*")
                if ".system_generated" not in p.parts
            )
            if opts.prune_empty and conv.info is not None and conv.info.step_count == 0 \
                    and not has_real_brain:
                for f in list(conv.files):
                    for comp in f.companions():
                        self.stash(comp, "empty conversation")
                for b in list(conv.brains.values()):
                    if b.exists():
                        self.stash(b, "empty conversation brain")
                for a in list(conv.annotations.values()):
                    if a.exists():
                        self.stash(a, "empty conversation annotations")
                conv.files = []
                conv.brains = {}
                conv.annotations = {}
                conv.info = None
                conv.chosen = None
                continue
            chosen = conv.chosen
            if chosen.surface != "hub":
                dest = hub_conv / chosen.path.name
                move = chosen.surface == "cli" or (chosen.surface == "ide" and link_ide)
                existing = [f for f in conv.files if f.surface == "hub" and f.kind == chosen.kind]
                for f in existing:
                    for comp in f.companions():
                        self.stash(comp, "replaced by newer %s copy" % chosen.surface)
                    conv.files.remove(f)
                companions = chosen.companions()

                def run(comps=companions, move=move, src_surface=chosen.surface):
                    hub_conv.mkdir(parents=True, exist_ok=True)
                    for comp in comps:
                        target = hub_conv / comp.name
                        if move:
                            shutil.move(str(comp), str(target))
                        else:
                            shutil.copy2(str(comp), str(target))
                        self.manifest.append({"op": "move" if move else "copy", "src": str(comp),
                                              "dst": str(target), "from": src_surface})
                self.act("%s %s from %s into hub" % ("move" if move else "copy",
                                                     chosen.path.name, chosen.surface), run)
                new_file = TrajFile("hub", chosen.kind, dest) if not self.dry_run else chosen
                if not self.dry_run:
                    new_file._steps = chosen._steps
                    new_file.mtime = chosen.mtime
                    if move:
                        conv.files.remove(chosen)
                    conv.files.append(new_file)
                    conv.chosen = new_file
                    if conv.info is not None:
                        conv.info.path = new_file.path
                else:
                    conv.files.append(_PlannedFile("hub", chosen))
            # Pick up stray files of the other kind left in the CLI surface.
            for f in list(conv.files):
                if f.surface == "cli" and f is not conv.chosen and not isinstance(f, _PlannedFile):
                    for comp in f.companions():
                        self.stash(comp, "duplicate of hub copy")
                    if f in conv.files:
                        conv.files.remove(f)
            self._merge_tree(conv, "brain", opts)
            self._merge_annotations(conv, opts)

    def _merge_tree(self, conv, kind, opts):
        hub_dir = self.env.brain_dir("hub") / conv.id
        for surface in ("ide", "cli"):
            src = conv.brains.get(surface)
            if src is None or not src.is_dir():
                continue
            if os.path.realpath(str(src)) == os.path.realpath(str(hub_dir)):
                continue
            move = surface == "cli" or (surface == "ide" and opts.link_surfaces)

            def run(src=src, move=move):
                for p in sorted(src.rglob("*")):
                    if not p.is_file():
                        continue
                    rel = p.relative_to(src)
                    target = hub_dir / rel
                    if target.exists():
                        if file_mtime(p) and file_mtime(target) and file_mtime(p) > file_mtime(target) \
                                and p.read_bytes() != target.read_bytes():
                            self.backup_file(target)
                            shutil.copy2(str(p), str(target))
                        continue
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(str(p), str(target))
                if move:
                    dest = self._backup_rel(src)
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    shutil.move(str(src), str(dest if not dest.exists() else Path(str(dest) + ".dup")))
            self.act("%s brain/%s from %s into hub" % ("move" if move else "merge",
                                                       short_id(conv.id), surface), run)
            if not self.dry_run:
                if move:
                    conv.brains.pop(surface, None)
                conv.brains["hub"] = hub_dir

    def _merge_annotations(self, conv, opts):
        hub_path = self.env.ann_dir("hub") / (conv.id + ".pbtxt")
        hub_text = ""
        if hub_path.exists():
            try:
                hub_text = hub_path.read_text("utf-8")
            except OSError:
                hub_text = ""
        for surface in ("ide", "cli"):
            src = conv.annotations.get(surface)
            if src is None or not src.exists():
                continue
            if os.path.realpath(str(src)) == os.path.realpath(str(hub_path)):
                continue
            move = surface == "cli" or (surface == "ide" and opts.link_surfaces)
            try:
                text = src.read_text("utf-8")
            except OSError:
                continue
            take = not hub_path.exists() or (
                not pbtxt_get_title(hub_text) and pbtxt_get_title(text)) or (
                pbtxt_get_title(hub_text) == pbtxt_get_title(text)
                and (file_mtime(src) or 0) > (file_mtime(hub_path) or 0))

            def run(src=src, take=take, move=move, text=text):
                if take:
                    self.backup_file(hub_path)
                    atomic_write_text(hub_path, text)
                if move:
                    dest = self._backup_rel(src)
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    shutil.move(str(src), str(dest))
            if take or move:
                self.act("%s annotations for %s from %s" % ("take" if take else "retire",
                                                            short_id(conv.id), surface), run)
                if take:
                    hub_text = text
            if not self.dry_run:
                if move:
                    conv.annotations.pop(surface, None)
                if take or hub_path.exists():
                    conv.annotations["hub"] = hub_path

    def link_surfaces(self, surfaces):
        for surface in surfaces:
            root = self.env.surface_dirs[surface]
            if not root.exists():
                continue
            for sub in LINKABLE_SUBDIRS:
                src = root / sub
                target = self.env.hub / sub
                if src.is_symlink() and os.path.realpath(str(src)) == os.path.realpath(str(target)):
                    continue

                def run(src=src, target=target):
                    target.mkdir(parents=True, exist_ok=True)
                    if os.path.lexists(str(src)):
                        dest = self._backup_rel(src)
                        dest.parent.mkdir(parents=True, exist_ok=True)
                        shutil.move(str(src), str(dest))
                        self.manifest.append({"op": "stash", "src": str(src), "dst": str(dest),
                                              "reason": "replaced by link"})
                    try:
                        os.symlink(str(target), str(src), target_is_directory=True)
                    except (OSError, NotImplementedError) as exc:
                        src.mkdir(parents=True, exist_ok=True)
                        self.warn("cannot create link %s -> %s (%s)" % (src, target, exc))
                self.act("link %s -> %s" % (src, target), run)

    # -- project reconciliation ------------------------------------------
    def merge_project(self, src, dst, reason="merge"):
        if src.id == dst.id or src.removed:
            return
        covered = dst.folder_uris()
        for uri in src.folder_uris():
            p = file_uri_to_path(uri)
            if not any(u == uri or path_is_under(p, file_uri_to_path(u)) for u in covered):
                dst.add_resource(uri)
        if dst.name_is_pathlike() and not src.name_is_pathlike():
            dst.name = src.name
        src.removed = True
        self.merge_map[src.id] = dst.id
        self.say("  %s project %s (%s) -> %s (%s)" % (reason, src.name, src.id[:8], dst.name, dst.id[:8]))

    def conv_counts(self):
        hub, total = {}, {}
        for c in self.convs.values():
            pid = c.metadata.get_str(MetaF.PROJECT_ID)
            if not pid:
                continue
            total[pid] = total.get(pid, 0) + 1
            if c.chosen is not None and c.chosen.surface == "hub":
                hub[pid] = hub.get(pid, 0) + 1
        return hub, total

    def dedupe_projects(self, preferred=()):
        hub, total = self.conv_counts()
        groups = {}
        for p in self.active_projects():
            uri = p.primary_uri
            if uri:
                groups.setdefault(uri, []).append(p)
        for uri, projs in groups.items():
            if len(projs) < 2:
                continue
            keep = max(projs, key=lambda p: (p.id in preferred, p.richness(), hub.get(p.id, 0) > 0,
                                             total.get(p.id, 0), not p.name_is_pathlike(), p.id))
            for p in projs:
                if p is not keep:
                    self.merge_project(p, keep, "dedupe")

    def merge_stale_subprojects(self):
        for p in self.active_projects():
            uris = p.folder_uris()
            paths = [file_uri_to_path(u) for u in uris]
            if not paths or any(x is None or os.path.exists(x) for x in paths):
                continue
            parent = None
            for q in self.active_projects():
                if q is p:
                    continue
                for qu in q.folder_uris():
                    qp = file_uri_to_path(qu)
                    if qp and all(path_is_under(x, qp) and x != qp for x in paths):
                        if parent is None or len(qp) > len(parent[1]):
                            parent = (q, qp)
            if parent is not None:
                self.merge_project(p, parent[0], "merge stale")

    def create_project(self, name, uri):
        data = new_project_data(name, uri)
        proj = Project(self.env.projects_dir / (data["id"] + ".json"), data)
        proj.created = True
        self.projects[proj.id] = proj
        self.say("  create project %s -> %s" % (name, uri))
        return proj

    def auto_create_projects(self, force_all=False):
        parents = set()
        for p in self.active_projects():
            for u in p.folder_uris():
                path = file_uri_to_path(u)
                if path and path != "/":
                    parents.add(posixpath.dirname(path.rstrip("/")))
        created = []
        home = os.path.normpath(str(self.env.home))
        for conv in sorted(self.convs.values(), key=lambda c: c.id):
            if conv.is_subagent or not conv.workspace_uri or conv.info is None:
                continue
            if self.project_for_uri(conv.workspace_uri) is not None:
                continue
            path = file_uri_to_path(conv.workspace_uri)
            if not path or os.path.normpath(path) in (home, "/"):
                continue
            sibling = posixpath.dirname(path.rstrip("/")) in parents
            if not (force_all or sibling):
                continue
            if not os.path.isdir(path):
                continue
            proj = self.create_project(posixpath.basename(path.rstrip("/")) or path, conv.workspace_uri)
            created.append(proj)
        return created

    def apply_project_renames(self, renames):
        for token, new_name in renames:
            proj = self.resolve_project(token)
            if proj.name != new_name:
                self.say("  rename project %s (%s) -> %s" % (proj.name, proj.id[:8], new_name))
                proj.name = new_name

    def tidy_project_uris(self):
        for p in self.active_projects():
            p.map_resource_uris(lambda u: (self.remap.uri(scrub_uri(u) or normalize_uri(u))
                                           if (scrub_uri(u) or normalize_uri(u)) else u))

    # -- high-level commands ---------------------------------------------
    def commit(self, repair_ids=None, deep=False, write_annotations=False,
               backfill_annotations=False, sidebar=True, clear_cli_metadata=True):
        """Write trajectories, summaries, state databases, and caches."""
        targets = [c for c in self.convs.values() if c.info is not None and
                   (repair_ids is None or c.id in repair_ids)]
        rewrote = 0
        for conv in sorted(targets, key=lambda c: c.id):
            md = self.build_metadata(conv)
            conv.new_metadata = md
            try:
                if self.write_trajectory_metadata(conv, md, deep=deep):
                    rewrote += 1
            except (OSError, sqlite3.Error, LagrangeError) as exc:
                self.warn("could not update %s: %s" % (short_id(conv.id), exc))
            if deep:
                self.rewrite_brain_paths(conv)
            if not conv.is_subagent and (write_annotations or backfill_annotations):
                self.write_annotation_title(conv, conv.title, surfaces=SURFACES,
                                            overwrite=write_annotations)
        for conv in self.convs.values():
            if conv.new_metadata is None and conv.info is not None:
                conv.new_metadata = conv.metadata
        scope = None if repair_ids is None else set(repair_ids)
        self.write_hub_summaries(scope=scope)
        self.reset_summary_databases()
        self.update_state_dbs(scope=scope, sidebar=sidebar)
        self.update_cli_caches(clear_metadata=clear_cli_metadata, scope=scope)
        return rewrote

    def sync(self, opts):
        self.remap = Remapper(opts.remaps)
        self.ensure_safe()
        self.say("Scanning...")
        self.scan()
        self.backup_indexes()
        self.say("Projects:")
        self.tidy_project_uris()
        for src_tok, dst_tok in opts.merge_projects:
            self.merge_project(self.resolve_project(src_tok), self.resolve_project(dst_tok))
        self.dedupe_projects(preferred=[self.resolve_project(d).id for _, d in opts.merge_projects
                                        if self.resolve_project(d, allow_none=True)])
        if opts.merge_stale_subprojects:
            self.merge_stale_subprojects()
        if opts.consolidate:
            self.say("Consolidating conversations into %s:" % self.env.hub)
            self.consolidate(opts)
        for cid, target in opts.assign.items():
            conv = self.resolve_conversation(cid)
            uri, pid = self._target_to_uri(target)
            for c in [conv] + self.children_of(conv.id):
                c.override_workspace = uri
                if pid is not None:
                    c.override_project = pid
        if opts.link_surfaces:
            self.surface_alias["ide"] = "hub"
        if opts.link_cli:
            self.surface_alias["cli"] = "hub"
        self.resolve_all()
        self.auto_create_projects(force_all=opts.auto_create_projects)
        if opts.clean_project_names:
            for p in self.active_projects():
                if p.name_is_pathlike():
                    new = clean_project_name(p.name, p.primary_uri, self.env.home)
                    if new and new != p.name:
                        self.say("  rename project %s (%s) -> %s" % (p.name, p.id[:8], new))
                        p.name = new
        self.apply_project_renames(opts.rename_projects)
        self.resolve_all()
        self.save_projects()
        self.say("Trajectories and indexes:")
        n = self.commit(deep=opts.rewrite_deep_paths, write_annotations=opts.write_annotations,
                        backfill_annotations=opts.backfill_annotations)
        self.remap_ide_storage()
        link = []
        if opts.link_surfaces:
            link.append("ide")
        if opts.link_cli:
            link.append("cli")
        if link:
            self.link_surfaces(link)
        self.write_manifest()
        tops = [c for c in self.convs.values() if c.info is not None and not c.is_subagent]
        subs = [c for c in self.convs.values() if c.info is not None and c.is_subagent]
        self.say("")
        self.say("%s %d top-level conversations and %d subagents; %d trajectories updated." % (
            "Would sync" if self.dry_run else "Synced", len(tops), len(subs), n))
        if not self.dry_run:
            self.say("Start Antigravity: it rebuilds its search index from the new summaries.")
        return 0

    def _target_to_uri(self, target):
        proj = self.resolve_project(target, allow_none=True) if not is_local_path(target) \
            and "://" not in target else None
        if proj is not None:
            if not proj.primary_uri:
                raise LagrangeError("project %s has no folder" % proj.name)
            return proj.primary_uri, proj.id
        uri = path_to_file_uri(target)
        if not is_valid_workspace_uri(uri):
            raise LagrangeError("invalid workspace path: %s" % target)
        return uri, None

    def rename_conversation(self, token, title):
        if not is_valid_title(title):
            raise LagrangeError("invalid title")
        self.ensure_safe()
        self.scan()
        conv = self.resolve_conversation(token)
        self.backup_indexes()
        conv.override_title = title
        self.resolve_all(repair_ids=set())
        self.say("Renaming %s -> %r" % (short_id(conv.id), title))
        self.write_annotation_title(conv, title, surfaces=SURFACES, overwrite=True)
        for c in self.convs.values():
            c.new_metadata = c.metadata
        self.write_hub_summaries(scope={conv.id})
        self.reset_summary_databases()
        self.update_state_dbs(scope={conv.id}, sidebar=False)
        self.update_cli_caches(clear_metadata=False, scope={conv.id})
        self.write_manifest()
        return 0

    def move_conversation(self, token, target):
        self.ensure_safe()
        self.scan()
        conv = self.resolve_conversation(token)
        uri, pid = self._target_to_uri(target)
        family = [conv] + self.children_of(conv.id)
        self.backup_indexes()
        for c in family:
            c.override_workspace = uri
            c.override_project = pid if pid is not None else self.resolve_project_id(uri, "", explicit=True)
        ids = {c.id for c in family}
        self.resolve_all(repair_ids=ids)
        self.say("Moving %s (+%d subagents) -> %s" % (short_id(conv.id), len(family) - 1, uri))
        self.commit(repair_ids=ids, clear_cli_metadata=False)
        self.write_manifest()
        return 0

    def rename_project(self, token, new_name):
        self.ensure_safe()
        self.scan()
        proj = self.resolve_project(token)
        self.backup_indexes()
        if proj.name == new_name:
            self.say("Project already named %r." % new_name)
            return 0
        self.say("Renaming project %s (%s) -> %r" % (proj.name, proj.id[:8], new_name))
        proj.name = new_name
        self.save_projects()
        self.update_cli_caches(clear_metadata=False, scope=set())
        self.write_manifest()
        return 0

    def merge_projects_cmd(self, src_tok, dst_tok):
        self.ensure_safe()
        self.scan()
        src = self.resolve_project(src_tok)
        dst = self.resolve_project(dst_tok)
        if src.id == dst.id:
            raise LagrangeError("source and target are the same project")
        self.backup_indexes()
        self.merge_project(src, dst)
        ids = {c.id for c in self.convs.values()
               if c.info is not None and c.metadata.get_str(MetaF.PROJECT_ID) == src.id}
        for c in self.convs.values():
            if c.id in ids:
                c.override_project = dst.id
        self.resolve_all(repair_ids=ids, infer=False)
        self.save_projects()
        self.say("Repointing %d conversations." % len(ids))
        self.commit(repair_ids=ids, clear_cli_metadata=False)
        self.write_manifest()
        return 0

    def remap_path_cmd(self, old, new, deep=False):
        self.remap = Remapper([(old, new)])
        self.ensure_safe()
        self.scan()
        self.backup_indexes()
        self.tidy_project_uris()
        self.dedupe_projects()
        self.resolve_all(infer=False)
        self.save_projects()
        affected = set()
        for c in self.convs.values():
            if c.info is None:
                continue
            before = [scrub_uri(u) for u in c.current_workspaces()]
            if before != [c.workspace_uri] + c.extra_workspaces or deep:
                affected.add(c.id)
            if c.metadata.get_str(MetaF.PROJECT_ID) != c.project_id:
                affected.add(c.id)
        self.say("Remapping %s -> %s (%d conversations%s)" % (
            self.remap.rules[0][0], self.remap.rules[0][1], len(affected), ", deep" if deep else ""))
        self.commit(repair_ids=affected, deep=deep, clear_cli_metadata=False)
        # Summaries and sidebars for every conversation may carry the old path.
        self.write_hub_summaries(scope=set(self.hub_summaries) | affected)
        self.update_state_dbs(scope={c.id for c in self.convs.values() if c.info is not None})
        self.remap_ide_storage()
        self.write_manifest()
        return 0

    def create_project_cmd(self, name, path):
        self.ensure_safe()
        self.scan()
        uri = path_to_file_uri(path)
        if not is_valid_workspace_uri(uri):
            raise LagrangeError("invalid project path: %s" % path)
        existing = [p for p in self.active_projects() if p.primary_uri == uri]
        if existing:
            raise LagrangeError("project %s already uses %s" % (existing[0].name, uri))
        self.backup_indexes()
        self.create_project(name, uri)
        self.save_projects()
        self.write_manifest()
        return 0

    # -- status -----------------------------------------------------------
    def collect_status(self, include_subagents=False):
        self.resolve_all(repair_ids=set())
        issues = list(self.anomalies)
        projects = []
        hub_counts, totals = self.conv_counts()
        by_uri = {}
        for p in sorted(self.projects.values(), key=lambda p: p.name.lower()):
            uris = p.folder_uris()
            exists = [bool(file_uri_to_path(u) and os.path.exists(file_uri_to_path(u))) for u in uris]
            projects.append({"id": p.id, "name": p.name, "folders": uris,
                             "folders_exist": exists, "conversations": totals.get(p.id, 0)})
            if p.primary_uri:
                by_uri.setdefault(p.primary_uri, []).append(p)
            if uris and not all(exists):
                issues.append("project %s (%s): folder missing on disk" % (p.name, p.id[:8]))
            if p.name_is_pathlike():
                issues.append("project %s (%s): name is a path" % (p.name, p.id[:8]))
        for uri, ps in by_uri.items():
            if len(ps) > 1:
                issues.append("duplicate projects for %s: %s" % (uri, ", ".join(
                    "%s (%s)" % (p.name, p.id[:8]) for p in ps)))
        convs = []
        for c in sorted(self.convs.values(), key=lambda c: -(self.last_modified(c) if c.info else 0)):
            if c.info is None:
                issues.append("%s: no readable trajectory (%s)" % (short_id(c.id), ", ".join(
                    "%s:%s(%dB)" % (f.surface, f.kind, f.size) for f in c.files)))
                continue
            entry = self._conv_status(c, issues)
            if c.is_subagent and not include_subagents:
                continue
            convs.append(entry)
        for db in self.state_dbs:
            for cid, s in db.summaries().items():
                for ws in s.get_msgs(SummaryF.WORKSPACES):
                    raw = ws.get_str(WsF.FOLDER_URI)
                    if raw and (_CONTROL_RE.search(raw) or scrub_uri(raw) != raw):
                        issues.append("%s state.vscdb: corrupted workspace URI for %s" % (
                            db.app_name, short_id(cid)))
                        break
                if cid not in self.convs:
                    issues.append("%s state.vscdb: orphan summary %s" % (db.app_name, short_id(cid)))
        for cid in self.hub_summaries:
            if cid not in self.convs:
                issues.append("hub summaries: orphan summary %s" % short_id(cid))
        surfaces = {}
        for s in SURFACES:
            root = self.env.surface_dirs[s]
            surfaces[s] = {"path": str(root), "exists": root.exists(),
                           "linked": {sub: self.symlinked.get((s, sub)) for sub in LINKABLE_SUBDIRS
                                      if (s, sub) in self.symlinked},
                           "conversations": sum(1 for c in self.convs.values()
                                                if any(f.surface == s for f in c.files))}
        tops = sum(1 for c in self.convs.values() if c.info is not None and not c.is_subagent)
        subs = sum(1 for c in self.convs.values() if c.info is not None and c.is_subagent)
        return {
            "version": __version__,
            "home": str(self.env.home),
            "crypto_backend": self._backend_name(),
            "surfaces": surfaces,
            "state_dbs": [{"app": d.app_name, "path": str(d.path), "error": d.error} for d in self.state_dbs],
            "projects": projects,
            "top_level_conversations": tops,
            "subagents": subs,
            "conversations": convs,
            "issues": issues,
        }

    @staticmethod
    def _backend_name():
        try:
            return get_crypto_backend().name
        except LagrangeError:
            return None

    def _conv_status(self, c, issues):
        sid = short_id(c.id)
        md = c.metadata
        pid = md.get_str(MetaF.PROJECT_ID)
        proj = self.projects.get(pid)
        raw_ws = c.current_workspaces()
        if c.chosen.surface != "hub":
            issues.append("%s: only in %s (not visible in Hub)" % (sid, "/".join(c.surfaces)))
        if c.info.source == SOURCE_CLI:
            issues.append("%s: tagged source=CLI (hidden from the Hub list)" % sid)
        hub_sum = self.hub_summaries.get(c.id)
        if c.chosen.surface == "hub" and hub_sum is None:
            issues.append("%s: missing from Hub summaries" % sid)
        if hub_sum is not None and hub_sum.get_int(SummaryF.SOURCE) == SOURCE_CLI:
            issues.append("%s: Hub summary tagged source=CLI" % sid)
        if not c.is_subagent:
            if not raw_ws:
                issues.append("%s: no workspace" % sid)
            for u in raw_ws:
                if u and (scrub_uri(u) != u):
                    issues.append("%s: non-canonical workspace URI %r" % (sid, u))
            if c.workspace_uri:
                p = file_uri_to_path(c.workspace_uri)
                if p and not os.path.exists(p):
                    issues.append("%s: workspace folder missing on disk (%s)" % (sid, p))
                if not md.get_strs(MetaF.WORKSPACE_URIS):
                    issues.append("%s: workspace_uris not set" % sid)
            if pid and pid != OUTSIDE_PROJECT and proj is None:
                issues.append("%s: unknown project id %s" % (sid, pid))
            elif not pid or pid == OUTSIDE_PROJECT:
                match = self.project_for_uri(c.workspace_uri) if c.workspace_uri else None
                if match is not None:
                    issues.append("%s: not assigned to project %s" % (sid, match.name))
            if c.title_source not in ("annotations", "summary-annotation", "override"):
                issues.append("%s: no saved title (would use %s)" % (sid, c.title_source))
        return {
            "id": c.id,
            "title": c.title,
            "title_source": c.title_source,
            "kind": c.chosen.kind,
            "surfaces": c.surfaces,
            "chosen_surface": c.chosen.surface,
            "steps": c.info.step_count,
            "created": fmt_time(self.created_time(c)),
            "modified": fmt_time(self.last_modified(c)),
            "workspace": c.workspace_uri,
            "project_id": pid,
            "project": proj.name if proj else ("" if not pid else pid),
            "source": c.info.source,
            "subagent": c.is_subagent,
            "parent": c.parent_id,
            "subagent_count": sum(1 for x in self.convs.values() if x.parent_id == c.id),
        }

    def print_status(self, include_subagents=False, as_json=False):
        self.scan()
        st = self.collect_status(include_subagents=include_subagents)
        if as_json:
            self.say(json.dumps(st, indent=2, ensure_ascii=False))
            return 0
        self.say("Lagrange %s  home=%s  crypto=%s" % (st["version"], st["home"], st["crypto_backend"]))
        self.say("")
        self.say("Surfaces")
        for name, s in st["surfaces"].items():
            linked = (" linked: " + ", ".join(s["linked"])) if s["linked"] else ""
            self.say("  %-4s %-45s %s %3d conversations%s" % (
                name, s["path"], "ok " if s["exists"] else "-- ", s["conversations"], linked))
        for d in st["state_dbs"]:
            self.say("  state.vscdb  %s%s" % (d["path"], " (error: %s)" % d["error"] if d["error"] else ""))
        self.say("")
        self.say("Projects (%d)" % len(st["projects"]))
        for p in st["projects"]:
            self.say("  %-24s %s  %3d convs  %s" % (p["name"][:24], p["id"][:8], p["conversations"],
                                                    ", ".join(p["folders"])))
        self.say("")
        self.say("Conversations: %d top-level, %d subagents" % (st["top_level_conversations"], st["subagents"]))
        for c in st["conversations"]:
            ws = file_uri_to_path(c["workspace"]) or c["workspace"] or "-"
            subs = " +%d sub" % c["subagent_count"] if c["subagent_count"] else ""
            self.say("  %s %s %-3s %5d steps  %-4s %-38s %-14s %s%s" % (
                c["id"][:8], c["modified"], c["kind"], c["steps"], c["chosen_surface"],
                c["title"][:38], (c["project"] or "-")[:14], ws, subs))
        self.say("")
        if st["issues"]:
            self.say("Issues (%d)" % len(st["issues"]))
            for i in st["issues"]:
                self.say("  - " + i)
            self.say("")
            self.say("Run `lagrange.py sync --dry-run` to preview a repair.")
        else:
            self.say("No issues found.")
        return 0


class _PlannedFile(TrajFile):
    """Placeholder used during dry runs for a file that would be moved to the Hub."""

    def __init__(self, surface, original):
        self.surface = surface
        self.kind = original.kind
        self.path = original.path
        self.size = original.size
        self.mtime = original.mtime
        self._steps = original._steps


# ---------------------------------------------------------------------------
# Interactive mode
# ---------------------------------------------------------------------------


def _ask(prompt, default=None):
    try:
        val = input(prompt).strip()
    except EOFError:
        return default
    return val or default


def _confirm(prompt):
    return (_ask(prompt + " [y/N] ", "n") or "n").lower().startswith("y")


def interactive(env=None):
    env = env or Env()
    print("Lagrange %s: Antigravity conversation, workspace, and project manager" % __version__)
    menu = [
        ("1", "Status report"),
        ("2", "Full sync and repair"),
        ("3", "Move a conversation to a workspace or project"),
        ("4", "Rename a conversation"),
        ("5", "Rename a project"),
        ("6", "Merge two projects"),
        ("7", "Remap a moved workspace folder"),
        ("8", "Create a project"),
        ("0", "Exit"),
    ]
    while True:
        print("")
        for key, label in menu:
            print("  %s) %s" % (key, label))
        choice = _ask("Choose: ", "0")
        try:
            if choice == "1":
                Lagrange(env).print_status()
            elif choice == "2":
                opts = SyncOptions()
                remaps = _ask("Moved folders to remap (OLD=NEW, comma separated, blank for none): ", "")
                for item in [x for x in (remaps or "").split(",") if x.strip()]:
                    old, _, new = item.partition("=")
                    opts.remaps.append((old.strip(), new.strip()))
                opts.link_surfaces = _confirm("Link the IDE conversation folders to the Hub store?")
                print("\nPreview:")
                Lagrange(env, dry_run=True).sync(opts)
                if _confirm("\nApply these changes?"):
                    Lagrange(env, force=_confirm("Ignore running-process check?")).sync(opts)
            elif choice == "3":
                Lagrange(env).print_status()
                cid = _ask("Conversation id (or prefix): ")
                target = _ask("Target workspace path or project name: ")
                if cid and target:
                    Lagrange(env, dry_run=True).move_conversation(cid, target)
                    if _confirm("Apply?"):
                        Lagrange(env).move_conversation(cid, target)
            elif choice == "4":
                cid = _ask("Conversation id (or prefix): ")
                title = _ask("New title: ")
                if cid and title:
                    Lagrange(env).rename_conversation(cid, title)
            elif choice == "5":
                token = _ask("Project id or name: ")
                name = _ask("New name: ")
                if token and name:
                    Lagrange(env).rename_project(token, name)
            elif choice == "6":
                src = _ask("Project to merge (source): ")
                dst = _ask("Project to keep (target): ")
                if src and dst:
                    Lagrange(env, dry_run=True).merge_projects_cmd(src, dst)
                    if _confirm("Apply?"):
                        Lagrange(env).merge_projects_cmd(src, dst)
            elif choice == "7":
                old = _ask("Old folder path: ")
                new = _ask("New folder path: ")
                deep = _confirm("Also rewrite paths inside conversation steps and brain files?")
                if old and new:
                    Lagrange(env, dry_run=True).remap_path_cmd(old, new, deep=deep)
                    if _confirm("Apply?"):
                        Lagrange(env).remap_path_cmd(old, new, deep=deep)
            elif choice == "8":
                name = _ask("Project name: ")
                path = _ask("Project folder: ")
                if name and path:
                    Lagrange(env).create_project_cmd(name, path)
            elif choice in ("0", "q", "quit", "exit"):
                return 0
        except LagrangeError as exc:
            print("Error: %s" % exc)


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------


def _pair(text, sep="="):
    if sep not in text:
        raise argparse.ArgumentTypeError("expected OLD%sNEW, got %r" % (sep, text))
    a, _, b = text.partition(sep)
    if not a.strip() or not b.strip():
        raise argparse.ArgumentTypeError("expected OLD%sNEW, got %r" % (sep, text))
    return a.strip(), b.strip()


def build_parser():
    def make_common(suppress):
        kw = {"default": argparse.SUPPRESS} if suppress else {}
        c = argparse.ArgumentParser(add_help=False)
        c.add_argument("--home", help="home folder to operate on (default: your home)", **kw)
        c.add_argument("--config-root", help="folder that holds the Antigravity app data "
                       "(default: platform specific)", **kw)
        c.add_argument("--verbose", "-v", action="store_true", help="print every action", **kw)
        return c

    # Sub-commands suppress their copies of the global options so a value given
    # before the sub-command is not reset to the default.
    top_common = make_common(False)
    common = make_common(True)

    mut = argparse.ArgumentParser(add_help=False)
    mut.add_argument("--dry-run", "-n", action="store_true", help="show what would change")
    mut.add_argument("--force", action="store_true",
                     help="run even if Antigravity processes are detected")

    p = argparse.ArgumentParser(
        prog="lagrange.py", parents=[top_common],
        description="Unify, repair, and manage Antigravity conversations, workspaces, and projects.")
    p.add_argument("--version", action="version", version="Lagrange " + __version__)
    sub = p.add_subparsers(dest="command")

    s = sub.add_parser("status", parents=[common], help="cross-surface diagnostic report")
    s.add_argument("--json", action="store_true")
    s.add_argument("--include-subagents", action="store_true")

    s = sub.add_parser("sync", aliases=["repair"], parents=[common, mut],
                       help="one-shot unification and repair of every surface")
    s.add_argument("--remap", action="append", type=_pair, default=[], metavar="OLD=NEW",
                   help="a workspace folder moved from OLD to NEW (repeatable)")
    s.add_argument("--assign", action="append", type=_pair, default=[], metavar="ID=PATH",
                   help="force a conversation into a workspace path or project (repeatable)")
    s.add_argument("--merge-project", action="append", type=_pair, default=[], metavar="SRC=DST")
    s.add_argument("--rename-project", action="append", type=_pair, default=[], metavar="ID_OR_NAME=NAME")
    s.add_argument("--auto-create-projects", action="store_true",
                   help="create a project for every conversation workspace without one")
    s.add_argument("--merge-stale-subprojects", action="store_true",
                   help="merge projects whose folder is gone into their parent project")
    s.add_argument("--prune-empty", action="store_true", help="retire empty 0-step conversations")
    g = s.add_mutually_exclusive_group()
    g.add_argument("--link-surfaces", dest="link_surfaces", action="store_true", default=True,
                   help="link the IDE conversations/brain/annotations folders to the Hub (default)")
    g.add_argument("--no-link-surfaces", dest="link_surfaces", action="store_false")
    s.add_argument("--link-cli", action="store_true",
                   help="also link the CLI folders (the Hub then sees the CLI store as its own)")
    s.add_argument("--rewrite-deep-paths", action="store_true",
                   help="also rewrite remapped paths inside steps and brain files")
    s.add_argument("--write-annotations", action="store_true",
                   help="overwrite annotation titles with the resolved titles")
    s.add_argument("--no-backfill-annotations", dest="backfill_annotations", action="store_false",
                   help="do not add titles to annotation files that have none")
    s.add_argument("--keep-project-names", action="store_true",
                   help="do not rename projects whose name is a folder path")

    s = sub.add_parser("rename-conversation", parents=[common, mut])
    s.add_argument("conversation")
    s.add_argument("title")

    s = sub.add_parser("move-conversation", parents=[common, mut])
    s.add_argument("conversation")
    s.add_argument("target", help="workspace folder path or project id/name")

    s = sub.add_parser("rename-project", parents=[common, mut])
    s.add_argument("project")
    s.add_argument("name")

    s = sub.add_parser("merge-project", parents=[common, mut])
    s.add_argument("source")
    s.add_argument("target")

    s = sub.add_parser("remap-path", parents=[common, mut])
    s.add_argument("old")
    s.add_argument("new")
    s.add_argument("--deep", action="store_true",
                   help="also rewrite paths inside steps and brain files")

    s = sub.add_parser("create-project", parents=[common, mut])
    s.add_argument("name")
    s.add_argument("path")
    return p


def main(argv=None):
    argv = sys.argv[1:] if argv is None else list(argv)
    parser = build_parser()
    args = parser.parse_args(argv)
    env = Env(home=getattr(args, "home", None), config_root=getattr(args, "config_root", None))
    if not args.command:
        code = interactive(env)
        if getattr(sys, "frozen", False):
            _ask("\nPress Enter to exit.")
        return code
    app = Lagrange(env, dry_run=getattr(args, "dry_run", False), force=getattr(args, "force", False),
                   verbose=getattr(args, "verbose", False))
    try:
        if args.command == "status":
            return app.print_status(include_subagents=args.include_subagents, as_json=args.json)
        if args.command in ("sync", "repair"):
            opts = SyncOptions(
                remaps=args.remap, assign=dict(args.assign), merge_projects=args.merge_project,
                rename_projects=args.rename_project, auto_create_projects=args.auto_create_projects,
                prune_empty=args.prune_empty, link_surfaces=args.link_surfaces, link_cli=args.link_cli,
                rewrite_deep_paths=args.rewrite_deep_paths, write_annotations=args.write_annotations,
                backfill_annotations=args.backfill_annotations,
                clean_project_names=not args.keep_project_names,
                merge_stale_subprojects=args.merge_stale_subprojects)
            return app.sync(opts)
        if args.command == "rename-conversation":
            return app.rename_conversation(args.conversation, args.title)
        if args.command == "move-conversation":
            return app.move_conversation(args.conversation, args.target)
        if args.command == "rename-project":
            return app.rename_project(args.project, args.name)
        if args.command == "merge-project":
            return app.merge_projects_cmd(args.source, args.target)
        if args.command == "remap-path":
            return app.remap_path_cmd(args.old, args.new, deep=args.deep)
        if args.command == "create-project":
            return app.create_project_cmd(args.name, args.path)
    except LagrangeError as exc:
        print("Error: %s" % exc, file=sys.stderr)
        return 2
    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
