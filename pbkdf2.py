# -*- coding: utf-8 -*-

"""
    pbkdf2
    ~~~~~~

    This module implements pbkdf2 for Python.  It also has some basic
    tests that ensure that it works.  The implementation is straightforward
    and uses stdlib only stuff and can be easily be copy/pasted into
    your favourite application.

    Use this as replacement for bcrypt that does not need a c implementation
    of a modified blowfish crypto algo.

    Python 2.7 and 3 compatible

"""

from binascii import hexlify
import hmac
import hashlib
import sys
from struct import Struct
from operator import xor
from itertools import starmap

_PY3 = sys.version_info[0] == 3

if not _PY3:
    from itertools import izip as zip

if _PY3:
    text_type = str
else:
    text_type = unicode


_pack_int = Struct('>I').pack


def _bytes_(s, encoding='utf8', errors='strict'):
    if isinstance(s, text_type):
        return s.encode(encoding, errors)
    return s


def _hexlify_(s):
    if _PY3:
        return str(hexlify(s), encoding="utf8")
    else:
        return s.encode('hex')


def _range_(*args):
    if _PY3:
        return range(*args)
    else:
        return xrange(*args)


def pbkdf2_hex(data, salt, iterations=1000, keylen=24, hashfunc=None):
    """Like :func:`pbkdf2_bin` but returns a hex encoded string."""
    return _hexlify_(pbkdf2_bin(data, salt, iterations, keylen, hashfunc))


def pbkdf2_bin(data, salt, iterations=1000, keylen=24, hashfunc=None):
    """Returns a binary digest for the PBKDF2 hash algorithm of `data`
    with the given `salt`.  It iterates `iterations` time and produces a
    key of `keylen` bytes.  By default SHA-1 is used as hash function,
    a different hashlib `hashfunc` can be provided.
    """
    hashfunc = hashfunc or hashlib.sha1
    mac = hmac.new(_bytes_(data), None, hashfunc)

    def _pseudorandom(x, mac=mac):
        h = mac.copy()
        h.update(_bytes_(x))

        if _PY3:
            return [y for y in h.digest()]
        else:
            return map(ord, h.digest())

    buf = []

    for block in _range_(1, -(-keylen // mac.digest_size) + 1):
        rv = u = _pseudorandom(_bytes_(salt) + _pack_int(block))

        for i in _range_(iterations - 1):
            if _PY3:
                u = _pseudorandom(bytes(u))
            else:
                u = _pseudorandom(''.join(map(chr, u)))
            rv = starmap(xor, zip(rv, u))
        buf.extend(rv)

    if _PY3:
        return bytes(buf)[:keylen]
    else:
        return ''.join(map(chr, buf))[:keylen]
