#!/usr/bin/env python3

'''DHCP value types.'''

# Copyright (c) 2018 Inocybe Technologies.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# THIS CODE IS PROVIDED ON AN *AS IS* BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT
# LIMITATION ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS
# FOR A PARTICULAR PURPOSE, MERCHANTABLITY OR NON-INFRINGEMENT.
#
# See the Apache Version 2.0 License for specific language governing
# permissions and limitations under the License.

from collections import OrderedDict

from struct import unpack_from as s_unpack
from struct import calcsize as s_size
from struct import pack as s_pack
from socket import AF_INET, inet_ntop, inet_pton
from socket import error as SocketError

from six import (iteritems, binary_type, iterbytes, PY2, int2byte)

class ValueType(object):
    '''A base class for value types.'''
    @property
    def sfmt(self):
        '''Return a :module:`struct` format string (which MUST NOT be prefixed with a byte order
           control character) indicating how values of this type are to be packed and unpacked.
           Alternatively, return None if values are to be packed and unpacked using :meth:`pack` and
           :meth:`unpack`.
        '''
        return None
    def __call__(self, val):
        '''Return the canonical python value for lexical value `val`. Raise :class:`ValueError` or
           :class:`TypeError` as appropriate if the canonical value cannot be determined from `val`.
        '''
        raise NotImplementedError()
    def pack(self, val):
        '''Return a binary string packing `val`. If :attr:`sfmt` is None then this method MUST be
           overridden. Raise :class:`ValueError` or :class:`TypeError` if `val` cannot be packed.
        '''
        if self.sfmt is None:
            raise NotImplementedError()
        return s_pack('>' + self.sfmt, val)
    def unpack(self, octets):
        '''Return a 2-tuple (val, octets), the value unpacked from binary string `octets`, and the
           trailing octets not unpacked, respectively. If :attr:`sfmt` is None then this method MUST
           be overridden. Raise :class:`ValueError` or :class:`TypeError` if a value of this type
           cannot be unpacked from `octets`.
        '''
        if self.sfmt is None:
            raise NotImplementedError()
        sfmt = '>' + self.sfmt
        return (s_unpack(sfmt, octets)[0], octets[s_size(sfmt):])
    @staticmethod
    def encode(val):
        '''Encode and return `val` for packing. Raise :class:`ValueError` or :class:`TypeError` if
           `val` cannot be encoded.
        '''
        return val
    @staticmethod
    def decode(val):
        '''Decode and return unpacked `val`. Raise :class:`ValueError` or :class:`TypeError` if
           `val` cannot be decoded.
        '''
        return val

class Int(ValueType):
    '''A value type enforcing integer values between `min_` and `max_` inclusive. `sfmt` is the
       :module:`struct` format string for packing and unpacking values of this type.
    '''
    def __init__(self, min_, max_, sfmt):
        ValueType.__init__(self)
        self._min = int(min_)
        self._max = int(max_)
        self._sfmt = sfmt
    @property
    def min_(self):
        '''Return the minimum value accepted by this type.'''
        return self._min
    @property
    def max_(self):
        '''Return the maximum value accepted by this type.'''
        return self._max
    @property
    def sfmt(self):
        '''Return the :module:`struct` format string for packing and unpacking values.'''
        return self._sfmt
    def __call__(self, val):
        '''Return the canonical integer value for lexical value `val`, where `val` is either numeric
           or a string containing a base-encoded integer. If a canonical value cannot be determined
           from `val`, or is outside this type's value range, then raise :class:`ValueError` or
           :class:`TypeError`.
        '''
        try:
            val = int(val, base=0)
        except TypeError:
            val = int(val)
        if val < self.min_:
            raise ValueError(val)
        elif self.max_ < val:
            raise ValueError(val)
        else:
            return val

class Enum(Int):
    '''An integer value type decoding integer values to string labels.
       `enum` must specify the mapping of integer value to string label.
    '''
    def __init__(self, min_, max_, sfmt, enum):
        Int.__init__(self, min_, max_, sfmt)
        self.value_to_label = dict(enum)
        self.label_to_value = dict([(v, k) for (k, v) in iteritems(self.value_to_label)])
    def __call__(self, val):
        if val in self.label_to_value:
            return val
        try:
            return self.value_to_label[super(Enum, self).__call__(val)]
        except KeyError:
            raise ValueError(val)
    def encode(self, val):
        try:
            return self.label_to_value[val]
        except KeyError:
            raise ValueError(val)
    def decode(self, val):
        try:
            return self.value_to_label[val]
        except KeyError:
            raise ValueError(val)

class UInt8(Int):
    '''A value type enforcing unsigned integer values with a max range of 0 .. 0xFF.
       Packed values are stored in a binary string of length one.
    '''
    def __init__(self, min_=0, max_=0xFF):
        if min_ < 0:
            raise ValueError(min_)
        elif max_ > 0xFF:
            raise ValueError(max_)
        Int.__init__(self, min_, max_, 'B')

class UInt16(Int):
    '''A value type enforcing unsigned integer values with a max range 0 .. 0xFFFF.
       Packed values are stored in a binary string of length two.
    '''
    def __init__(self, min_=0, max_=0xFFFF):
        if min_ < 0:
            raise ValueError(min_)
        elif max_ > 0xFFFF:
            raise ValueError(max_)
        Int.__init__(self, min_, max_, 'H')

class UInt32(Int):
    '''A value type enforcing unsigned integer values with a max range 0 .. 0xFFFFFFFF.
       Packed values are stored in a binary string of length four.
    '''
    def __init__(self, min_=0, max_=0xFFFFFFFF):
        if min_ < 0:
            raise ValueError(min_)
        elif max_ > 0xFFFFFFFF:
            raise ValueError(max_)
        Int.__init__(self, min_, max_, 'I')

class SInt32(Int):
    '''A value type enforcing signed integer values with a max range -0x80000000 .. 0x7FFFFFFF.
       Packed values are stored in a binary string of length four.
    '''
    def __init__(self, min_=-0x80000000, max_=0x7FFFFFFF):
        if min_ < -0x80000000:
            raise ValueError(min_)
        elif max_ > 0x7FFFFFFF:
            raise ValueError(max_)
        Int.__init__(self, min_, max_, 'i')

class IPv4(ValueType):
    '''A value type enforcing IPv4 address string values.
       Packed values are stored in a binary string of length four.
    '''
    @property
    def sfmt(self):
        '''Return the :module:`struct` format string for packing and unpacking values.'''
        return '4s'
    def __call__(self, val):
        '''Return `val` if it is an IPv4 address string. Otherwise, raise :class:`ValueError`.'''
        try:
            inet_pton(AF_INET, val)
        except (ValueError, SocketError, OSError):
            raise ValueError(val)
        else:
            return val
    @staticmethod
    def encode(val):
        '''Return a binary string representing IPv4 address string `val`.
           Otherwise, raise :class:`ValueError`.
        '''
        try:
            return inet_pton(AF_INET, val)
        except (ValueError, SocketError, OSError):
            raise ValueError(val)
    @staticmethod
    def decode(octets):
        '''Return an IPv4 address string from binary string `octets`.
           Otherwise, raise :class:`ValueError`.
        '''
        try:
            return inet_ntop(AF_INET, octets)
        except (ValueError, SocketError, OSError):
            raise ValueError(octets)

class NulTerminatedString(ValueType):
    '''A value type enforcing string values which, when encoded with a NUL terminator, have a max
       binary string length of `max_`. String values are encoded and decoded with `encoding`.
    '''
    def __init__(self, max_, encoding='iso-8859-1'):
        ValueType.__init__(self)
        self._max = int(max_)
        self._encoding = encoding
    @property
    def max_(self):
        '''Return the maximum encoded value length accepted by this type.'''
        return self._max
    @property
    def encoding(self):
        '''Return the string encoding for encoded values.'''
        return self._encoding
    @property
    def sfmt(self):
        '''Return the :module:`struct` format string for packing and unpacking values. Values are
           encoded into a field of fixed size, :attr:`max_` octets. The 's' format automatically
           right fills with zeroes.
        '''
        return '{:d}s'.format(self.max_)
    def __call__(self, val):
        '''Return `val` if it is a string whose encoded value complies with this type's max encoded
           length restriction. Otherwise, raise :class:`ValueError`.
        '''
        self.encode(val)
        return val
    def encode(self, val):
        '''Return a binary string value without a NUL terminator representing string `val`, if the
           encoded value complies with this type's max encoded length restriction. Otherwise, raise
           :class:`ValueError`.
        '''
        try:
            octets = val.rstrip('\0').encode(self.encoding)
        except AttributeError:
            pass
        else:
            if len(octets) < self.max_: ### allows at least 1 octet for NUL terminator
                return octets
        raise ValueError(val)
    def decode(self, octets):
        '''Return a string value complying with this type's max encoded length restriction from
           binary string value `octets`, with all characters after, and including, the first NUL
           terminator discarded. Otherwise, raise :class:`ValueError`.
        '''
        try:
            val = octets.decode(self.encoding)
        except AttributeError:
            pass
        else:
            idx = val.find('\0')
            if idx != -1:
                val = val[:idx]
            try:
                return self(val)
            except ValueError:
                pass
        raise ValueError(octets)

class HexString(ValueType):
    '''A value type enforcing colon-separated hexadecimal string values which have a max encoded
       binary string length of `max_` octets.
    '''
    def __init__(self, max_):
        ValueType.__init__(self)
        self._max = int(max_)
    @property
    def max_(self):
        '''Return the maximum encoded value length accepted by this type.'''
        return self._max
    @property
    def sfmt(self):
        '''Return the :module:`struct` format string for packing and unpacking values. Values are
           encoded into a field of fixed size, :attr:`max_` octets. The 's' format automatically
           right fills with zeroes.
        '''
        return '{:d}s'.format(self.max_)
    def __call__(self, val):
        '''Return `val` if it is a hexadecimal string whose encoded value complies with this type's
           max encoded length restriction. Otherwise, raise :class:`ValueError`.
        '''
        self.encode(val)
        return val
    def encode(self, val):
        '''Return a binary string value representing hexadecimal string `val`, if the encoded value
           complies with this type's max encoded length restriction. Otherwise, raise
           :class:`ValueError`.
        '''
        try:
            elems = [] if val == '' else val.split(':')
        except AttributeError:
            pass
        else:
            if PY2:
                octets = ''.join([int2byte(int(_, base=16)) for _ in elems])
            else:
                octets = bytes([int(_, base=16) for _ in elems]) ### pylint: disable=redefined-variable-type
            if len(octets) <= self.max_:
                return octets
        raise ValueError(val)
    def decode(self, octets):
        '''Return a hexadecimal string value complying with this type's max encoded length
           restriction from binary string value `octets`. Otherwise, raise :class:`ValueError`.
        '''
        ### note that Python 2 binary type is str, which this implementation will attempt to process
        if isinstance(octets, binary_type) and len(octets) <= self.max_:
            return ':'.join(['{:02x}'.format(_) for _ in iterbytes(octets)])
        raise ValueError(octets)
    @staticmethod
    def truncate(val, max_):
        '''Return a hexadecimal string value with at most `max_` elements from hexadecimal string
           value `val`.
        '''
        return ':'.join(val.split(':')[:max_])

def _structured_value_init(bases, body):
    '''Return a function for use as the  __init__ method of a class built by
       :class:`StructuredValue`.
    '''
    def init(self, *args, **kwargs):
        '''Initialise `self` from `args` and `kwargs`.'''
        ### partially initialise `self` for receiving input values...
        bases[0].__init__(self)
        ### ...assign input values with field type checking
        ivals = dict(*args, **kwargs)
        for key in ivals:
            self[key] = ivals[key]
        ### complete initialisation using class-specific method or bases
        if '__init__' in body:
            body['__init__'](self)
        else:
            for base in bases[1:]:
                base.__init__(self)
    return init

def _structured_value_setitem(self, key, val):
    '''A function for use as the __setitem__ method of a class built by :class:`StructuredValue`.'''
    val = self.screen(key, val)
    super(self.__class__, self).__setitem__(key, val)

def _structured_value_screen(self, key, val):
    '''A function for use as the screen method of a class built by :class:`StructuredValue`.

       If `key` is not a supported field, raise :class:`KeyError`.
       If `val` is not a supported lexical value type for field, raise :class:`TypeError`.
       If `val` is not a supported lexical value for field, raise :class:`ValueError`.
       Otherwise, return the canonical value for field from lexical value `val`.
    '''
    try:
        return self.fields[key](val)
    except KeyError:
        raise KeyError('unsupported field for {}: {}'.format(self.name, key))
    except ValueError:
        raise ValueError('bad value for {} field {}: {}'.format(self.name, key, val))
    except TypeError:
        raise TypeError('bad value for {} field {}: {}'.format(self.name, key, val))

def _structured_value_update(self, *args, **kwargs):
    '''A function for use as the update method of a class built by :class:`StructuredValue`.

       Apply all changes specified by `args` and `kwargs`, or no changes.
    '''
    ivals = dict(*args, **kwargs)
    for key in ivals:
        ivals[key] = self.screen(key, ivals[key])
    super(self.__class__, self).update(ivals)

def _structured_value_pack(self):
    '''A function for use as the pack method of a class built by :class:`StructuredValue`.

       Raise :class:`KeyError` if any required field does not have a value in `self`.
    '''
    octets = b''
    for key in self.fields:
        field = self.fields[key]
        val = field.encode(self[key])
        octets += field.pack(val)
    return octets

def _structured_value_unpack(cls, octets):
    '''A function for use as the unpack classmethod of a class built by :class:`StructuredValue`.'''
    args = {}
    for key in cls.fields:
        field = cls.fields[key]
        (val, octets) = field.unpack(octets)
        args[key] = field.decode(val)
    return cls(args)

class StructuredValue(type):
    '''A metaclass for constructing classes which represent a structured value. A structured value
       comprises a sequence of field values.

       The class using this metaclass MUST define a `spec` class attribute, a sequence of (key,
       value type) pairs, one per field, in order of occurrence in a packed binary string.

       The class returned by this metaclass derives from :class:`dict`, followed by any other base
       classes specified by the class. The returned class enforces that values can only be set at
       keys in `spec` and that values must conform to the corresponding value type. Class instances
       may be constructed as per :class:`dict` or by calling the class method :meth:`unpack` with a
       binary string. Class instances may be packed to a binary string by calling :meth:`pack`.
    '''
    def __new__(mcs, name, bases, dct):
        obases = list(bases)
        ### make :class:`dict` first in python MRO
        try:
            obases.remove(dict)
        except ValueError:
            pass
        obases.insert(0, dict)
        bases = tuple(obases)
        body = dict(dct)
        body['fields'] = OrderedDict(dct['spec'])
        body['__init__'] = _structured_value_init(bases, dct)
        body['__setitem__'] = _structured_value_setitem
        body['screen'] = _structured_value_screen
        body['update'] = _structured_value_update
        body['pack'] = _structured_value_pack
        body['unpack'] = classmethod(_structured_value_unpack)
        return type(name, bases, body)
