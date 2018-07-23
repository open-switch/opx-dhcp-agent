#!/usr/bin/env python3

'''Type-Length-Value encoding and decoding support.'''

from collections import OrderedDict

from struct import Struct
from socket import AF_INET, inet_ntop, inet_pton
from socket import error as SocketError

from six import (binary_type, iterbytes, PY2, int2byte)

class Int(object):
    '''A value type enforcing integer values between `min_` and `max_` inclusive. `sfmt` is the
       :module:`struct` format string for packing and unpacking values of this type.
    '''
    def __init__(self, min_, max_, sfmt):
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

class UInt8(Int):
    '''A value type enforcing unsigned integer values with a max range of 0 .. 0xFF.
       Binary-encoded values are stored in one octet.
    '''
    def __init__(self, min_=0, max_=0xFF):
        if min_ < 0:
            raise ValueError(min_)
        elif max_ > 0xFF:
            raise ValueError(max_)
        Int.__init__(self, min_, max_, 'B')

class UInt16(Int):
    '''A value type enforcing unsigned integer values with a max range 0 .. 0xFFFF.
       Binary-encoded values are stored in two octets.
    '''
    def __init__(self, min_=0, max_=0xFFFF):
        if min_ < 0:
            raise ValueError(min_)
        elif max_ > 0xFFFF:
            raise ValueError(max_)
        Int.__init__(self, min_, max_, 'H')

class UInt32(Int):
    '''A value type enforcing unsigned integer values with a max range 0 .. 0xFFFFFFFF.
       Binary-encoded values are stored in four octets.
    '''
    def __init__(self, min_=0, max_=0xFFFFFFFF):
        if min_ < 0:
            raise ValueError(min_)
        elif max_ > 0xFFFFFFFF:
            raise ValueError(max_)
        Int.__init__(self, min_, max_, 'I')

class IPv4(object):
    '''A value type enforcing IPv4 address string values.
       Binary-encoded values are stored in four octets.
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
    def decode(octets):
        '''Return an IPv4 address string from binary-encoded value `octets`. Otherwise, raise
           :class:`ValueError`.
        '''
        try:
            return inet_ntop(AF_INET, octets)
        except (ValueError, SocketError, OSError):
            raise ValueError(octets)
    @staticmethod
    def encode(val):
        '''Return a binary-encoded value representing IPv4 address string `val`. Otherwise, raise
           :class:`ValueError`.
        '''
        try:
            return inet_pton(AF_INET, val)
        except (ValueError, SocketError, OSError):
            raise ValueError(val)

class NulTerminatedString(object):
    '''A value type enforcing string values which, when encoded with a NUL terminator, have a max
       encoded length of `max_` octets. String values are encoded and decoded with `encoding`.
    '''
    def __init__(self, max_, encoding='iso-8859-1'):
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
           right fills with zero bytes.
        '''
        return '{:d}s'.format(self.max_)
    def __call__(self, val):
        '''Return `val` if it is a string whose encoded value complies with this type's max encoded
           length restriction. Otherwise, raise :class:`ValueError`.
        '''
        self.encode(val)
        return val
    def decode(self, octets):
        '''Return a string value complying with this type's max encoded length restriction from
           binary-encoded value `octets`, with all characters after, and including, the first NUL
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
    def encode(self, val):
        '''Return a binary-encoded value without a NUL terminator representing string `val`, if the
           encoded value complies with this type's max encoded length restriction. Otherwise, raise
           :class:`ValueError`.
        '''
        try:
            octets = val.encode(self.encoding)
        except AttributeError:
            pass
        else:
            if len(octets) < self.max_: ### allows at least 1 octet for NUL terminator
                return octets
        raise ValueError(val)

class HexString(object):
    '''A value type enforcing colon-separated hexadecimal string values which have a max encoded
       length of `max_` octets.
    '''
    def __init__(self, max_):
        self._max = int(max_)
    @property
    def max_(self):
        '''Return the maximum encoded value length accepted by this type.'''
        return self._max
    @property
    def sfmt(self):
        '''Return the :module:`struct` format string for packing and unpacking values. Values are
           encoded into a field of fixed size, :attr:`max_` octets. The 's' format automatically
           right fills with zero bytes.
        '''
        return '{:d}s'.format(self.max_)
    def __call__(self, val):
        '''Return `val` if it is a hexadecimal string whose encoded value complies with this type's
           max encoded length restriction. Otherwise, raise :class:`ValueError`.
        '''
        self.encode(val)
        return val
    def decode(self, octets):
        '''Return a hexadecimal string value complying with this type's max encoded length
           restriction from binary-encoded value `octets`. Otherwise, raise :class:`ValueError`.
        '''
        ### note that Python 2 binary type is str, which this implementation will attempt to process
        if isinstance(octets, binary_type) and len(octets) <= self.max_:
            return ':'.join(['{:02x}'.format(_) for _ in iterbytes(octets)])
        raise ValueError(octets)
    def encode(self, val):
        '''Return a binary-encoded value representing hexadecimal string `val`, if the encoded value
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
    @staticmethod
    def truncate(val, max_):
        '''Return a hexadecimal string value with at most `max_` elements from hexadecimal string
           value `val`.
        '''
        return ':'.join(val.split(':')[:max_])

def _value_init(bases, body):
    '''Return a function for use as the  __init__ method of a class built by :class:`Value`.'''
    def init(self, *args, **kwargs):
        '''Initialise `self` from `args` and `kwargs`.'''
        ### partially initialise `self` for receiving input values...
        bases[0].__init__(self)
        ### ...assign input values with type-checking
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

def _value_setitem(self, key, val):
    '''A function for use as the __setitem__ method of a class built by :class:`Value`.'''
    val = self.screen(key, val)
    super(self.__class__, self).__setitem__(key, val)

def _value_screen(self, key, val):
    '''A function for use as the screen method of a class built by :class:`Value`.

       If `key` is not a supported field, raise :class:`KeyError`.
       If `val` is not a supported lexical value type for field, raise :class:`TypeError`.
       If `val` is not a supported lexical value for field, raise :class:`ValueError`.
       Otherwise, return the canonical value for field from lexical value.
    '''
    try:
        return self.fields[key](val)
    except KeyError:
        raise KeyError('unsupported field for {}: {}'.format(self.name, key))
    except ValueError:
        raise ValueError('bad value for {} field {}: {}'.format(self.name, key, val))
    except TypeError:
        raise TypeError('unsupported field for {}: {}'.format(self.name, key))

def _value_update(self, *args, **kwargs):
    '''A function for use as the update method of a class built by :class:`Value`.

       Apply all changes specified by `args` and `kwargs`, or no changes.
    '''
    ivals = dict(*args, **kwargs)
    for key in ivals:
        ivals[key] = self.screen(key, ivals[key])
    super(self.__class__, self).update(ivals)

def _value_encode(self):
    '''A function for use as the encode method of a class built by :class:`Value`.

       Raise :class:`KeyError` if any required field does not have a value in `self`.
    '''
    args = []
    for key in self.fields:
        val = self[key]
        try:
            val = self.fields[key].encode(val)
        except AttributeError:
            pass
        args.append(val)
    return self.struct.pack(*args)

def _value_decode(cls, octets):
    '''A function for use as the decode classmethod of a class built by :class:`Value`.'''
    args = {}
    for (key, val) in zip(cls.fields, cls.struct.unpack_from(octets)):
        try:
            val = cls.fields[key].decode(val)
        except AttributeError:
            pass
        args[key] = val
    return cls(args) ### octets[cls.struct.size:]

class Value(type):
    '''A metaclass for constructing classes which represent a structured value. A structured value
       comprises a sequence of field values.

       The class using this metaclass MUST define a `spec` class attribute, a sequence of (key,
       value type) pairs, one per field, in order of their occurrence in an encoded octet string.

       The class returned by this metaclass derives from :class:`dict`, followed by any other base
       classes specified by the class. The returned class enforces that values can only be set at
       keys in `spec` and that values must conform to the corresponding value type. Class instances
       may be constructed as per :class:`dict` or by calling the class method :meth:`decode` with an
       octet string. Class instances may be encoded to an octet string by calling :meth:`encode`.
    '''
    def __new__(mcs, name, bases, dct):
        obases = list(bases)
        dct = dict(dct)
        ### order bases: make dict first in python MRO
        try:
            obases.remove(dict)
        except ValueError:
            pass
        obases.insert(0, dict)
        bases = tuple(obases)
        ### build the structured value fields from the class specification
        fields = OrderedDict(dct['spec'])
        struct = Struct('>' + ''.join([_.sfmt for _ in fields.values() if _.sfmt]))
        ### build the class body...
        ### ...from specified methods and attributes in `dct`
        body = dict(dct)
        ### ...overriding with StructuredValue methods and attributes
        body['fields'] = fields
        body['struct'] = struct
        body['__init__'] = _value_init(bases, dct)
        body['__setitem__'] = _value_setitem
        body['screen'] = _value_screen
        body['update'] = _value_update
        body['encode'] = _value_encode
        body['decode'] = classmethod(_value_decode)
        return type(name, bases, body)
