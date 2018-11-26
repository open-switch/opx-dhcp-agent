#!/usr/bin/env python3

'''Supported DHCP options.'''

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

from .types import HexString

_HEXSTRING = HexString(256)

class Option(dict):
    '''A base class for DHCP option implementations.

       All implementations MUST specify:
       * a string name in :attr:`option`
       * an integer tag value in the range 0 .. 255 inclusive in :attr:`tag`

       An option implementation for a tag-only option MUST specify:
       * None in :attr:`length`
       * None in :attr:`value_type`

       An option implementation for a TLV option with a fixed length value MUST specify:
       * an integer value in the range 0 .. 255 inclusive in :attr:`length`
       * a :class:`.types.ValueType` instance, or boolean True, in :attr:`value_type`

       An option implementation for a TLV option with a variable length value MUST specify:
       * None in :attr:`length`
       * a :class:`.types.ValueType` instance, or boolean True, in :attr:`value_type`

       If an option implementation supplies boolean True in :attr:`value_type` then it MUST override
       :method:`encode_value` and :method:`decode_value`.
    '''
    option = None
    tag = None
    length = None
    value_type = None
    def __init__(self, value=None, canonical=True):
        if canonical:
            kwargs = {'option': self.option}
        else:
            kwargs = {'tag': self.tag}
            if value is not None:
                kwargs['length'] = len(value)
        if value is not None:
            kwargs['value'] = value
        dict.__init__(self, **kwargs)
    @classmethod
    def encode(cls, option):
        '''Return a :class:`dict` instance encoding `option` as a tag-only or a TLV option.

           If `cls` implements a tag-only option and `option` has 'option' matching :attr:`option`,
           then return a :class:`dict` with a solitary pair at key 'tag', with value :attr:`tag`.

           If `cls` implements a TLV option and `option` has 'option' matching :attr:`option`, and
           has a 'value' which can be encoded and packed according to :attr:`value_type`, then
           return an instance with pairs at key 'tag', with value :attr:`tag`, at key 'value', with
           the binary string value encoded and packed from `option` 'value', and at key 'length',
           with the length of that binary string value.

           Otherwise raise :class:`KeyError`, :class:`ValueError` or :class:`TypeError`.
        '''
        if cls.option != option['option']:
            raise ValueError(option)
        if cls.value_type:
            octets = cls.encode_value(option['value'])
            return cls(value=octets, canonical=False)
        else:
            return cls(canonical=False)
    @classmethod
    def encode_value(cls, val):
        '''Return a binary string value encoded from `val` according to :attr:`value_type`.
           Otherwise raise :class:`ValueError` or :class:`TypeError`.
        '''
        val = cls.value_type.encode(val)
        return cls.value_type.pack(val)
    @classmethod
    def decode(cls, option):
        '''Return an instance of `cls` with pairs decoded from `option`.

           If `cls` implements a tag-only option and `option` has a 'tag' matching :attr:`tag`, then
           return an instance with a solitary pair at key 'option', with value :attr:`option`.

           If `cls` implements a TLV option and `option` has a 'tag' matching :attr:`tag`, 'length'
           matching :attr:`length` (if not None), and a binary string 'value' which can be unpacked
           and decoded according to :attr:`value_type`, then return an instance with pairs at key
           'option', with value :attr:`option`, and at key 'value', with the value unpacked and
           decoded from `option` binary string 'value'.

           Otherwise raise :class:`KeyError`, :class:`ValueError` or :class:`TypeError`.
        '''
        if cls.tag != option['tag']:
            raise ValueError(option)
        if cls.length is not None and cls.length != option['length']:
            raise ValueError(option)
        if cls.value_type:
            if option['length'] != len(option['value']):
                raise ValueError(option)
            return cls(value=cls.decode_value(option['value']), canonical=True)
        else:
            return cls(canonical=True)
    @classmethod
    def decode_value(cls, octets):
        '''Return value decoded from `octets` according to :attr:`value_type`.
           Otherwise raise :class:`ValueError` or :class:`TypeError`.
        '''
        (value, octets) = cls.value_type.unpack(octets)
        if octets != b'':
            raise ValueError(octets)
        return cls.value_type.decode(value)

class Supported(object):
    '''A set of supported DHCP options.'''
    def __init__(self):
        self._names = {}
        self._tags = {}
    def add(self, obj):
        '''Add option implementation `obj` to this set of supported options. `obj` must implement
           the interface specified by :class:`Option` and must specify a unique string name and
           unique integer tag (within the scope of this instance) through its 'option' and 'tag'
           attributes.
        '''
        option = obj.option
        if option in self._names:
            raise ValueError('option {} is already registered'.format(option))
        tag = obj.tag
        if tag in self._tags:
            raise ValueError('tag {} is already registered'.format(tag))
        self._names[option] = obj
        self._tags[tag] = obj
    def encode(self, options):
        '''Return a list of encoded options from iterable `options`. If an option is a supported
           option by name, then attempt to encode the option using the registered implementation.
           If the option is not a supported option by name, or the registered implementation failed
           to encode the option, then attempt to encode the option as a TLV option encoding the
           hexadecimal string value to a binary string. Finally, if the option cannot be encoded
           by either of these means, include the option in the return value without change.
        '''
        result = []
        for option in options:
            try:
                encoded = self._names[option['option']].encode(option)
            except (KeyError, ValueError):
                try:
                    encoded = {
                        'tag': option['tag'],
                        'length': option['length'],
                        'value': _HEXSTRING.encode(option['value']),
                    }
                except (KeyError, ValueError, TypeError):
                    result.append(option)
                else:
                    result.append(encoded)
            else:
                result.append(encoded)
        return result
    def decode(self, options):
        '''Return a list of decoded options from iterable `options`. If an option is a supported
           option by tag, then attempt to decode the option using the registered implementation.
           If the option is not a supported option by tag, or the registered implementation failed
           to decode the option, then attempt to decode the option as a TLV option decoding the
           binary string value to a hexadecimal string. Finally, if the option cannot be decoded
           by either of these means, include the option in the return value without change.
        '''
        result = []
        for option in options:
            try:
                decoded = self._tags[option['tag']].decode(option)
            except (KeyError, ValueError):
                try:
                    decoded = {
                        'tag': option['tag'],
                        'length': option['length'],
                        'value': _HEXSTRING.decode(option['value']),
                    }
                except (KeyError, ValueError, TypeError):
                    result.append(option)
                else:
                    result.append(decoded)
            else:
                result.append(decoded)
        return result

class BuiltIn(type):
    '''A metaclass serving as a registry of built-in DHCP options.'''
    _supported = Supported()
    def __new__(mcs, name, bases, body):
        cls = type(name, bases, body)
        mcs._supported.add(cls)
        return cls
    @classmethod
    def encode(mcs, options):
        '''Return a list of encoded options from `options` using the built-in implementations.'''
        return mcs._supported.encode(options)
    @classmethod
    def decode(mcs, options):
        '''Return a list of decoded options from `options` using the built-in implementations.'''
        return mcs._supported.decode(options)
