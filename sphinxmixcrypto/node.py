#!/usr/bin/env python

# Copyright 2011 Ian Goldberg
# Copyright 2016-2017 David Stainton
#
# This file is part of Sphinx.
#
# Sphinx is free software: you can redistribute it and/or modify
# it under the terms of version 3 of the GNU Lesser General Public
# License as published by the Free Software Foundation.
#
# Sphinx is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with Sphinx.  If not, see
# <http://www.gnu.org/licenses/>.

"""
This module includes cryptographic unwrapping of messages for mix net nodes
"""

import zope.interface
import attr

from sphinxmixcrypto.padding import remove_padding
from sphinxmixcrypto.interfaces import IPacketReplayCache, IKeyState
from sphinxmixcrypto.crypto_primitives import SECURITY_PARAMETER, GroupCurve25519, SphinxDigest
from sphinxmixcrypto.crypto_primitives import SphinxStreamCipher, SphinxLioness, xor, CURVE25519_SIZE
from sphinxmixcrypto.errors import HeaderAlphaGroupMismatchError, ReplayError, IncorrectMACError
from sphinxmixcrypto.errors import InvalidProcessDestinationError, InvalidMessageTypeError
from sphinxmixcrypto.errors import SphinxBodySizeMismatchError


@attr.s(frozen=True)
class SphinxParams(object):

    max_hops = attr.ib(validator=attr.validators.instance_of(int))
    payload_size = attr.ib(validator=attr.validators.instance_of(int))

    @property
    def beta_cipher_size(self):
        """
        i am a helper method that is used to compute the size of the
        stream cipher output used in sphinx packet operations
        """
        return CURVE25519_SIZE + (2 * self.max_hops + 1) * SECURITY_PARAMETER

    def get_dimensions(self):
        """
        i am a helper method that returns the sphinx packet element sizes, a 4-tuple.
        e.g. payload = 1024 && 5 hops ==
        alpha 32 beta 176 gamma 16 delta 1024
        """
        alpha = CURVE25519_SIZE
        beta = (2 * self.max_hops + 1) * SECURITY_PARAMETER
        gamma = SECURITY_PARAMETER
        delta = self.payload_size
        return alpha, beta, gamma, delta


@attr.s(frozen=True)
class SphinxHeader(object):
    """
    The Sphinx header.

    The Sphinx paper refers to the header fields as the greek letters: alpha, beta and gamma.
    """
    alpha = attr.ib(validator=attr.validators.instance_of(bytes))
    beta = attr.ib(validator=attr.validators.instance_of(bytes))
    gamma = attr.ib(validator=attr.validators.instance_of(bytes))


@attr.s(frozen=True)
class SphinxBody(object):
    """
    A Sphinx has the body of a lion or lioness.  The sphinx packet
    body is repeated encrypted with the lioness wide-block cipher.

    The Sphinx paper refers to this field of the packet as the greek letter delta.
    """
    delta = attr.ib(validator=attr.validators.instance_of(bytes))


@attr.s(frozen=True)
class SphinxPacket(object):
    """
    I am a decoded sphinx packet
    """
    header = attr.ib(validator=attr.validators.instance_of(SphinxHeader))
    body = attr.ib(validator=attr.validators.instance_of(SphinxBody))

    def get_raw_bytes(self):
        """
        Get all the bytes.
        """
        return self.header.alpha + self.header.beta + \
            self.header.gamma + self.body.delta

    @classmethod
    def from_raw_bytes(cls, params, raw_packet):
        """
        Create a SphinxPacket given the raw bytes and
        an instance of SphinxParams.
        """
        assert isinstance(params, SphinxParams)
        alpha, beta, gamma, delta = params.get_dimensions()
        _alpha = raw_packet[:alpha]
        _beta = raw_packet[alpha:alpha + beta]
        _gamma = raw_packet[alpha + beta:alpha + beta + gamma]
        _delta = raw_packet[alpha + beta + gamma:]
        return cls(SphinxHeader(_alpha, _beta, _gamma), SphinxBody(_delta))


@attr.s(frozen=True)
class UnwrappedMessage(object):
    """
    I am the returned result of calling `sphinx_packet_unwrap`.
    """
    next_hop = attr.ib(validator=attr.validators.optional(attr.validators.instance_of(tuple)))
    exit_hop = attr.ib(validator=attr.validators.optional(attr.validators.instance_of(tuple)))
    client_hop = attr.ib(validator=attr.validators.optional(attr.validators.instance_of(tuple)))


# Decode the prefix-free encoding.
# Returns the type, value, and the remainder of the input string
def prefix_free_decode(s):
    if len(s) == 0:
        return None, None, None
    if isinstance(s[0], int):
        l = s[0]
    else:
        l = ord(s[0])
    if l == 0:
        return 'process', None, s[1:]
    if l == 255:
        return 'mix', s[:SECURITY_PARAMETER], s[SECURITY_PARAMETER:]
    if l < 128:
        return 'client', s[1:l + 1], s[l + 1:]
    return None, None, None


@zope.interface.implementer(IPacketReplayCache)
class PacketReplayCacheDict:
    """
    I am an implementation of IPacketReplayCache,
    that uses a dict to implement our replay cache;
    this helps us detect sphinx packet replays.
    """

    def __init__(self):
        self.cache = {}

    def has_seen(self, tag):
        return tag in self.cache

    def set_seen(self, tag):
        self.cache[tag] = True

    def flush(self):
        self.cache = {}


def sphinx_packet_unwrap(params, replay_cache, key_state, sphinx_packet):
    """
    sphinx_packet_unwrap returns a UnwrappedMessage given the replay
    cache, private key and a packet or raises an exception if an error
    was encountered
    """
    assert isinstance(params, SphinxParams)
    assert IPacketReplayCache.providedBy(replay_cache)
    assert IKeyState.providedBy(key_state)
    assert isinstance(sphinx_packet, SphinxPacket)

    if len(sphinx_packet.body.delta) != params.payload_size:
        raise SphinxBodySizeMismatchError()
    group = GroupCurve25519()
    digest = SphinxDigest()
    stream_cipher = SphinxStreamCipher()
    block_cipher = SphinxLioness()
    if not group.in_group(sphinx_packet.header.alpha):
        raise HeaderAlphaGroupMismatchError()
    s = group.expon(sphinx_packet.header.alpha, key_state.get_private_key())
    tag = digest.hash_replay(s)
    if replay_cache.has_seen(tag):
        raise ReplayError()
    if sphinx_packet.header.gamma != digest.hmac(digest.create_hmac_key(s), sphinx_packet.header.beta):
        raise IncorrectMACError()
    replay_cache.set_seen(tag)
    payload = block_cipher.decrypt(block_cipher.create_block_cipher_key(s), sphinx_packet.body.delta)
    B = xor(sphinx_packet.header.beta + (b"\x00" * (2 * SECURITY_PARAMETER)), stream_cipher.generate_stream(digest.create_stream_cipher_key(s), params.beta_cipher_size))
    message_type, val, rest = prefix_free_decode(B)

    if message_type == "mix":
        b = digest.hash_blinding(sphinx_packet.header.alpha, s)
        alpha = group.expon(sphinx_packet.header.alpha, b)
        gamma = B[SECURITY_PARAMETER:SECURITY_PARAMETER * 2]
        beta = B[SECURITY_PARAMETER * 2:]
        unwrapped_sphinx_packet = SphinxPacket(
            header=SphinxHeader(alpha, beta, gamma),
            body=SphinxBody(payload)
        )
        result = UnwrappedMessage(next_hop = (val, unwrapped_sphinx_packet), exit_hop=None, client_hop=None)
        return result
    elif message_type == "process":
        if payload[:SECURITY_PARAMETER] == (b"\x00" * SECURITY_PARAMETER):
            inner_type, val, rest = prefix_free_decode(payload[SECURITY_PARAMETER:])
            if inner_type == "client":
                # We're to deliver rest (unpadded) to val
                body = remove_padding(rest)
                result = UnwrappedMessage(exit_hop = (val, body), next_hop=None, client_hop=None)
                return result
        raise InvalidProcessDestinationError()
    elif message_type == "client":
        id = rest[:SECURITY_PARAMETER]
        result = UnwrappedMessage(client_hop = (val, id, SphinxBody(payload)), exit_hop=None, next_hop=None)
        return result
    raise InvalidMessageTypeError()
