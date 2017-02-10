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

from sphinxmixcrypto.client import SphinxPacket, SphinxHeader, SphinxBody, SphinxParams
from sphinxmixcrypto.padding import remove_padding
from sphinxmixcrypto.interfaces import IPacketReplayCache, IKeyState
from sphinxmixcrypto.crypto_primitives import SECURITY_PARAMETER, GroupCurve25519, SphinxDigest
from sphinxmixcrypto.crypto_primitives import SphinxStreamCipher, SphinxLioness, xor, CURVE25519_SIZE
from sphinxmixcrypto.errors import HeaderAlphaGroupMismatchError, ReplayError, IncorrectMACError
from sphinxmixcrypto.errors import InvalidProcessDestinationError, InvalidMessageTypeError
from sphinxmixcrypto.errors import SphinxBodySizeMismatchError


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
    sphinx_packet_unwrap performs the decryption operation for mixes.
    replayed packets and packets with bad MACs are rejected.
    after unwrapping the message type is identified, the data is placed
    in UnwrappedMessage's appropriate tuple.

    :param SphinxParams params: An instance of SphinxParams.

    :param replay_cache: An IPacketReplayCache provider.

    :param key_state: An IKeyState provider.

    :param SphinxPacket sphinx_packet: An instance of SphinxPacket.

    :returns: an UnwrappedMessage.
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
