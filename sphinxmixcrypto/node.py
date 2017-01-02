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

import binascii
import zope.interface

from sphinxmixcrypto.padding import remove_padding
from sphinxmixcrypto.common import IPacketReplayCache, ISphinxNodeState
from sphinxmixcrypto.crypto_primitives import SECURITY_PARAMETER, GroupCurve25519, SphinxDigest, PAYLOAD_SIZE
from sphinxmixcrypto.crypto_primitives import SphinxStreamCipher, SphinxLioness, xor


class HeaderAlphaGroupMismatchError(Exception):
    pass


class ReplayError(Exception):
    pass


class IncorrectMACError(Exception):
    pass


class InvalidProcessDestinationError(Exception):
    pass


class InvalidMessageTypeError(Exception):
    pass


class NoSURBSAvailableError(Exception):
    pass


class KeyMismatchError(Exception):
    pass


class SphinxBodySizeMismatchError(Exception):
    pass


DSPEC = b"\x00"  # The special destination


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


def destination_encode(dest):
    """
    encode destination
    """
    assert len(dest) >= 1 and len(dest) <= 127
    return b"%c" % len(dest) + dest


def generate_node_id(id_length, idnum):
    """
    generate a new node id
    """
    node_id = b"\xff" + idnum + (b"\x00" * (id_length - len(idnum) - 1))
    return node_id


def generate_node_id_name(id_len, rand_reader):
    idnum = rand_reader.read(4)
    id = generate_node_id(id_len, idnum)
    name = "Node " + str(binascii.b2a_hex(idnum))
    return id, name


def generate_node_keypair(rand_reader):
    group = GroupCurve25519()
    private_key = group.gensecret(rand_reader)
    public_key = group.expon(group.generator, private_key)
    return public_key, private_key


class SphinxPacket:
    def __init__(self, alpha, beta, gamma, delta):
        self.alpha = alpha
        self.beta = beta
        self.gamma = gamma
        self.delta = delta


class UnwrappedMessage:
    def __init__(self):
        self.tuple_next_hop = ()
        self.tuple_exit_hop = ()
        self.tuple_client_hop = ()


@zope.interface.implementer(ISphinxNodeState)
class SphinxNodeState:

    def __init__(self, id, name, public_key, private_key, replay_cache):
        self.id = id
        self.name = name
        self.public_key = public_key
        self.private_key = private_key
        self.replay_cache = replay_cache


@zope.interface.implementer(IPacketReplayCache)
class PacketReplayCacheDict:

    def __init__(self):
        self.cache = {}

    def has_seen(self, tag):
        return tag in self.cache

    def set_seen(self, tag):
        self.cache[tag] = True

    def flush(self):
        self.cache = {}


def sphinx_packet_unwrap(node_state, packet):
    """
    sphinx_packet_unwrap returns a UnwrappedMessage given a node_state
    and a packet or raises an exception if an error was encountered,
    where the node_state provides the ISphinxNodeState interface and
    the packet is an instance of SphinxPacket.
    """

    assert ISphinxNodeState.providedBy(node_state)
    if len(packet.delta) != PAYLOAD_SIZE:
        raise SphinxBodySizeMismatchError()
    result = UnwrappedMessage()
    group = GroupCurve25519()
    digest = SphinxDigest()
    stream_cipher = SphinxStreamCipher()
    block_cipher = SphinxLioness()
    if not group.in_group(packet.alpha):
        raise HeaderAlphaGroupMismatchError()
    s = group.expon(packet.alpha, node_state.private_key)
    tag = digest.hash_replay(s)
    if node_state.replay_cache.has_seen(tag):
        raise ReplayError()
    if packet.gamma != digest.hmac(digest.create_hmac_key(s), packet.beta):
        raise IncorrectMACError()
    node_state.replay_cache.set_seen(tag)
    payload = block_cipher.decrypt(block_cipher.create_block_cipher_key(s), packet.delta)
    B = xor(packet.beta + (b"\x00" * (2 * SECURITY_PARAMETER)), stream_cipher.generate_stream(digest.create_stream_cipher_key(s)))
    message_type, val, rest = prefix_free_decode(B)

    if message_type == "mix":
        b = digest.hash_blinding(packet.alpha, s)
        alpha = group.expon(packet.alpha, b)
        gamma = B[SECURITY_PARAMETER:SECURITY_PARAMETER * 2]
        beta = B[SECURITY_PARAMETER * 2:]
        result.tuple_next_hop = (val, (alpha, beta, gamma), payload)
        return result
    elif message_type == "process":
        if payload[:SECURITY_PARAMETER] == (b"\x00" * SECURITY_PARAMETER):
            inner_type, val, rest = prefix_free_decode(payload[SECURITY_PARAMETER:])
            if inner_type == "client":
                # We're to deliver rest (unpadded) to val
                body = remove_padding(rest)
                result.tuple_exit_hop = (val, body)
                return result
        raise InvalidProcessDestinationError()
    elif message_type == "client":
        id = rest[:SECURITY_PARAMETER]
        result.tuple_client_hop = (val, id, payload)
        return result
    raise InvalidMessageTypeError()
