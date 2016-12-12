#!/usr/bin/env python

# Copyright 2011 Ian Goldberg
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
This SphinxNode module includes cryptographic algorithms for mix net nodes
"""

import os
import re
import binascii


class HeaderAlphaGroupMismatchError(Exception):
    pass


class ReplayError(Exception):
    pass


class IncorrectMACError(Exception):
    pass


class InvalidSpecialDestinationError(Exception):
    pass


class NoSuchClientError(Exception):
    pass


class InvalidMessageTypeError(Exception):
    pass


class NoSURBSAvailableError(Exception):
    pass


class KeyMismatchError(Exception):
    pass


class BlockSizeMismatchError(Exception):
    pass


DSPEC = b"\x00"  # The special destination


def pad_body(msgtotalsize, body):
    """
    pad_body appends padding to the body of a message.
    Given the total size and the message data a new
    padded message is returned.
    """
    body = bytes(body) + b"\x7f"
    body = body + (b"\xff" * (msgtotalsize - len(body)))
    return body


def unpad_body(body):
    """
    unpad_body performs the inverse of pad_body
    """
    return re.compile(b"\x7f\xff*$").sub(b"", body)


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


def generate_node_id_name(id_len):
    idnum = os.urandom(4)
    id = generate_node_id(id_len, idnum)
    name = "Node " + str(binascii.b2a_hex(idnum))
    return id, name


def generate_node_keypair(group):
    private_key = group.gensecret()
    public_key = group.expon(group.generator, private_key)
    return public_key, private_key


class UnwrappedMessage:
    def __init__(self):
        self.tuple_next_hop = ()
        self.tuple_exit_hop = ()
        self.tuple_client_hop = ()


class SphinxNodeState:
    def __init__(self):
        self.private_key = None
        self.public_key = None
        self.id = None
        self.name = None


class SphinxNode:
    def __init__(self, params, state=None):
        self.params = params
        if state is None:
            self.public_key, self.private_key = generate_node_keypair(self.params.group)
            self.id, self.name = generate_node_id_name(self.params.k)
        else:
            assert isinstance(state, SphinxNodeState)
            self.private_key = state.private_key
            self.public_key = state.public_key
            self.id = state.id
            self.name = state.name
        self.received = []
        self.seen = {}

    def get_id(self):
        return self.id

    # Decode the prefix-free encoding.  Return the type, value, and the
    # remainder of the input string
    def _prefix_free_decode(self, s):
        if len(s) == 0:
            return None, None, None
        if isinstance(s[0], int):
            l = s[0]
        else:
            l = ord(s[0])
        if l == 0:
            return 'Dspec', None, s[1:]
        if l == 255:
            return 'node', s[:self.params.k], s[self.params.k:]
        if l < 128:
            return 'dest', s[1:l + 1], s[l + 1:]
        return None, None, None

    def unwrap(self, header, payload):
        """
        unwrap returns a UnwrappedMessage given a header and payload
        or raises an exception if an error was encountered
        """
        print "UNWRAP"
        result = UnwrappedMessage()
        p = self.params
        group = p.group
        alpha, beta, gamma = header

        if not group.in_group(alpha):
            raise HeaderAlphaGroupMismatchError()
        s = group.expon(alpha, self.private_key)
        tag = p.htau(s)

        if tag in self.seen:
            raise ReplayError()
        if gamma != p.mu(p.hmu(s), beta):
            raise IncorrectMACError()

        self.seen[tag] = 1
        B = p.xor(beta + (b"\x00" * (2 * p.k)), p.rho(p.create_stream_cipher_key(s)))
        message_type, val, rest = self._prefix_free_decode(B)

        if message_type == "node":
            b = p.hb(alpha, s)
            alpha = group.expon(alpha, b)
            gamma = B[p.k:p.k * 2]
            beta = B[p.k * 2:]

            # XXX this may raise KeyMismatchError or BlockSizeMismatchError
            payload = p.pii(p.create_block_cipher_key(s), payload)

            result.tuple_next_hop = (val, (alpha, beta, gamma), payload)
            return result
        elif message_type == "Dspec":
            payload = p.pii(p.create_block_cipher_key(s), payload)
            if payload[:p.k] == (b"\x00" * p.k):
                inner_type, val, rest = self._prefix_free_decode(payload[p.k:])
                if inner_type == "dest":
                    # We're to deliver rest (unpadded) to val
                    body = unpad_body(rest)
                    self.received.append(body)
                    result.tuple_exit_hop = (val, body)
                    return result
            raise InvalidSpecialDestinationError()
        elif message_type == "dest":
            id = rest[:p.k]
            payload = p.pii(p.create_block_cipher_key(s), payload)
            if val in p.clients:  # val is client-id
                result.tuple_client_hop = (val, id, payload)
                return result
            else:
                raise NoSuchClientError()
        raise InvalidMessageTypeError()
