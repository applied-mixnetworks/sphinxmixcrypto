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

import os
import binascii

from sphinxmixcrypto.node import destination_encode, DSPEC
from sphinxmixcrypto.padding import add_padding, remove_padding


def rand_subset(lst, nu):
    """
    Return a list of nu random elements of the given list (without
    replacement).
    """
    # Randomize the order of the list by sorting on a random key
    nodeids = [(os.urandom(8), x) for x in lst]
    nodeids.sort(key=lambda x: x[0])
    # Return the first nu elements of the randomized list
    return [x[1] for x in nodeids[:nu]]


def create_header(params, route, node_map, dest, id, secret=None, padding=None):
    route_len = len(route)
    assert len(dest) <= 2 * (params.r - route_len + 1) * params.k
    assert route_len <= params.r
    assert len(id) == params.k
    if padding is None:
        padding = os.urandom(((2 * (params.r - route_len) + 2) * params.k - len(dest)))
    else:
        assert len(padding) == ((2 * (params.r - route_len) + 2) * params.k - len(dest))
    p = params
    group = p.group
    if secret is None:
        x = group.gensecret()
    else:
        x = group.makesecret(secret)

    # Compute the (alpha, s, b) tuples
    blinds = [x]
    asbtuples = []
    for node in route:
        alpha = group.multiexpon(group.generator, blinds)
        s = group.multiexpon(node_map[node], blinds)
        b = p.hb(alpha, s)
        blinds.append(b)
        asbtuples.append({'alpha': alpha, 's': s, 'b': b})

    # Compute the filler strings
    phi = b''
    for i in range(1, route_len):
        min = (2 * (p.r - i) + 3) * p.k
        phi = p.xor(phi + (b"\x00" * (2 * p.k)),
                    p.rho(p.create_stream_cipher_key(asbtuples[i - 1]['s']))[min:])

    # Compute the (beta, gamma) tuples
    beta = dest + id + padding
    beta = p.xor(beta,
                 p.rho(p.create_stream_cipher_key(asbtuples[route_len - 1]['s']))[:(2 * (p.r - route_len) + 3) * p.k]) + phi
    gamma_key = p.hmu(asbtuples[route_len - 1]['s'])
    gamma = p.mu(gamma_key, beta)
    for i in range(route_len - 2, -1, -1):
        id = route[i + 1]
        assert len(id) == p.k
        beta = p.xor(id + gamma + beta[:(2 * p.r - 1) * p.k],
                     p.rho(p.create_stream_cipher_key(asbtuples[i]['s']))[:(2 * p.r + 1) * p.k])
        gamma = p.mu(p.hmu(asbtuples[i]['s']), beta)
    return (asbtuples[0]['alpha'], beta, gamma), [y['s'] for y in asbtuples]


def create_forward_message(params, route, node_map, dest, msg, secret=None, padding=None):
    p = params
    route_len = len(route)
    assert len(dest) < 128 and len(dest) > 0
    assert p.k + 1 + len(dest) + len(msg) < p.m
    # Compute the header and the secrets
    header, secrets = create_header(params, route, node_map, DSPEC, b"\x00" * p.k, secret=secret, padding=padding)
    encoded_dest = destination_encode(dest)
    body = (b"\x00" * p.k) + bytes(encoded_dest) + bytes(msg)
    padded_body = add_padding(body, p.m)
    # Compute the delta values
    key = p.create_block_cipher_key(secrets[route_len - 1])
    delta = p.pi(key, padded_body)
    for i in range(route_len - 2, -1, -1):
        delta = p.pi(p.create_block_cipher_key(secrets[i]), delta)
    alpha, beta, gamma = header
    return alpha, beta, gamma, delta


def create_surb(params, route, node_map, dest):
    p = params
    id = os.urandom(p.k)

    # Compute the header and the secrets
    header, secrets = create_header(params, route, node_map, destination_encode(dest), id)

    # ktilde is 32 bytes because our create_block_cipher_key
    # requires a 32 byte input. However in the Sphinx reference
    # implementation the block cipher key creator function called "hpi"
    # allows any size input. ktilde was previously 16 bytes.
    ktilde = os.urandom(32)
    keytuple = [ktilde]
    keytuple.extend([p.create_block_cipher_key(x) for x in secrets])
    return id, keytuple, (route[0], header, ktilde)


class NymKeyNotFoundError(Exception):
    pass


class CorruptMessageError(Exception):
    pass


class ClientMessage:
    def __init__(self):
        self.payload = None


class SphinxClient:
    def __init__(self, params, id=None):
        self.params = params
        if id is None:
            self.id = b"Client " + bytes(str(binascii.hexlify(os.urandom(4))).encode("utf-8"))
        else:
            self.id = id
        params.clients[self.id] = self
        self.keytable = {}

    def create_nym(self, route, node_map):
        """Create a SURB for the given nym (passing through nllength
        nodes), and send it to the nymserver."""

        message_id, keytuple, nymtuple = create_surb(self.params, route, node_map, self.id)
        self.keytable[message_id] = keytuple
        return nymtuple

    def decrypt(self, message_id, delta):
        """
        decrypt reply message
        """
        message = ClientMessage()
        p = self.params
        keytuple = self.keytable.pop(message_id, None)

        if keytuple is None:
            raise NymKeyNotFoundError
        ktilde = keytuple.pop(0)
        route_len = len(keytuple)
        for i in range(route_len - 1, -1, -1):
            delta = p.pi(keytuple[i], delta)
        delta = p.pii(p.create_block_cipher_key(ktilde), delta)

        if delta[:p.k] == (b"\x00" * p.k):
            msg = remove_padding(delta[p.k:])
            message.tuple_message = (self.id, msg)
            return message

        raise CorruptMessageError
