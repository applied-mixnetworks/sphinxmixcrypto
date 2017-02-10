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

import attr

from sphinxmixcrypto.crypto_primitives import CURVE25519_SIZE
from sphinxmixcrypto.crypto_primitives import SECURITY_PARAMETER, xor
from sphinxmixcrypto.crypto_primitives import SphinxLioness, SphinxStreamCipher, SphinxDigest, GroupCurve25519
from sphinxmixcrypto.padding import add_padding, remove_padding
from sphinxmixcrypto.interfaces import IReader, IMixPKI
from sphinxmixcrypto.errors import NymKeyNotFoundError, CorruptMessageError


def destination_encode(dest):
    """
    encode destination
    """
    assert len(dest) >= 1 and len(dest) <= 127
    return b"%c" % len(dest) + dest


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

    def elements_from_raw_bytes(self, raw_packet):
        """
        return the Sphinx packet elements, a 4-tuple
        of byte slices: alpha, beta, gamma and delta.
        """
        alpha, beta, gamma, delta = self.get_dimensions()
        assert len(raw_packet) == alpha + beta + gamma + delta
        _alpha = raw_packet[:alpha]
        _beta = raw_packet[alpha:alpha + beta]
        _gamma = raw_packet[alpha + beta:alpha + beta + gamma]
        _delta = raw_packet[alpha + beta + gamma:]
        return _alpha, _beta, _gamma, _delta


@attr.s(frozen=True)
class SphinxHeader(object):
    """
    The Sphinx header.

    The Sphinx paper refers to the header fields as the greek letters: alpha, beta and gamma.
    """
    alpha = attr.ib(validator=attr.validators.instance_of(bytes))
    beta = attr.ib(validator=attr.validators.instance_of(bytes))
    gamma = attr.ib(validator=attr.validators.instance_of(bytes))


def create_header(params, route, pki, dest, message_id, rand_reader):
    """
    Create a sphinx header, used to construct forward messages and reply blocks.

    :param SphinxParams params: An instance of SphinxParams.

    :param route: A list of 16 byte mix node IDs.

    :param pki: An IMixPKI provider.

    :param dest: A "prefix free encoded" destination type or client ID.

    :param message_id: Message identifier.

    :param rand_reader: Source of entropy, an IReader provider.

    :returns: a 2-tuple, a SphinxHeader and a list of shared secrets for each hop in the route.
    """
    assert IMixPKI.providedBy(pki)
    route_len = len(route)
    assert len(dest) <= 2 * (params.max_hops - route_len + 1) * SECURITY_PARAMETER
    assert route_len <= params.max_hops
    assert len(message_id) == SECURITY_PARAMETER

    group = GroupCurve25519()
    digest = SphinxDigest()
    stream_cipher = SphinxStreamCipher()
    x = group.gensecret(rand_reader)
    padding = rand_reader.read(((2 * (params.max_hops - route_len) + 2) * SECURITY_PARAMETER - len(dest)))

    # Compute the (alpha, s, b) tuples
    blinds = [x]
    asbtuples = []
    for node_id in route:
        alpha = group.multiexpon(group.generator, blinds)
        s = group.multiexpon(pki.get(node_id), blinds)
        b = digest.hash_blinding(alpha, s)
        blinds.append(b)
        asbtuples.append({'alpha': alpha, 's': s, 'b': b})

    # Compute the filler strings
    phi = b''
    stream_cipher = SphinxStreamCipher()
    for i in range(1, route_len):
        min = (2 * (params.max_hops - i) + 3) * SECURITY_PARAMETER
        phi = xor(phi + (b"\x00" * (2 * SECURITY_PARAMETER)),
                  stream_cipher.generate_stream(digest.create_stream_cipher_key(asbtuples[i - 1]['s']), params.beta_cipher_size)[min:])

    # Compute the (beta, gamma) tuples
    beta = dest + message_id + padding
    stream_key = digest.create_stream_cipher_key(asbtuples[route_len - 1]['s'])
    beta = xor(beta,
               stream_cipher.generate_stream(stream_key, (2 * (params.max_hops - route_len) + 3) * SECURITY_PARAMETER)[:(2 * (params.max_hops - route_len) + 3) * SECURITY_PARAMETER]) + phi
    gamma_key = digest.create_hmac_key(asbtuples[route_len - 1]['s'])
    gamma = digest.hmac(gamma_key, beta)
    for i in range(route_len - 2, -1, -1):
        message_id = route[i + 1]
        assert len(message_id) == SECURITY_PARAMETER
        stream_key = digest.create_stream_cipher_key(asbtuples[i]['s'])
        beta = xor(message_id + gamma + beta[:(2 * params.max_hops - 1) * SECURITY_PARAMETER],
                   stream_cipher.generate_stream(stream_key, params.beta_cipher_size)[:(2 * params.max_hops + 1) * SECURITY_PARAMETER])
        gamma = digest.hmac(digest.create_hmac_key(asbtuples[i]['s']), beta)
    sphinx_header = SphinxHeader(asbtuples[0]['alpha'], beta, gamma)
    return sphinx_header, [y['s'] for y in asbtuples]


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
        return b"".join((self.header.alpha, self.header.beta,
                        self.header.gamma, self.body.delta))

    @classmethod
    def from_raw_bytes(cls, params, raw_packet):
        """
        Create a SphinxPacket given the raw bytes and
        an instance of SphinxParams.
        """
        assert isinstance(params, SphinxParams)
        alpha, beta, gamma, delta = params.elements_from_raw_bytes(raw_packet)
        return cls(SphinxHeader(alpha, beta, gamma), SphinxBody(delta))

    @classmethod
    def forward_message(cls, params, route, pki, dest, plaintext_message, rand_reader):
        """
        Create a new SphinxPacket, a forward message.

        :param SphinxParams params: An instance of SphinxParams.

        :param route: A list of 16 byte mix node IDs.

        :param pki: An IMixPKI provider.

        :param dest: A "prefix free encoded" destination type or client ID.

        :param plaintext_message: The plaintext message.

        :param rand_reader: Source of entropy, an IReader provider.

        :returns: a SphinxPacket.
        """
        assert IMixPKI.providedBy(pki)

        route_len = len(route)
        assert len(dest) < 128 and len(dest) > 0
        assert SECURITY_PARAMETER + 1 + len(dest) + len(plaintext_message) < params.payload_size
        block_cipher = SphinxLioness()

        # Compute the header and the secrets
        header, secrets = create_header(params, route, pki, b"\x00", b"\x00" * SECURITY_PARAMETER, rand_reader)
        encoded_dest = destination_encode(dest)
        body = (b"\x00" * SECURITY_PARAMETER) + bytes(encoded_dest) + bytes(plaintext_message)
        padded_body = add_padding(body, params.payload_size)

        # Compute the delta values
        block_cipher = SphinxLioness()
        key = block_cipher.create_block_cipher_key(secrets[route_len - 1])
        delta = block_cipher.encrypt(key, padded_body)
        for i in range(route_len - 2, -1, -1):
            delta = block_cipher.encrypt(block_cipher.create_block_cipher_key(secrets[i]), delta)

        return cls(header, SphinxBody(delta))


def create_reply_block(params, route, pki, dest, rand_reader):
    """
    Create a single use reply block, a SURB. Reply blocks are used
    to achieve recipient anonymity.

    :param SphinxParams params: An instance of SphinxParams.

    :param route: A list of 16 byte mix node IDs.

    :param pki: An IMixPKI provider.

    :param dest: A "prefix free encoded" destination type or client ID.

    :param plaintext_message: The plaintext message.

    :param rand_reader: Source of entropy, an IReader provider.

    :returns: a 3-tuple, a 16 byte message ID, key tuple and reply block tuple
    """
    assert IMixPKI.providedBy(pki)

    message_id = rand_reader.read(SECURITY_PARAMETER)
    block_cipher = SphinxLioness()
    # Compute the header and the secrets
    header, secrets = create_header(params, route, pki, destination_encode(dest), message_id, rand_reader)

    # ktilde is 32 bytes because our create_block_cipher_key
    # requires a 32 byte input. However in the Sphinx reference
    # implementation the block cipher key creator function called "hpi"
    # allows any size input. ktilde was previously 16 bytes.
    ktilde = rand_reader.read(32)
    keytuple = [ktilde]
    keytuple.extend([block_cipher.create_block_cipher_key(x) for x in secrets])
    return message_id, keytuple, (route[0], header, ktilde)


@attr.s(frozen=True)
class ClientMessage(object):
    identity = attr.ib(validator=attr.validators.instance_of(bytes))
    payload = attr.ib(validator=attr.validators.instance_of(bytes))


@attr.s
class SphinxClient(object):

    params = attr.ib(validator=attr.validators.instance_of(SphinxParams))
    client_id = attr.ib(validator=attr.validators.instance_of(bytes))
    rand_reader = attr.ib(validator=attr.validators.provides(IReader))
    _keytable = attr.ib(init=False, default={})

    def create_nym(self, route, pki):
        """
        Create a SURB for the given nym (passing through nllength
        nodes), and send it to the nymserver.
        """
        assert IMixPKI.providedBy(pki)

        message_id, keytuple, nymtuple = create_reply_block(self.params, route, pki, self.client_id, self.rand_reader)
        self._keytable[message_id] = keytuple
        return nymtuple

    def decrypt(self, message_id, delta):
        """
        decrypt reply message
        returns a ClientMessage
        """
        keytuple = self._keytable.pop(message_id, None)
        block_cipher = SphinxLioness()
        if keytuple is None:
            raise NymKeyNotFoundError
        ktilde = keytuple.pop(0)
        route_len = len(keytuple)
        for i in range(route_len - 1, -1, -1):
            delta = block_cipher.encrypt(keytuple[i], delta)
        delta = block_cipher.decrypt(
            block_cipher.create_block_cipher_key(ktilde), delta
        )

        if delta[:SECURITY_PARAMETER] == (b"\x00" * SECURITY_PARAMETER):
            plaintext_message = remove_padding(delta[SECURITY_PARAMETER:])
            return ClientMessage(identity=self.client_id, payload=plaintext_message)

        raise CorruptMessageError
