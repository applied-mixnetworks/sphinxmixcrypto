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
import functools

from sphinxmixcrypto.crypto_primitives import CURVE25519_SIZE
from sphinxmixcrypto.crypto_primitives import SECURITY_PARAMETER, xor
from sphinxmixcrypto.crypto_primitives import SphinxLioness, SphinxStreamCipher, SphinxDigest, GroupCurve25519
from sphinxmixcrypto.padding import add_padding, remove_padding
from sphinxmixcrypto.interfaces import IMixPKI
from sphinxmixcrypto.errors import CorruptMessageError


def is_16bytes(instance, attribute, value):
    """
    validator for a 16 byte value
    """
    if not isinstance(value, bytes) or len(value) != 16:
        raise ValueError("must be 16 byte value")


def is_32bytes(instance, attribute, value):
    """
    validator for a 32 byte value
    """
    if not isinstance(value, bytes) or len(value) != 32:
        raise ValueError("must be 32 byte value")


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

    def get_sphinx_forward_size(self):
        return functools.reduce(lambda a, b: a + b, self.get_dimensions(), 0)

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
class ClientMessage(object):
    message_id = attr.ib(validator=is_16bytes)
    payload = attr.ib(validator=attr.validators.instance_of(bytes))


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


@attr.s(frozen=True)
class ReplyBlockDecryptionToken(object):
    """
    I am a single-use decryption token providing decryption of a ciphertext
    message that was composed using a single-use reply block.
    """

    message_id = attr.ib(validator=is_16bytes)
    keys = attr.ib(validator=attr.validators.instance_of(list))

    def decrypt(self, ciphertext):
        """
        decrypt the ciphertext which was composed using the
        corresponding reply block.
        returns a ClientMessage containing the destination and plaintext payload.
        """
        block_cipher = SphinxLioness()
        ktilde = self.keys.pop(0)
        route_len = len(self.keys)
        delta = ciphertext
        for i in range(route_len - 1, -1, -1):
            delta = block_cipher.encrypt(self.keys[i], delta)
        delta = block_cipher.decrypt(
            block_cipher.create_block_cipher_key(ktilde), delta
        )

        if delta[:SECURITY_PARAMETER] == (b"\x00" * SECURITY_PARAMETER):
            plaintext_message = remove_padding(delta[SECURITY_PARAMETER:])
            return ClientMessage(self.message_id, plaintext_message)

        raise CorruptMessageError


@attr.s(frozen=True)
class ReplyBlock(object):
    """
    hello, I'm a single-use encryption/delivery token with a short lifetime,
    also known as a SURB - single use reply block. Reply blocks are of course
    vulnerable to deanonymization in the "compulsion threat model" where the
    adversary can force multiple mix operators to decrypt Sphinx packets.

    Lifetime, is controlled by mix key rotation which is relatively
    frequent in order to protect against the compulsion
    threat. However let it be known there are other defenses against
    the compulsion threat as described in these papers:

    1. Compulsion Resistant Anonymous Communications by George Danezis and Jolyon Clulow
    https://www.freehaven.net/anonbib/cache/ih05-danezisclulow.pdf

    2. Forward Secure Mixes by by George Danezis
    https://www.freehaven.net/anonbib/cache/Dan:SFMix03.pdf
    """
    header = attr.ib(validator=attr.validators.instance_of(SphinxHeader))
    destination = attr.ib(validator=is_16bytes)  # first mix hop
    key = attr.ib(validator=is_32bytes)

    @staticmethod
    def compose_reply_block(message_id, params, route, pki, dest, rand_reader):
        """
        Create a single use reply block and the corresponding decryption token.

        :param SphinxParams params: An instance of SphinxParams.

        :param route: A list of 16 byte mix node IDs.

        :param pki: An IMixPKI provider.

        :param dest: A "prefix free encoded" destination type or client ID.

        :param plaintext_message: The plaintext message.

        :param rand_reader: Source of entropy, an IReader provider.

        :returns: a 3-tuple, a 16 byte message ID, key tuple and reply block tuple
        """
        assert IMixPKI.providedBy(pki)

        block_cipher = SphinxLioness()
        # Compute the header and the secrets
        header, secrets = create_header(params, route, pki, destination_encode(dest), message_id, rand_reader)

        # ktilde is 32 bytes because our create_block_cipher_key
        # requires a 32 byte input. However in the Sphinx reference
        # implementation the block cipher key creator function called "hpi"
        # allows any size input. ktilde was previously 16 bytes.
        ktilde = rand_reader.read(32)
        keys = [ktilde]
        keys.extend([block_cipher.create_block_cipher_key(x) for x in secrets])
        return ReplyBlockDecryptionToken(message_id, keys), ReplyBlock(header, route[0], ktilde)

    def compose_forward_message(self, params, message):
        """
        compose a sphinx packet
        """
        assert isinstance(params, SphinxParams)
        block_cipher = SphinxLioness()
        key = block_cipher.create_block_cipher_key(self.key)
        block = add_padding((b"\x00" * SECURITY_PARAMETER) + message, params.payload_size)
        return SphinxPacket(self.header, SphinxBody(block_cipher.encrypt(key, block)))
