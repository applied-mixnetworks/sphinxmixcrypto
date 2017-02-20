
import py.test
import zope.interface
import binascii
import os
from Cryptodome.Cipher import ChaCha20

from sphinxmixcrypto.crypto_primitives import SphinxLioness, GroupCurve25519
from sphinxmixcrypto import SphinxHeader, SphinxBody, SphinxPacket, sphinx_packet_unwrap
from sphinxmixcrypto import PacketReplayCacheDict, ReplayError, SECURITY_PARAMETER, create_header
from sphinxmixcrypto import IncorrectMACError, HeaderAlphaGroupMismatchError, destination_encode
from sphinxmixcrypto import add_padding, InvalidProcessDestinationError, InvalidMessageTypeError, SphinxBodySizeMismatchError
from sphinxmixcrypto import SphinxParams, CorruptMessageError, UnwrappedMessage
from sphinxmixcrypto import IReader, IMixPKI, IKeyState, ReplyBlock, ReplyBlockDecryptionToken
from sphinxmixcrypto import _metadata


def use_metadata():
    return _metadata.__version__


@zope.interface.implementer(IReader)
class RandReader:
    def __init__(self):
        pass

    def read(self, n):
        return os.urandom(n)


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


@zope.interface.implementer(IReader)
class ChachaNoiseReader():
    """
    hello, i am an entropy "iterator". sphinx uses a source of entropy
    for generation of key material. i'm deterministic so use me to
    write deterministic tests.
    """
    def __init__(self, seed_string):
        assert isinstance(seed_string, str) and len(seed_string) == 64
        self.cipher = ChaCha20.new(key=binascii.unhexlify(seed_string), nonce=b"\x00" * 8)

    def read(self, n):
        return self.cipher.encrypt(b"\x00" * n)


def test_chacha_noise_reader():
    rand_reader = ChachaNoiseReader("47ade5905376604cde0b57e732936b4298281c8a67b6a62c6107482eb69e2941")
    r = rand_reader.read(32)
    assert r == binascii.unhexlify("feedc80ac8ab0e7cb9beb86eb9a3cd16455204c964aedb628df25e54d58fe4a0")


@zope.interface.implementer(IKeyState)
class SphinxNodeKeyState:

    def __init__(self, private_key):
        self.private_key = private_key

    def get_private_key(self):
        return self.private_key

    def get_public_key(self):
        pass


@zope.interface.implementer(IMixPKI)
class DummyPKI(object):

    def __init__(self):
        self.node_map = {}
        self.addr_map = {}

    def set(self, node_id, pub_key, addr):
        assert node_id not in self.node_map.keys()
        self.node_map[node_id] = pub_key
        self.addr_map[node_id] = addr

    def get(self, node_id):
        return self.node_map[node_id]

    def identities(self):
        return self.node_map.keys()

    def set_client_addr(self, transport_name, client_id, addr):
        pass

    def get_client_addr(self, transport_name, client_id):
        pass

    def get_mix_addr(self, transport_name, node_id):
        return self.addr_map[node_id]

    def rotate(self, node_id, new_pub_key, signature):
        pass


def test_sphinx_params():
    params = SphinxParams(5, 1024)
    alpha, beta, gamma, delta = params.get_dimensions()
    assert alpha == 32
    assert beta == 176
    assert gamma == 16
    assert delta == 1024


class TestSphinxCorrectness():

    def newTestRoute(self, numHops):
        self.pki = DummyPKI()
        rand_reader = RandReader()
        self.private_key_map = {}
        for i in range(numHops):
            public_key, private_key = generate_node_keypair(rand_reader)
            id, name = generate_node_id_name(SECURITY_PARAMETER, rand_reader)
            self.pki.set(id, public_key, i)
            self.private_key_map[id] = private_key
        route = rand_subset(self.pki.identities(), numHops)
        return route

    def test_sphinx_single_hop(self):
        route = self.newTestRoute(1)
        destination = b"client"
        message = b"this is a test"
        rand_reader = RandReader()
        params = SphinxParams(5, 1024)
        packet = SphinxPacket.forward_message(params, route, self.pki, destination, message, rand_reader)
        replay_cache = PacketReplayCacheDict()
        key_state = SphinxNodeKeyState(self.private_key_map[route[0]])
        result = sphinx_packet_unwrap(params, replay_cache, key_state, packet)
        received_dest, received_message = result.exit_hop
        assert result.client_hop is None
        assert result.next_hop is None
        assert received_dest == destination
        assert received_message == message

    def test_sphinx_replay(self):
        route = self.newTestRoute(5)
        destination = b"client"
        message = b"this is a test"
        rand_reader = RandReader()
        params = SphinxParams(5, 1024)
        packet = SphinxPacket.forward_message(params, route, self.pki, destination, message, rand_reader)
        replay_cache = PacketReplayCacheDict()
        key_state = SphinxNodeKeyState(self.private_key_map[route[0]])
        sphinx_packet_unwrap(params, replay_cache, key_state, packet)
        py.test.raises(ReplayError, sphinx_packet_unwrap, params, replay_cache, key_state, packet)
        replay_cache.flush()
        sphinx_packet_unwrap(params, replay_cache, key_state, packet)

    def test_sphinx_assoc_data(self):
        route = self.newTestRoute(5)
        destination = b"client"
        message = b"this is a test"
        rand_reader = RandReader()
        params = SphinxParams(5, 1024)
        packet = SphinxPacket.forward_message(params, route, self.pki, destination, message, rand_reader)
        packet = SphinxPacket(packet.header, SphinxBody(b"something else"))
        replay_cache = PacketReplayCacheDict()
        key_state = SphinxNodeKeyState(self.private_key_map[route[0]])
        py.test.raises(SphinxBodySizeMismatchError, sphinx_packet_unwrap, params, replay_cache, key_state, packet)

    def test_sphinx_corrupt_mac(self):
        route = self.newTestRoute(5)
        destination = b"client"
        message = b"this is a test"
        rand_reader = RandReader()
        params = SphinxParams(5, 1024)
        packet = SphinxPacket.forward_message(params, route, self.pki, destination, message, rand_reader)
        replay_cache = PacketReplayCacheDict()
        public_key, private_key = generate_node_keypair(rand_reader)
        key_state = SphinxNodeKeyState(private_key)
        py.test.raises(IncorrectMACError, sphinx_packet_unwrap, params, replay_cache, key_state, packet)

    def test_sphinx_alpha_too_big(self):
        route = self.newTestRoute(5)
        destination = b"dest"
        message = b"this is a test"
        rand_reader = RandReader()
        params = SphinxParams(5, 1024)
        packet = SphinxPacket.forward_message(params, route, self.pki, destination, message, rand_reader)
        packet = SphinxPacket(
            SphinxHeader(packet.header.alpha + b"A",
                         packet.header.beta,
                         packet.header.gamma),
            packet.body
        )
        replay_cache = PacketReplayCacheDict()
        public_key, private_key = generate_node_keypair(rand_reader)
        key_state = SphinxNodeKeyState(private_key)
        py.test.raises(HeaderAlphaGroupMismatchError, sphinx_packet_unwrap, params, replay_cache, key_state, packet)


class TestSphinxEnd2End():

    def setUpMixVectors(self):
        hexedState = [
            {
                "id": binascii.unhexlify("ff2182654d0000000000000000000000"),
                "public_key": binascii.unhexlify("d7314c8d2ba771dbe2982fa6299844f1b92736881e78ae7644f4bccbf8817a69"),
                "private_key": binascii.unhexlify("306e5a009897d4e134727037f9b275294bd01fb33c0c7dbe5f1fdaed765d0c47"),
            },
            {
                "id": binascii.unhexlify("ff0f9a62780000000000000000000000"),
                "public_key": binascii.unhexlify("5ce56657b8af66bd47df2469b10065206a2fd777a0cd17b104160256810bc976"),
                "private_key": binascii.unhexlify("98967364dfe5d5f5d0180c727797d9111f3b1da573c25036ba16396579c25048"),
            },
            {
                "id": binascii.unhexlify("ffc74d10550000000000000000000000"),
                "public_key": binascii.unhexlify("47ade5905376604cde0b57e732936b4298281c8a67b6a62c6107482eb69e2941"),
                "private_key": binascii.unhexlify("18c539194baae419f50ff117cbf15456a0762845af3d0a77ba85024ba488ce58"),
            },
            {
                "id": binascii.unhexlify("ffbb0407380000000000000000000000"),
                "public_key": binascii.unhexlify("4704aff4bc2aaaa3fd187d52913a203aba4e19f6e7b491bda8c8e67daa8daa67"),
                "private_key": binascii.unhexlify("781e6fc7636d70dae8ebf2337538b22d7b64281a55505c1f12921e7b61f09c59"),
            },
            {
                "id": binascii.unhexlify("ff81855a360000000000000000000000"),
                "public_key": binascii.unhexlify("73514173ee741afacdd4733e84f629b5cb9e34d28d072d749a8171fc6d64a930"),
                "private_key": binascii.unhexlify("9863a8f1b5307938cd4bc9782411e9eea0a38b9144d096bd923085dfb8534277"),
            },

        ]
        self.pki = DummyPKI()
        self.route = []
        self.params = SphinxParams(5, 1024)
        self.private_key_map = {}
        self.key_state_map = {}
        self.replay_cache_map = {}

        # Create some nodes
        for i in range(len(hexedState)):
            self.route.append(hexedState[i]['id'])
            self.pki.set(hexedState[i]['id'], hexedState[i]['public_key'], i)
            self.private_key_map[hexedState[i]['id']] = hexedState[i]['private_key']
            replay_cache = PacketReplayCacheDict()
            self.replay_cache_map[hexedState[i]['id']] = replay_cache
            key_state = SphinxNodeKeyState(hexedState[i]['private_key'])
            self.key_state_map[hexedState[i]['id']] = key_state

        message_id = binascii.unhexlify("ff81855a360000000000000000000000")
        self.reply_route = []
        for s in hexedState:
            self.reply_route.append(s['id'])
        dest = binascii.unhexlify("0f436c69656e74206665656463383061")

    def test_sphinx_replay(self):
        rand_reader = ChachaNoiseReader("47ade5905376604cde0b57e732936b4298281c8a67b6a62c6107482eb69e2941")
        self.setUpMixVectors()
        message = b"the quick brown fox"
        params = SphinxParams(5, 1024)
        packet = SphinxPacket.forward_message(params, self.route, self.pki,
                                              self.route[-1], message, rand_reader)
        replay_cache = PacketReplayCacheDict()
        key_state = SphinxNodeKeyState(self.private_key_map[self.route[0]])

        sphinx_packet_unwrap(params, replay_cache, key_state, packet)
        py.test.raises(ReplayError, sphinx_packet_unwrap, params, replay_cache, key_state, packet)

    def test_client_surb(self):
        rand_reader = ChachaNoiseReader("47ade5905376604cde0b57e732936b4298281c8a67b6a62c6107482eb69e2941")
        self.setUpMixVectors()
        message_id = binascii.unhexlify("ff81855a360000000000000000000000")
        client_id = binascii.unhexlify("0f436c69656e74206665656463383061")
        self.alice_decryption_token, self.reply_block = ReplyBlock.compose_reply_block(message_id, self.params, self.reply_route, self.pki, client_id, rand_reader)

        message = b"Open, secure and reliable connectivity is necessary (although not sufficient) to excercise the human rights such as freedom of expression and freedom of association [FOC], as defined in the Universal Declaration of Human Rights [UDHR]."
        sphinx_packet = self.reply_block.compose_forward_message(self.params, message)
        unwrapped_message = UnwrappedMessage(next_hop=(self.reply_route[0], sphinx_packet), exit_hop=None, client_hop=None)
        self.alpha = binascii.unhexlify("b00eb0894f1b49530150c33cc4055cf3b97f3cac22f03f25050394bf5d80c954")
        self.beta = binascii.unhexlify("1c162721f4896fa5054be6dec39a00dc8efdf23c574de810ed5e5dca8b0d0ef0b410306377c251f3cb855f466b3f7b696dda60a914e03d6e537fe3e712cbb98e414e0cfec3fd14f0e79b66fc0338820aabb680cc6cb9274b836852bd737ecc121e828697675fc839ebf820ba9d53e17f94b5bad2631f915ae059d4e37fa04b776158f306d92ce2bce232f60412feff11c754450970bba6a318e45f9ce9210202d669c7bf7c38eb1c14b9cda4e6311eba")
        self.gamma = binascii.unhexlify("eff2a11d309fa2c07832c1ecb0917078")
        self.delta = binascii.unhexlify("aac22e90370689f1ef5ded95cc593b4c7fd5b796df440ebfe5ae1a90921312d89bbf76eda53b23a18c6dab15966fd4a4806099b28d6b06723087586e5c56aded125f6c067edccb8322a1696a892498d8d6cfdca2a758d0687b5c6a8a8207e04c0810e2c95da8db03fd5e4f91326b23cd9ccebd403bab33d59184aff393cc26779fbb56d80c10ff10507a9fc24cc61d00f27d27f076439f3c06f97ffbc97a02918aba1d2aceac013ec22d528148295f5e501559d9ed4d9f8064aca4c0ab3542678b24144f1814869d34a536ae2b4f2c6f330cd9f579f048dc592059b126feae908815f1fc4557aabfb559aa218b37b83270e5da67fc0eab152b1971701906ebaf6b7a9510cb766c975ca984098063f079f2fbb7108a59feb87983a15e9cb50cc8b3c8b7c6bdfe435b7feade94be9193df304b4eb09ec7490774b6cbfd7d86663ba59685d3beadcb82cab429bcb7244a5d06e58b3172b858bc87a3b6db5260a5a2cc476dd9b959416e286e8e3579460c9257bcdf3564319d92bd66d1bafe47ddea32f202cdb1f0bf64ef23abb37b251026437a1dc6e260dbf63d387067b35a27ea70fd6cde2a2f6037b58f433bc22f18d944c90e05ab9d8b22ef06ad8ce3ac98afb39f0ec823f64ee8b620ab332b65b275f2b11ddd722ba51771286add25193b8dbbee47bf188f78aea393337a50c2353910a849abe81a30d77ffdb3483480ff81af8d5d298c912606c1a92eac84e37c9ac24885b8e8bfd39fdfe68dbb2e3bf2bbd87bdb8c7fcda8d4cbb80706530d13aff83d53e3fd5aa02a7544c910c8b4a73366bd388bb3459d3501195b6a7a4dd03703948ae78811bf4996f0be68c8c6340c6a4df620f8c4a9dce6bd20d1fd6e1ce15bc885821bc35c0ffbf367e05b48329bb40d81461360c4921441cfff72a0cc4e6697ad709a05b503ab29364d01daa74a26e1fb548a8d5aebba97696c2fee10ca9f871f954f647c0233d50ec0fb48b5cc47a5c2b4493250ad35029f0e1da8f0a9088178d1ef8264e6d24d8d1580afb1bf816c0bb65c6022ef718775ca207c358cb15e50805b297c6a5d129cfc8e609dca434fb07f09ed199d8f9e7254622ee3e136c43b4e36f287ed857f526f08a3835ac5e8c9f1242e08cb7db38747c5c129a468b2d4035c12ee66ed75f72dda853bbf5ac2920dc6726c72f8e3be2058ad985ac8c2e0263b3ebece2857a2eb0d4f76b3330ac378ceaff1b809226d9de4088943d4a8e834dc3f9ef5dbdfc55991e6fa4cf9c6f5e44119fea12ecbb2d699302f53d4809c87e0fd9c331b283a29fbaffaf66af1c931f16c32c3ae2f4459240ceb6170760f785a1156d6bf568a69c594857abd8a826d5fa38d5d59e1bd034736a97bd221304950687186474bc9aab6b8315647c84b0925a026c03dc795f015a6ce345d7f76a02a11ff28518ddcaf99547ab7")
        self.match_hop = "ff81855a360000000000000000000000"
        params = SphinxParams(5, 1024)
        result = self.mixnet_test_state_machine(params, unwrapped_message)
        assert message == result.payload

    def mixnet_test_state_machine(self, params, result):
        i = 0
        while True:
            if result.next_hop:
                if result.next_hop[0] == binascii.unhexlify(self.match_hop):
                    #print "SPHINX PACKET alpha %s beta %s gamma %s delta %s" % (binascii.hexlify(result.next_hop[1].header.alpha), binascii.hexlify(result.next_hop[1].header.beta), binascii.hexlify(result.next_hop[1].header.gamma), binascii.hexlify(result.next_hop[1].body.delta))
                    assert result.next_hop[1].header.alpha == self.alpha
                    assert result.next_hop[1].header.beta == self.beta
                    assert result.next_hop[1].header.gamma == self.gamma
                    assert result.next_hop[1].body.delta == self.delta
                    pass
                if result.next_hop[1]:
                    sphinx_packet = result.next_hop[1]
                    assert isinstance(sphinx_packet, SphinxPacket)
                    result = self.send_to_mix(params, result.next_hop[0], sphinx_packet)
                    i += 1
            elif result.exit_hop:
                # print("Deliver [%s] to [%s]" % (result.exit_hop[1], binascii.hexlify(result.exit_hop[0])))
                return result.exit_hop[1]
            elif result.client_hop:
                result = self.send_to_client(*result.client_hop)
                # print("message received by [%s]" % result.message[0])
                return result

    def send_to_client(self, client_id, message_id, sphinx_body):
        # print("send_to_client client_id %s message_id %s delta len %s" % (client_id, binascii.hexlify(message_id), len(delta)))
        return self.alice_decryption_token.decrypt(sphinx_body.delta)

    def send_to_mix(self, params, destination, packet):
        return sphinx_packet_unwrap(params, self.replay_cache_map[destination], self.key_state_map[destination], packet)

    def test_end_to_end(self):
        rand_reader = ChachaNoiseReader("47ade5905376604cde0b57e732936b4298281c8a67b6a62c6107482eb69e2941")
        #  XXX should we make client_ids be strings or what?
        self.setUpMixVectors()
        message = b"the quick brown fox"
        params = SphinxParams(5, 1024)
        packet = SphinxPacket.forward_message(params, self.route, self.pki,
                                              self.route[-1], message, rand_reader)
        #print "--------------- alpha %s beta %s gamma %s delta %s\n\n" % (binascii.hexlify(packet.header.alpha), binascii.hexlify(packet.header.beta), binascii.hexlify(packet.header.gamma), binascii.hexlify(packet.body.delta))
        replay_cache = PacketReplayCacheDict()
        key_state = SphinxNodeKeyState(self.private_key_map[self.route[0]])
        result = sphinx_packet_unwrap(params, replay_cache, key_state, packet)
        self.alpha = binascii.unhexlify("b00eb0894f1b49530150c33cc4055cf3b97f3cac22f03f25050394bf5d80c954")
        self.beta = binascii.unhexlify("13554b4891e71b85632e83baa0a230bd710b818a9d94863c7732deb742c167b3570b6799f99ff76c94bc58b613ff073e6dda60a914e03d6e537fe3e712cbb98e414e0cfec3fd14f0e79b66fc0338820aabb680cc6cb9274b836852bd737ecc121e828697675fc839ebf820ba9d53e17f94b5bad2631f915ae059d4e37fa04b776158f306d92ce2bce232f60412feff11c754450970bba6a318e45f9ce9210202d669c7bf7c38eb1c14b9cda4e6311eba")
        self.gamma = binascii.unhexlify("0b747d558acd9d59ceedc1f876634644")
        self.delta = binascii.unhexlify("0269f1c546605e56162c97ed66054a14565e868193f159b1f25f962bb29a94581826586f955fff0841a9266bc6cb75aa8f217c6d2998bdbdf3782e0e0e8eaa2d3e159ccecccb12c7476d015de13daa6e4d757cf979abadba7e8a92153e5f28f56c94f084d3a9da487ff4a1f478b470f89c74e18179e7aff47e82710f973952a66043d341e27d54370506d63344a6fc738d39d1af3cc1d8394aeaf46a286688c9882fc95077a6b0b438cda481400e56debd0468aa9d5656a7e920ce0882bd07bee35801389ceb9a377a399e639a1d257d7ecd047c161f273faf1026ce5c3f7e5855865be24f53bb48e34dea1bad0c688c4c07564d8d771a8ad8ce980520d81da565a7da0e9e70eb1e975621729f146f090d8ad5e475ed42b4d68993c8ff7a75aaab4ef29d620b4caf5761a41887f3952950bc974468ef4381ebd8dc36dee74f9e1603c195527d84f45bcb18f9161ce5ba989abbc8fe887bbf90c6e2aa453f728bfdef11b776fff9796d8e3affe7b945a38f50285eb9e3dd3697082f0bbd554ea9f5c31e57c1e7f252fe76b69d7af55c9668688d1114de093c6c837dcd8a2836d3ed5199171860288806111893a468666e9ac83562d02d660f183451dbfdd094d26a988ae4bf67a86ae56fbef6a1a8cf53fa304ec41ac93a80c5b68a29e2fa195fa4b165659bf4dc6e2cff12becb34e5c7c6fa567868483f1ced888a441412408f51cff75c3e31d2535d95f9029017d02d993f6bd4b14b9f9d819a207afa7b38a4f70af0c93a3234c96a612f2633e456f2d09bd334fa8015a39f762c301e9fdcf4c525f2549e228dd10ea8549620606ac893a2a299644678ebb8872a217374289a4f75c638268929064f1f5ff51b4aa142fac7fe63d6b155fcc8539c34405635b9da0b7602dba8b6df82335ef03cc9afcc818761f1f4c87ac9e6a39caa249a99131492a8e48de7af9caf3aea7448936d6d2ce9b24f8a53385377196d16e69de43cb84ce6435a68d4e10fbcefeefeca20023ae76d34c7405f16d33d726073052985189cd4ec92d7a4d8cedf29e10a56c27fd5aa2be904d823a4b345bb2f4ae2e7c8ccc95a2e144fa012ad44bf7ee811f51965d90b60c590ab6794868e1d76b7678202a37473e6bd945ced2bd7802b7a5117cb87af00a43d5edae7830bdeb72440d071ce24fe59c4610fc7119044bd3f5d60aeabcc394f020e8e300ad0fe9b58023ca6470345514dab5a7212ce17b612094fadfc7f6e3d5542bff77f80e785064307d5ec8c26b80f06fb3b7d4d6f4c42b647564f4ba05371ef8c02f1fd32a2ae7522425136ab6eb8206f2e0094d78b644b7057aad1d2afa5f9e6abf082da932076cf63b173a1eef549ba18522200748705bac31e950849826a153185f9180aa71553fdb25152ac2a1674c8b007ba78274af411363b6dab068c3d0ceaec2873d96ba7")
        self.match_hop = "ff81855a360000000000000000000000"
        result = self.mixnet_test_state_machine(params, result)
        assert result == message

    def mixnet_test_corrupted_packet_state_machine(self, params, result):
        i = 0
        while True:
            if result.next_hop:
                packet = result.next_hop[1]
                result = self.send_to_mix(params, result.next_hop[0], packet)
                i += 1
            elif result.exit_hop:
                return result.exit_hop[1]
            elif result.client_hop:
                result = self.send_to_client(*result.client_hop)
                return result

    def test_sphinx_corrupted_process_message(self):
        rand_reader = ChachaNoiseReader("47ade5905376604cde0b57e732936b4298281c8a67b6a62c6107482eb69e2941")
        self.setUpMixVectors()
        destination = b"dest"
        message = b"this is a test"
        rand_reader = RandReader()
        params = SphinxParams(5, 1024)
        packet = create_corrupt_process_message(params, self.route, self.pki, destination, message, rand_reader)
        replay_cache = PacketReplayCacheDict()
        key_state = SphinxNodeKeyState(self.private_key_map[self.route[0]])
        result = sphinx_packet_unwrap(params, replay_cache, key_state, packet)
        py.test.raises(InvalidProcessDestinationError, self.mixnet_test_corrupted_packet_state_machine, params, result)

    def test_sphinx_invalid_message(self):
        rand_reader = ChachaNoiseReader("47ade5905376604cde0b57e732936b4298281c8a67b6a62c6107482eb69e2941")
        self.setUpMixVectors()
        message = b"the quick brown fox"
        params = SphinxParams(5, 1024)
        packet = create_invalid_message(params, self.route, self.pki,
                                        self.route[-1], message, rand_reader)
        replay_cache = PacketReplayCacheDict()
        key_state = SphinxNodeKeyState(self.private_key_map[self.route[0]])
        result = sphinx_packet_unwrap(params, replay_cache, key_state, packet)
        py.test.raises(InvalidMessageTypeError, self.mixnet_test_corrupted_packet_state_machine, params, result)


def create_corrupt_process_message(params, route, node_map, dest, msg, rand_reader):
    route_len = len(route)
    assert len(dest) < 128 and len(dest) > 0
    assert SECURITY_PARAMETER + 1 + len(dest) + len(msg) < params.payload_size
    block_cipher = SphinxLioness()
    # Compute the header and the secrets
    header, secrets = create_header(params, route, node_map, b"\x00", b"\x00" * SECURITY_PARAMETER, rand_reader)
    encoded_dest = destination_encode(dest)
    body = (b"\xFF" * SECURITY_PARAMETER) + bytes(encoded_dest) + bytes(msg)
    padded_body = add_padding(body, params.payload_size)

    # Compute the delta values
    key = block_cipher.create_block_cipher_key(secrets[route_len - 1])
    delta = block_cipher.encrypt(key, padded_body)
    for i in range(route_len - 2, -1, -1):
        delta = block_cipher.encrypt(block_cipher.create_block_cipher_key(secrets[i]), delta)

    return SphinxPacket(header=header, body=SphinxBody(delta))


def create_invalid_message(params, route, node_map, dest, msg, rand_reader):
    route_len = len(route)
    assert len(dest) < 128 and len(dest) > 0
    assert SECURITY_PARAMETER + 1 + len(dest) + len(msg) < params.payload_size
    # Compute the header and the secrets
    header, secrets = create_header(params, route, node_map, b"\xFE" * SECURITY_PARAMETER, b"\xFE" * SECURITY_PARAMETER, rand_reader)
    encoded_dest = destination_encode(dest)
    body = (b"\x00" * SECURITY_PARAMETER) + bytes(encoded_dest) + bytes(msg)
    padded_body = add_padding(body, params.payload_size)
    block_cipher = SphinxLioness()
    # Compute the delta values
    key = block_cipher.create_block_cipher_key(secrets[route_len - 1])
    delta = block_cipher.encrypt(key, padded_body)
    for i in range(route_len - 2, -1, -1):
        delta = block_cipher.encrypt(block_cipher.create_block_cipher_key(secrets[i]), delta)

    return SphinxPacket(header=header, body=SphinxBody(delta))


def test_client_corrupt_message():
    message_id = b"A" * 16
    keys = [b"A" * 32]
    decryption_token = ReplyBlockDecryptionToken(message_id, keys)
    py.test.raises(CorruptMessageError, decryption_token.decrypt, b"A" * 1024)
