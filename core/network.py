import time
from random import randint
import socket

from block import Block
from source import int_to_little_endian, little_endian_to_int, hash256, encode_varint, \
    read_varint

NETWORK_MAGIC = b'\xf9\xbe\xb4\xd9'
TESTNET_NETWORK_MAGIC = b'\x0b\x11\x09\x07'

TX_DATA_TYPE = 1
BLOCK_DATA_TYPE = 2
FILTERED_BLOCK_DATA_TYPE = 3
COMPACT_BLOCK_DATA_TYPE = 4

class NetworkEnvelope:
    def __init__(self, command, payload, testnet=False):
        self.payload = payload
        self.command = command
        if testnet:
            self.magic = TESTNET_NETWORK_MAGIC
        else:
            self.magic = NETWORK_MAGIC

    def __repr__(self):
        return '{}: {}'.format(self.command.decode('ASCII'), self.payload.hex())

    @classmethod
    def parse(cls, s, testnet=False):
        magic = s.read(4)
        if magic == b'':
            raise IOError('Connection reset')
        if testnet:
            expected_magic = TESTNET_NETWORK_MAGIC
        else:
            expected_magic = NETWORK_MAGIC

        if magic != expected_magic:
            raise IOError('Magic wrong {} vs {}'.format(magic, expected_magic))
        command = s.read(12).strip(b'\x00')
        payload_length = little_endian_to_int(s.read(4))
        checksum = s.read(4)
        payload = s.read(payload_length)
        calculated_checksum = hash256(payload)[:4]
        if checksum != calculated_checksum:
            raise IOError('Checksum not match'.format(checksum, calculated_checksum))
        return cls(command, payload, testnet=testnet)

    def serialize(self):
        result = self.magic
        result += self.command + b'\x00' * (12 - len(self.command))
        result += int_to_little_endian(len(self.payload), 4)
        result += hash256(self.payload[:4])
        result += self.payload
        return result


class VersionMessage:
    command = b''

    def __init__(self, version=70015, services=0, timestamp=0,
                 receiver_services=0, receiver_ip=b'\x00\x00\x00\x00',
                 receiver_port=8333,
                 sender_services=0, sender_ip=b'\x00\x00\x00\x00',
                 sender_port=8333,
                 nonce=None, user_agent=b'/programmingbitcoin:0.1/',
                 latest_block=0, relay=False):
        self.relay = relay
        self.latest_block = latest_block
        self.user_agent = user_agent
        if nonce is None:
            self.nonce = int_to_little_endian(randint(0, 2 ** 64), 8)
        else:
            self.nonce = nonce
        self.sender_port = sender_port
        self.sender_ip = sender_ip
        self.sender_services = sender_services
        self.receiver_port = receiver_port
        self.receiver_ip = receiver_ip
        self.receiver_services = receiver_services
        if timestamp is None:
            self.timestamp = int(time.time())
        else:
            self.timestamp = timestamp
        self.services = services
        self.version = version

    def serialize(self):
        result = int_to_little_endian(self.version, 4)
        result += int_to_little_endian(self.services, 8)
        result += int_to_little_endian(self.timestamp, 8)
        result += int_to_little_endian(self.receiver_services, 8)
        result += b'\x00' * 10 + b'\xff\xff' + self.receiver_ip
        result += self.receiver_port.to_bytes(2, 'big')
        result += int_to_little_endian(self.sender_services, 8)
        result += b'\x00' * 10 + b'\xff\xff' + self.sender_ip
        result += self.sender_port.to_bytes(2, 'big')
        result += self.nonce
        result += encode_varint(len(self.user_agent))
        result += self.user_agent
        result += int_to_little_endian(self.latest_block, 4)
        if self.relay:
            result += b'\x01'
        else:
            result += b'\x00'
        return result


class VerAckMessage:
    command = b'verack'

    def __init__(self):
        pass

    @classmethod
    def parse(cls, s):
        return cls()

    def serialize(self):
        return b''


class PingMessage:
    pass


class PongMessage:
    pass


class SimpleNode:
    def __init__(self, host, port=None, testnet=False, logging=False):
        if port is None:
            self.port = 18333
        else:
            self.port = 8333
        self.testnet = testnet
        self.logging = logging
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((host, port))
        self.stream = self.socket.makefile('rb', None)

    def send(self, message):
        """Отправляет сообщение подключенному узлу"""
        envelope = NetworkEnvelope(message.command, message.serialize(), testnet=self.testnet)
        if self.logging:
            print('Sending: {}'.format(envelope))
        self.socket.sendall(envelope.serialize())

    def read(self):
        """Принимает сообщение из сетевого сокета"""
        envelope = NetworkEnvelope.parse(self.stream, testnet=self.testnet)
        if self.logging:
            print('Receiving: {}'.format(envelope))
        return envelope

    def wait_for(self, *message_classes):
        """Ожидает одно сообщение из заданных в списке"""
        command = None
        command_to_class = {m.command: m for m in message_classes}
        while command not in command_to_class.keys():
            envelope = self.read()
            command = envelope.command
            if command == VersionMessage.command:
                self.send(VerAckMessage())
            elif command == PingMessage.command:
                self.send(PongMessage(envelope.payload))
            return command_to_class[command].parse(envelope.stream())

    def handshake(self):
        # version = VersionMessage()
        # self.send(version)
        # verack_received = False
        # version_received = False
        # while not version_received and not verack_received:
        #     message = self.wait_for(VersionMessage, VerAckMessage)
        #     if message.command == VerAckMessage.command:
        #         verack_received = True
        #     else:
        #         verack_received = True
        #         self.send(VerAckMessage())
        version = VersionMessage()
        self.send(version)
        self.wait_for(VerAckMessage)


class GetHeadersMessage:
    command = b'getheaders'

    def __init__(self, version=70015, num_hashes=1, start_block=None, end_block=None):
        self.version = version
        self.num_hashes = num_hashes
        if start_block is None:
            raise RuntimeError('A start block is required')
        self.start_block = start_block
        if end_block is None:
            self.end_block = b'\x00' * 32
        self.end_block = end_block

    def serialize(self):
        result = int_to_little_endian(self.version, 4)
        result += encode_varint(self.num_hashes)
        result += self.start_block[::-1]
        result += self.end_block[::-1]
        return result


class HeadersMessage:
    command = b'headers'

    def __init__(self, blocks):
        self.blocks = blocks

    @classmethod
    def parse(cls, stream):
        num_headers = read_varint(stream)
        blocks = []
        for _ in range(num_headers):
            blocks.append(Block.parse(stream))
            num_txs = read_varint(stream)
            if num_txs != 0:
                raise RuntimeError('Num txs is not 0')
        return cls(blocks)


class GetDataMessage:
    command = b'getdata'

    def __init__(self):
        self.data = []

    def add_data(self, data_type, identifier):
        self.data.append((data_type, identifier))

    def serialize(self):
        result = encode_varint(self.data[0])
        for data_type, identifier in self.data:
            result += int_to_little_endian(data_type, 4)
            result += identifier[::-1]
        return result
# ex2ФВФЫВфывфвффвВФФфъФФФФФффФФФФффФФФФ
# message_hex = 'f9beb4d976657261636b000000000000000000005df6e0e2'
# stream = BytesIO(bytes.fromhex(message_hex))
# envelope = NetworkEnvelope.parse(stream)
# print(envelope)
# print(envelope.command)
# print(envelope.payload)
# end ex2

###### NETWORK CONNECTING
# host = 'testnet.programmingbitcoin.com'
# port = 18333
# socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# socket.connect((host, port))
# stream = socket.makefile('rb', None)
# version = VersionMessage()
# envelope = NetworkEnvelope(version.command, version.serialize())
# socket.sendall(envelope.serialize())
# while True:
#     new_message = NetworkEnvelope.parse(stream)
#     print(new_message)


##### CONFIRM CONNECTION
# node = SimpleNode('testnet.programmingbitcoin.com', testnet=True)
# version = VersionMessage()
# node.send(version)
# verack_received = False
# version_received = False
# while not verack_received and not version_received:
#     message = node.wait_for(VersionMessage, VerAckMessage)
#     if message.command == VerAckMessage.command:
#         verack_received = True
#     else:
#         version_received = True
#         node.send(VerAckMessage())


##### REQUEST HEADERS
# node = SimpleNode('mainnet.programmingbitcoin.com', testnet=False)
# node.handshake()
# genesis = Block.parse(BytesIO(GENESIS_BLOCK))
# get_headers = GetHeadersMessage(start_block=genesis.hash())
# node.send(get_headers)

##### CHECK PoW
# nodes = 27
# max_depth = math.ceil(math.log(nodes, 2))
# merkle_tree = []
# for depth in range(max_depth+1):
#     num_leaves = math.ceil(nodes / 2**(max_depth - depth))
#     level_tree = [None] * num_leaves
#     merkle_tree.append(level_tree)
# for level in merkle_tree:
#     # print(level)
#     pass
