from programmingbitcoin.my_attempts.core.source import little_endian_to_int, int_to_little_endian, hash256, \
    bits_to_target, merkle_root

GENESIS_BLOCK = bytes.fromhex(
    '0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c')
TESTNET_GENESIS_BLOCK = bytes.fromhex(
    '0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4adae5494dffff001d1aa4ae18')
LOWEST_BITS = bytes.fromhex('ffff001d')


class Block:
    def __init__(self, version, prev_block, merkle_root,  timestamp, bits, nonce, tx_hashes=None):
        self.version = version
        self.prev_block = prev_block
        self.merkle_root = merkle_root
        self.timestamp = timestamp
        self.bits = bits
        self.nonce = nonce
        self.tx_hashes = tx_hashes

    @classmethod
    def parse(cls, s):
        version = little_endian_to_int(s.read(4))
        prev_block = s.read(32)[::-1]
        merkle_root = s.read(32)[::-1]
        timestamp = little_endian_to_int(s.read(4))
        bits = s.read(4)
        nonce = s.read(4)
        return cls(version, prev_block, merkle_root, timestamp, bits, nonce)

    def serialize(self):
        result = int_to_little_endian(self.version, 4)
        result += self.prev_block
        result += self.merkle_root
        result += int_to_little_endian(self.timestamp, 4)
        result += self.bits
        result += self.nonce
        return result

    def hash(self):
        s = self.serialize()
        h256 = hash256(s)
        return h256[::-1]

    def bip9(self):
        return self.version >> 29 == 0b001

    def bip91(self):
        return self.version >> 4 & 1 == 1

    def bip141(self):
        return self.version >> 1 & 1 == 1

    def target(self):
        return bits_to_target(self.bits)

    def difficulty(self):
        return 0xffff * 256 ** (0x1d - 3) / self.target()

    def check_pow(self):
        h256 = hash256(self.serialize())
        proof = little_endian_to_int(h256)
        return proof < self.target()

    def validate_merkle_root(self):
        hashes = [h[::-1] for h in self.tx_hashes]
        root = merkle_root(hashes)
        return root[::-1] == self.merkle_root


# # ch9 ex12
# block1_hex = '000000203471101bbda3fe307664b3283a9ef0e97d9a38a7eacd88000000\
# 00000000000010c8aba8479bbaa5e0848152fd3c2289ca50e1c3e58c9a4faaafbdf5803c5448dd\
# b845597e8b0118e43a81d3'
# block2_hex = '02000020f1472d9db4b563c35f97c428ac903f23b7fc055d1cfc26000000\
# 000000000000b3f449fcbe1bc4cfbcb8283a0d2c037f961a3fdf2b8bedc144973735eea707e126\
# 4258597e8b0118e5f00474'
#
# # target_to_bits()
# first_block = Block.parse(BytesIO(bytes.fromhex(block1_hex)))
# last_block = Block.parse(BytesIO(bytes.fromhex(block2_hex)))
# time_dif = last_block.timestamp - first_block.timestamp
# if time_dif > TWO_WEEKS * 4:
#     time_dif = TWO_WEEKS * 4
# if time_dif < TWO_WEEKS // 4:
#     time_dif = TWO_WEEKS // 4
#
# new_target = last_block.target() * time_dif // TWO_WEEKS
# new_bits = target_to_bits(new_target)
# print(new_bits.hex())
#
# stream = BytesIO(TESTNET_GENESIS_BLOCK)
# print(var_dump(Block.parse(stream)))
