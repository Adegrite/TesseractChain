from io import BytesIO

from source import bytes_to_bits_field, murmur3, bit_field_to_bytes, int_to_little_endian, encode_varint

BIP37_CONSTANT = 0xfba4c795


class BloomFilter:
    def __init__(self, size, functions_count, tweak):
        self.size = size
        self.bit_field = [0] * (size * 8)
        self.functions_count = functions_count
        self.tweak = tweak

    def add(self, item):
        for i in range(self.functions_count):
            seed = i * BIP37_CONSTANT + self.tweak
            h = murmur3(item, seed=seed)
            bit = h % self.size * 8
            self.bit_field[bit] = 1

    def filterload(self, flag=1):
        result = encode_varint(self.size)
        result += self.filter_bytes()
        result += int_to_little_endian(self.functions_count, 4)
        result += int_to_little_endian(self.tweak, 4)
        result += int_to_little_endian(flag, 1)
        return GenericMessage(b'filterload', result)

filter = BloomFilter(10, 5, tweak=99)
for phrase in (b'Hello World', b'Goodbye!'):
    for i in range(filter.functions_count):
        seed = i * BIP37_CONSTANT + filter.tweak
        h = murmur3(phrase, seed=seed)
        bit = h % (filter.size * 8)
        filter.bit_field[bit] = 1
print(bit_field_to_bytes(filter.bit_field).hex())

