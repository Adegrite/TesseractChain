import hashlib

BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
SIGHASH_ALL = 1
SIGHASH_NONE = 2
SIGHASH_SINGLE = 3
TWO_WEEKS = 60 * 60 * 24 * 14
MAX_TARGET = 0xffff * 256 ** (0x1d - 3)


def encode_base58(s):
    count = 0
    for c in s:
        if c == 0:
            count += 1
        else:
            break
    prefix = '1' * count
    num = int.from_bytes(s, 'big')
    result = ''
    while num > 0:
        num, mod = divmod(num, 58)
        result = BASE58_ALPHABET[mod] + result
    return prefix + result


def decode_base58(s):
    num = 0
    for c in s:
        num *= 58
        num += BASE58_ALPHABET.index(c)
    combined = num.to_bytes(25, byteorder='big')
    checksum = combined[-4:]
    if hash256(combined[:-4])[:4] != checksum:
        raise ValueError('bad address:{} {}'.format(checksum, hash256(combined[:-4])[:4]))
    return combined[1:-4]


def hash256(z):
    return hashlib.sha256(hashlib.sha256(z).digest()).digest()


def sha256(s):
    return hashlib.sha256(s).digest()


def encode_base58_checksum(b):
    return encode_base58(b + hash256(b)[:4])


def hash160(s):
    """sha256 followed by ripemd160"""
    return hashlib.new('ripemd160', hashlib.sha256(s).digest()).digest()


def little_endian_to_int(b):
    return int.from_bytes(b, 'little')

def int_to_little_endian(n, length):
    return n.to_bytes(length, 'little')


def read_varint(s):
    """Читает переменное целое число из потока"""
    i = s.read(1)[0]
    if i == 0xfd:
        return little_endian_to_int(s.read(2))
    elif i == 0xfe:
        return little_endian_to_int(s.read(4))
    elif i == 0xff:
        return little_endian_to_int(s.read(8))
    else:
        return i


def encode_varint(i):
    """Кодирует целое число в виде варианта"""
    if i < 0xfd:
        return bytes([i])

    if i < 0x10000:
        return b'\xfd' + int_to_little_endian(i, 2)
    if i < 0x10000000:
        return b'\xfe' + int_to_little_endian(i, 4)
    if i < 0x10000000000000000:
        return b'\xff' + int_to_little_endian(i, 8)
    else:
        raise ValueError('Integer too large: {}'.format(i))


def h160_to_p2pkh_address(h, testnet=False):
    h160 = bytes.fromhex(h)
    if testnet:
        prefix = b'\x6f'
    else:
        prefix = b'\x00'
    return encode_base58_checksum(prefix + h160)


def h160_to_p2sh_address(h, testnet=False):
    h160 = bytes.fromhex(h)
    if testnet:
        prefix = b'\xc4'
    else:
        prefix = b'\x05'
    return encode_base58_checksum(prefix + h160)


def bits_to_target(bits):
    exponent = bits[-1]
    coefficient = little_endian_to_int(bits[:-1])
    return coefficient * 256 ** (exponent - 3)


def target_to_bits(target):
    """Преобразует целочисленное значение обратно в биты"""
    raw_bytes = target.to_bytes(32, 'big')
    raw_bytes = raw_bytes.lstrip(b'\x00')
    if raw_bytes[0] == 0x7f:
        exponent = len(raw_bytes) + 1
        coefficient = b'\x00' + raw_bytes[:2]
    else:
        exponent = len(raw_bytes)
        coefficient = raw_bytes[:3]
    new_bits = coefficient[::-1] + bytes([exponent])
    return new_bits


def calculate_new_bits(prev_bits, time_differential):
    if time_differential > TWO_WEEKS * 4:
        time_differential = TWO_WEEKS * 4
    if time_differential < TWO_WEEKS // 4:
        time_differential = TWO_WEEKS // 4
    new_target = prev_bits.target() * time_differential // TWO_WEEKS
    return target_to_bits(new_target)


def merkle_parent(hash1, hash2):
    return hash256(hash1 + hash2)


def merkle_parent_level(hex_hashes):
    if len(hex_hashes) == 1:
        raise RuntimeError('Cannot take a parent with only 1 item')
    if len(hex_hashes) % 2 == 1:
        hex_hashes.append(hex_hashes[-1])
    parent_level = []
    for i in range(0, len(hex_hashes), 2):
        parent = merkle_parent(hex_hashes[i], hex_hashes[i + 1])
        parent_level.append(parent)
    return parent_level


def merkle_root(hex_hashes):
    current_level = hex_hashes
    while len(current_level) > 1:
        current_level = merkle_parent_level(current_level)
    return current_level[0]


def bytes_to_bits_field(some_bytes):
    flag_bits = []
    for byte in some_bytes:
        for _ in range(8):
            flag_bits.append(byte & 1)
            byte >>= 1
    return flag_bits


def bit_field_to_bytes(bit_field):
    if len(bit_field) % 8 != 0:
        raise RuntimeError('bit_field does not have a length that is divisible by 8')
    result = bytearray(len(bit_field) // 8)
    for i, bit in enumerate(bit_field):
        byte_index, bit_index = divmod(i, 8)
        if bit:
            result[byte_index] |= 1 << bit_index
    return bytes(result)


def murmur3(data, seed=0):
    # '''from http://stackoverflow.com/questions/13305290/is-there-a-pure-python-implementation-of-murmurhash'''
    c1 = 0xcc9e2d51
    c2 = 0x1b873593
    length = len(data)
    h1 = seed
    roundedEnd = (length & 0xfffffffc)  # round down to 4 byte block
    for i in range(0, roundedEnd, 4):
        # little endian load order
        k1 = (data[i] & 0xff) | ((data[i + 1] & 0xff) << 8) | \
             ((data[i + 2] & 0xff) << 16) | (data[i + 3] << 24)
        k1 *= c1
        k1 = (k1 << 15) | ((k1 & 0xffffffff) >> 17)  # ROTL32(k1,15)
        k1 *= c2
        h1 ^= k1
        h1 = (h1 << 13) | ((h1 & 0xffffffff) >> 19)  # ROTL32(h1,13)
        h1 = h1 * 5 + 0xe6546b64
    # tail
    k1 = 0
    val = length & 0x03
    if val == 3:
        k1 = (data[roundedEnd + 2] & 0xff) << 16
    # fallthrough
    if val in [2, 3]:
        k1 |= (data[roundedEnd + 1] & 0xff) << 8
    # fallthrough
    if val in [1, 2, 3]:
        k1 |= data[roundedEnd] & 0xff
        k1 *= c1
        k1 = (k1 << 15) | ((k1 & 0xffffffff) >> 17)  # ROTL32(k1,15)
        k1 *= c2
        h1 ^= k1
    # finalization
    h1 ^= length
    # fmix(h1)
    h1 ^= ((h1 & 0xffffffff) >> 16)
    h1 *= 0x85ebca6b
    h1 ^= ((h1 & 0xffffffff) >> 13)
    h1 *= 0xc2b2ae35
    h1 ^= ((h1 & 0xffffffff) >> 16)
    return h1 & 0xffffffff
