import hashlib
import hmac
from io import BytesIO

from programmingbitcoin.my_attempts.core.source import hash160, encode_base58_checksum


class FieldElement:
    def __init__(self, num, prime):
        if num >= prime or num < 0:
            error = f'Element {num} not in range field 0 to {prime}'
            raise ValueError(error)
        self.num = num
        self.prime = prime

    def __repr__(self):
        return f'Field element {self.num} ({self.prime})'

    def __eq__(self, other):
        if other is None:
            return False
        return self.num == other.num and self.prime == other.prime

    def __ne__(self, other):
        if other is None:
            return False
        # return self.num != other.num and self.prime != other.prime
        return not (self == other)

    def __add__(self, other):
        if self.prime != other.prime:
            raise TypeError('Cannot add numbers in different Fields')
        num = (self.num + other.num) % self.prime
        return self.__class__(num, self.prime)

    def __sub__(self, other):
        if self.prime != other.prime:
            raise TypeError('Cannot sub numbers in different Fields')
        sub = (self.num - other.num) % self.prime
        return self.__class__(sub, self.prime)

    def __mul__(self, other):
        if self.prime != other.prime:
            raise TypeError('Cannot multiply numbers in different Fields')
        mul = (self.num * other.num) % self.prime
        return self.__class__(mul, self.prime)

    def __rmul__(self, coefficient):
        num = (self.num * coefficient) % self.prime
        return self.__class__(num, self.prime)

    def __pow__(self, power, modulo=None):
        n = power % (self.prime - 1)
        num = pow(self.num, n, self.prime)
        return self.__class__(num, self.prime)

    def __truediv__(self, other):
        if self.prime != other.prime:
            raise TypeError('Cannot pow numbers in different Fields')
        not_int = self.num * pow(other.num, self.prime - 2, self.prime) % self.prime
        return self.__class__(not_int, self.prime)

    def __floordiv__(self, other):
        if self.prime != other.prime:
            raise TypeError('Cannot pow numbers in different Fields')
        integer = self.num * pow(other.num, self.prime - 2, self.prime) % self.prime
        return self.__class__(integer, self.prime)


class Point:
    def __init__(self, x, y, a, b):
        self.b = b
        self.a = a
        self.y = y
        self.x = x
        if self.x is None and self.y is None:
            return
        if self.y ** 2 != self.x ** 3 + a * x + b:
            raise ValueError(f'{self.x}, {self.y} is not on the same curve')

    def __eq__(self, other):
        return self.x == other.x and self.y == other.y and \
               self.a == other.a and self.b == other.b

    def __ne__(self, other):
        if other is None:
            return False
        return not (self == other)

    def __add__(self, other):
        if self.a != other.a or self.b != other.b:
            raise TypeError(f'{self} {other} are not on the same Curve')
        if self.x is None:
            return other
        if other.x is None:
            return self
        if self.x == other.x and self.y != other.y:  # vertical invertibility
            return self.__class__(None, None, self.a, self.b)
        if self.x != other.x:  # tangent
            s = (other.y - self.y) / (other.x - self.x)
            x = s ** 2 - self.x - other.x
            y = s * (self.x - x) - self.y
            return self.__class__(x, y, self.a, self.b)

        if self == other:  # p1=p2
            s = (3 * self.x ** 2 + self.a) / (2 * self.y)
            x = s ** 2 - 2 * self.x
            y = s * (self.x - x) - self.y
            return self.__class__(x, y, self.a, self.b)

        if self == other and self.y == 0 * self.x:  # infinity vertical tangent with 0 divider
            return self.__class__(None, None, self.a, self.b)

    def __rmul__(self, coef):
        current = self  # <1>
        result = self.__class__(None, None, self.a, self.b)  # <2>
        while coef:
            if coef & 1:  # <3>
                result += current
            current += current
            coef >>= 1  # <5>
        return result

    def __repr__(self):
        if self.x is None:
            return 'Point(infinity)'
        elif isinstance(self.x, FieldElement):
            return 'Point ({}, {})_{}_{} FieldElement({})'.format(self.x.num, self.y.num, self.a.num
                                                                  , self.b.num, self.x.prime)
        return 'Point ({}, {})_{}_{}'.format(self.x, self.y, self.a, self.b)


P = 2 ** 256 - 2 ** 32 - 977
A = 0
B = 7
N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141


class S256Field(FieldElement):
    def __init__(self, num, prime=None):
        super().__init__(num=num, prime=P)

    def __repr__(self):
        return '{:x}'.format(self.num).zfill(64)

    def sqrt(self):
        return self ** ((P + 1) / 4)


class S256Point(Point):
    def __init__(self, x, y, a=None, b=None):
        a, b = S256Field(A), S256Field(B)
        if type(x) == int:
            super().__init__(x=S256Field(x), y=S256Field(y), a=a, b=b)
        else:
            super().__init__(x=x, y=y, a=a, b=b)

    def __rmul__(self, coefficient):
        coef = coefficient % N
        return super().__rmul__(coef)

    def __repr__(self):
        if self.x is None:
            return 'S256 Point (infinity)'
        return 'S256Point ({}, {})'.format(self.x, self.y)

    def sec(self, compressed=True):
        """Возвращает двоичный ряд данных формата sec"""
        if compressed:
            if self.y.num % 2 == 0:
                return b'\x02' + self.x.num.to_bytes(32, 'big')
            else:
                return b'\x03' + self.x.num.to_bytes(32, 'big')
        else:
            return b'\x04' + self.x.num.to_bytes(32, 'big') + self.y.num.to_bytes(32, 'big')

    def verify(self, z, sig):
        s_inv = pow(sig.s, N - 2, N)
        u = z * s_inv % N
        v = sig.r * s_inv % N
        total = u * G + v * self
        return total.x.num == sig.r

    def hash160(self, compressed=True):
        return hash160(self.sec(compressed))

    def address(self, compressed=True, testnet=False):
        h160 = self.hash160(compressed)
        if testnet:
            prefix = b'\x6f'
        else:
            prefix = b'\x00'
        return encode_base58_checksum(prefix + h160)

    @classmethod
    def parse(self, sec_bin):
        """Возвращает объект S256Point из двоичных,
         а не шестнадцатиричных данных формата SEC"""
        if sec_bin[0] == 4:
            x = int.from_bytes(sec_bin[1:33], 'big')
            y = int.from_bytes(sec_bin[33:65], 'big')
            return S256Point(x=x, y=y)
        is_even = sec_bin % 2 == 0
        x = S256Field(int.from_bytes(sec_bin[1:33], 'big'))
        alpha = x ** 3 + S256Field(B)
        beta = alpha.sqrt()
        if beta.num % 2 == 0:
            even_beta = beta
            odd_beta = S256Field(P - beta)
        else:
            even_beta = S256Field(P - beta)
            odd_beta = beta
        if is_even:
            return S256Point(x, even_beta)
        else:
            return S256Point(x, odd_beta)

    # def hash256(s):
    #     '''two rounds of sha256'''
    #     return hashlib.sha256(hashlib.sha256(s).digest()).digest()


class Signature:
    def __init__(self, r, s):
        self.s = s
        self.r = r

    def __repr__(self):
        return 'Signature ({:x}, {:x})'.format(self.r, self.s)

    def der(self):
        rbin = self.r.to_bytes(32, 'big')
        rbin = rbin.lstrip(b'\x00')
        if rbin[0] & 0x80:
            rbin = b'\x00' + rbin
        result = bytes([2, len(rbin)]) + rbin
        sbin = self.s.to_bytes(32, 'big')
        sbin = sbin.lstrip(b'\x00')
        if sbin[0] & 0x80:
            sbin = b'\x00' + sbin
        result += bytes([2, len(sbin)]) + sbin
        return bytes([0x30, len(result)]) + result

    @classmethod
    def parse(cls, signature_bin):
        s = BytesIO(signature_bin)
        compound = s.read(1)[0]
        if compound != 0x30:
            raise SyntaxError('Bad Signature')
        length = s.read(1)[0]
        if length + 2 != signature_bin:
            raise SyntaxError('Bad Signature length')
        marker = s.read(1)[0]
        if marker != 0x02:
            raise SyntaxError('Bad Signature')
        rlength = s.read(1)[0]
        r = int.from_bytes(s.read(rlength), 'big')
        marker = s.read(1)[0]
        if marker != 0x02:
            raise SyntaxError('Bad Signature')
        slength = s.read(1)[0]
        s = int.from_bytes(s.read(slength), 'big')
        if len(signature_bin) != 6 + slength + rlength:
            raise SyntaxError('Signature too big')
        return cls(r, s)


class PrivateKey:
    def __init__(self, secret):
        self.secret = secret
        self.point = secret * G

    def hex(self):
        return '{:x}'.format(self.secret).zfill(64)

    def sign(self, z):
        k = self.deterministic_k(z)
        r = (k * G).x.num
        k_inv = pow(k, N - 2, N)
        s = (z + r * self.secret) * k_inv % N
        if s > N / 2:
            s = N - s
        return Signature(r, s)

    def deterministic_k(self, z):
        k = b'\x00' * 32
        v = b'\x01' * 32
        if z > N:
            z -= N
        z_bytes = z.to_bytes(32, 'big')
        secret_bytes = self.secret.to_bytes(32, 'big')
        s256 = hashlib.sha256
        k = hmac.new(k, v + b'\x00' + secret_bytes + z_bytes, s256).digest()
        v = hmac.new(k, v, s256).digest()
        k = hmac.new(k, v + b'\x01' + secret_bytes + z_bytes, s256).digest()
        v = hmac.new(k, v, s256).digest()
        while True:
            v = hmac.new(k, v, s256).digest()
            candidate = int.from_bytes(v, 'big')
            if N > candidate >= 1:
                return candidate
            k = hmac.new(k, v + b'\x00', s256).digest()
            v = hmac.new(k, v, s256).digest()

    def wif(self, compressed=True, testnet=False):
        secret_bytes = self.secret.to_bytes(32, 'big')
        if testnet:
            prefix = b'\xef'
        else:
            prefix = b'\x80'
        if compressed:
            suffix = b'\x01'
        else:
            suffix = b''
        return encode_base58_checksum(prefix + secret_bytes + suffix)


G = S256Point(
    0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
    0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8)



# ch 4 ex 1    SEC serialized(65b) and hexed Public Key
# private = PrivateKey(5000)
# print(private.point.sec().hex())
# private = PrivateKey(2018**5)
# print(private.point.sec().hex())
# private = PrivateKey(0xdeadbeef12345)
# print(private.point.sec().hex())
# end ex 1

# ex 2          compressed SEC serialized(33b) and hexed Public Key
# private = PrivateKey(5001)
# print(private.point.sec(compressed=True).hex())
# private = PrivateKey(2019**5)
# print(private.point.sec(compressed=True).hex())
# private = PrivateKey(0xdeadbeef54321)
# print(private.point.sec(compressed=True).hex())
# end ex2

# ex3           hexed DER format for signature
# sig = Signature(r=0x37206a0610995c58074999cb9767b87af4c4978db68c06e8e6e81d282047a7c6,
#               s=0x8ca63759c1157ebeaec0d03cecca119fc9a75bf8e6d0fa65c841c8e2738cdaec)
# print(sig.der().hex())
# end ex 3

# ex4           Base58 encoded hash in bytes
# h = '7c076ff316692a3d7eb3c3bb0f8b1488cf72e1afcd929e29307032997a838a3d'
# print(encode_base58(bytes.fromhex(h)))
# end ex4

# ex5           compressed\non-compressed Public Key address in\not in testnet
# private = PrivateKey(5000)
# print(private.point.address(compressed=False, testnet=True))
# private = PrivateKey(2020**5)
# print(private.point.address(compressed=True, testnet=True))
# private = PrivateKey(0x12345deadbeef)
# print(private.point.address(compressed=True, testnet=False))
# end ex5

# ex6           wif converted(like SEC serialize, but for secret key) secret key
# secret = PrivateKey(5003)
# print(secret.wif(compressed=True, testnet=True))
# secret = PrivateKey(2021*5)
# print(secret.wif(compressed=False, testnet=True))
# secret = PrivateKey(0x54321deadbeef)
# print(secret.wif(compressed=True, testnet=False))
# end ex6

# ex7           encoded secret phrase for create address in testnet
# secret_pharase = b"I'm will build it and it could be written in history!"
# int_sp = little_endian_to_int(hash256(secret_pharase))
# pk = PrivateKey(int_sp)
# print(pk.point.address(testnet=True))
# end ex7

# ch5 ex1

