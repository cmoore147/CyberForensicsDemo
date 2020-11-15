import random


# fnction for finding gcd of two numbers using euclidean algorithm
def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a


# uses extened euclidean algorithm to get the d value
# for more info look here: https://crypto.stackexchange.com/questions/5889/calculating-rsa-private-exponent-when-given-public-exponent-and-the-modulus-fact
# will also be explained in class
def get_d(e, z):
    a = e
    b = z
    x = 0
    y = 1
    q = 0
    d = 0

    while (1):
        if (a == 1):
            return y
        if (a == 0):
            return -1
        q = b // a
        b = b - a * q
        x = x + q * y
        if (b == 1):
            d = z - x
            break
        if (b == 0):
            return -1
        q = a // b
        a = a - b * q
        y = y + q * x
    while (d < 0):
        d += z
    return d


def is_prime(num):
    if num > 1:

        # Iterate from 2 to n / 2
        for i in range(2, num // 2):

            # If num is divisible by any number between
            # 2 and n / 2, it is not prime
            if (num % i) == 0:
                return False
                break
            else:
                return True

    else:
        return False


def generate_keypair(p, q):
    if not (is_prime(p) and is_prime(q)):
        raise ValueError('Both numbers must be prime.')
    elif p == q:
        raise ValueError('p and q cannot be equal')
    n = p * q
    z = (p - 1) * (q - 1)  # this is phi(n)
    e = random.randrange(1, z)

    while (gcd(e, z) != 1):
        e = random.randrange(1, z)

    d = get_d(e, z)
    #print("d = " + d)
    return ((e, n), (d, n))


def encrypt(pk, plaintext):
    ###################################your code goes here#####################################
    # plaintext is a single character
    # cipher is a decimal number which is the encrypted version of plaintext
    # the pow function is much faster in calculating power compared to the ** symbol !!!
    cipher = pow(plaintext, pk[0], pk[1])  # encrypted letter
    return cipher


def decrypt(pk, ciphertext):
    ###################################your code goes here#####################################
    # ciphertext is a single decimal number
    # the returned value is a character that is the decryption of ciphertext
    plain = pow(ciphertext, pk[0], pk[1])  # decypted letter
    return plain
