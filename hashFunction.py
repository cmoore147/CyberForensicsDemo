import hashlib


# Python's hashing functions require binary values
def digest_hash(data):
    m = hashlib.sha1(bin(data).encode()).digest()
    return m

# if __name__ == '__main__':
#    data = b"Hello World!"
#    hashedData = digest_hash(data)
#    print(hashedData)
#    data = data + hashedData
#    print(data)
