import textwrap
import random
from aes import AES
from hashFunction import digest_hash
import binascii



def calculateAndAppendHash(data):
    hashValue = digest_hash(data)
    stringData = str(hex(data))
    stringHash = str(hex(int.from_bytes(hashValue, "big")))
    stringTotal = stringData + stringHash[2:]
    outData = hex(int(stringTotal, 16))
    return outData


def encrypt_data(plaintext, master_key):
    AESfunct = AES(master_key)
    encrypted = AES.encrypt(AESfunct, plaintext)
    return encrypted


def decrypt_data(ciphertext, master_key):
    AESfunct = AES(master_key)
    decrypted = AES.decrypt(AESfunct, ciphertext)
    return decrypted


def getSeqNum(data):
    return int(data[len(data) - 1], 16)


def incrementSeqNum(seq):
    return seq + 1

def processPlainText(plainText):
    data = binascii.hexlify(plainText.encode())
    return data.decode()

def generateAESkey():
    keys = [0x7134743677397A24432646294A404E63,
           0x452948404D6251655468576D5A713474,
           0x2F423F4528482B4D6250655368566D59,
           0x7538782F413F4428472B4B6250645367,
           0x5A7234753778214125442A472D4B614E,
           0x68576D5A7134743777217A25432A462D,
           0x50655368566D597133743677397A2443,
           0x2B4B6150645367566B59703373367639,
           0x442A472D4A614E645267556B58703273,
           0x217A25432A462D4A404E635266556A58,
           0x743677397A24432646294A404D635166,
           0x5970337336763979244226452948404D,
           0x67556B58703273357638792F423F4528,
           0x4E635266556A586E3272357538782F41,
           0x2948404D635166546A576E5A72347537,
           0x42264529482B4D6251655468576D5A71,
           0x38792F423F4528482B4B625065536856,
           0x72357538782F413F4428472D4B615064,
           0x576E5A7234753778214125442A472D4A,
           0x655468576D5A7134743777217A25432A,
           0x4B6250655368566D597133743677397A,
           0x2A472D4B6150645367566B5970337336,
           0x4125442A462D4A614E645267556B5870,
           0x3777217A25432A46294A404E63526655,
           0x7133743677397A244326462948404D63,
           0x566B5970337336763979244226452948]
    secretKey = keys[random.randrange(0,25)]
    return secretKey

class Handler:
    def __init__(self, secretKey,Name):
        self.secretKey = secretKey
        #self.PrivateKey = PrivateKey
        #self.PublicKey = PublicKey
        self.Name = Name

    def __encryptAndHashReceivedData__(self, plaintext,secretKey):
        plaintextStr = plaintext#str(hex(plaintext))
        plaintextStr = plaintextStr[2:]
        listOfBlocks = textwrap.wrap(plaintextStr, 32)
        #print(listOfBlocks)

        # Iterate through list of blocks and exncrypt each block and concatenate into full enxrypted string
        encryptedString = "0x"
        for x in listOfBlocks:
            #print(x)
            xHex = int(x, 16)
            encryptedData = encrypt_data(xHex, secretKey)
            #print("Encrypted data: " + str(hex(encryptedData)))
            tempStr = str(hex(encryptedData))
            tempStr = tempStr[2:]
            encryptedString += tempStr

        encryptedInt = int(encryptedString, 16)
        encryptedIntWithHash = calculateAndAppendHash(encryptedInt)
        encryptedStringWithHash = str(encryptedIntWithHash)
        return encryptedStringWithHash

    def __removeSequenceNumber__(self, data):
        sequenceNum = data[len(data) - 1:]
        sequenceNumInt = int(sequenceNum, 16)
        sequenceNumInt = sequenceNumInt + 1
        newSequenceNumStr = str(sequenceNumInt)
        return newSequenceNumStr

    def __appendSequenceNumber__(self, newSequenceNumStr, data):
        data = data[0: len(data) - 1]
        data = data + newSequenceNumStr
        return data




if __name__ == '__main__':
    key = 0x2b7e151628aed2a6abf7158809cf4f3c  # handlerPrivate AES key
    plaintext = 0x1111113243f6a8885a308d313198a2e03707343243f6a8885a308d313198a2e
    #print(sizeof(plaintext))
    HandlerX = Handler(key,'H1')
    encryptTheData = Handler.__encryptAndHashReceivedData__(HandlerX, plaintext)
    encryptTheData = encryptTheData + "0"
    print(encryptTheData)
    newSeqNum = Handler.__removeSequenceNumber__(HandlerX, encryptTheData)
    newData = Handler.__appendSequenceNumber__(HandlerX, newSeqNum, encryptTheData)
    print(newData)
    # handler2
    # strip seqNum
    # increment
    # append seq back on
    # recieve(data)
    # --------decrypt testing------
    # getSeqNumber
