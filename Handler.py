import textwrap
import random
from aes import AES
from hashFunction import digest_hash
import binascii



def calculateAndAppendHash(data):
    hashValue = digest_hash(data)
    stringData = str(hex(data))
    stringHash = str(hex(int.from_bytes(hashValue, "big")))
    print("Actual Hash ", stringHash)
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
    keys = [0xABCDEFABCDEFABCDEFABCDEFABCDEFAB,
            0xAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB,
            0xCCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDD,
            0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF]
    secretKey = keys[random.randrange(0,4)]
    print(keys)
    return secretKey

class Handler:
    def __init__(self, secretKey,Name,seqNum,Evidence,ServerPubkey):
        self.secretKey = secretKey
        self.Name = Name
        self.seqNum = seqNum
        self.Evidence = Evidence
        self.ServerPubkey = ServerPubkey

    def __encryptAndHashReceivedData__(self, plaintext,secretKey):
        plaintextStr = plaintext#str(hex(plaintext))
        listOfBlocks = textwrap.wrap(plaintextStr, 32)

        # Iterate through list of blocks and exncrypt each block and concatenate into full enxrypted string
        encryptedString = "0x"
        for x in listOfBlocks:
            xHex = int(x, 16)
            encryptedData = encrypt_data(xHex, secretKey)
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
