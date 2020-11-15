
from RSA import  generate_keypair,encrypt,decrypt


#def generateKeys(p,q,ServerInfo,theSocket):

#    publicKey, privateKey = generate_keypair(p,q)

#    message = ('[Server] Key: %s' % (publicKey))
#    theSocket.sendto(message)

'''
# Checks the msgs that server recieves
# - if it recieves data act on different return value
'''
def checkMsg(msg):
    h1k = ""
    h2k = ""

    if msg.find("H2k") == 0:
        print("\n~~~~ Received key ~~~~")
        h2k = processKey(msg)
        print("\nHandler2 key = %s", h2k)
        mode = 1
        return h2k, mode

    if msg.find("H1k") == 0:
        #print("\n~~~~ Received key ~~~~")
        h1k = processKey(msg)
        #print("\nHandler1 key = %s", h1k)
        mode = 1
        return h1k, mode
        # append the h1k value to the key outside this function since this doesn't
        # handle the delivery of mesgs

    if msg.find("Data") == 0:
        print("\n~~~~ Received Data ~~~~~")
        print(msg)
        data = getData(msg)
        mode = 0
        return data, mode

    return -1

def inputController(data,SocketData,theSocket):
    print(menu)
    command = input(">> ")
    command.join('\n')

    if command == '0':
        print("\n~~~~~~ My Keys ~~~~~~~")
        privateKey, publicKey = generate_keypair(p,q)
        print('\nPrivate: %s'
              '\nPublic: %s '
              % privateKey, publicKey)
        keys = privateKey,publicKey
        return keys
    if command == '1':
        print("\n~~~~~~~ Extracting Data ~~~~~~~~~")

        return 0


def getData(msg):
    msgArray = msg.split()
    return msgArray[2]


def processKey(key):
    msg = key.split()  # splits by the spaces and places it into an array
    key_e = int(msg[1]) # encrypted char
    key_decrypt = decrypt(pk,int(key_e)) #decrypted char
    return key_decrypt

def formKey(aesKeyChar,keyFinal):
    return keyFinal.append(aesKeyChar)
#
#
#
#
#
# if(msg.header == 1):break // exit listen mode
#
# data = 1
# print("~~~~ ")
# print("Stopped listening mode")
# print(" ~~~~\n\n")
#
# command = int(input("Enter 1 to perform decrytion\n>>"))
#
# if(command == 1):
#     print("\n~~~ check hash ~~~")
#     print("\nInitialHash = " + getHash(data))
#     print("\nCheckHash = " + (newdata = checkHash(data)))
#
#     print("\n~~~~decrypting~~~~")
#     print("\n Hander2Key = " + Handler2Key)
#
#
#
#     print()

if __name__ == '__main__':
    key = 0x2b7e151628aed2a6abf7158809cf4f3c
    plaintext = 0x1111113243f6a8885a308d313198a2e03707343243f6a8885a308d313198a2e
    #extract msg components
    #   - handler who sent it
    #   - has value
    #   - seq number
    getData(plaintext)
    #calculate hash
    #   - get hash from msg
    #   - compare with check
    #
    # Decrypt data with handler Key
    # newMsg = decrypted data
    #
    #extract msg components etc...
