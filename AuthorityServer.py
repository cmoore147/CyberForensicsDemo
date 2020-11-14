
from RSA import  generate_keypair,encrypt,decrypt


def generateAndSendKeys(p,q,ServerInfo,theSocket):

    publicKey, privateKey = generate_keypair(p,q)

    message = message = ('Server_pubK: %d' % (publicKey))
    theSocket.sendto()


def checkMsg(msg):
    h1k = ""
    h2k = ""

    if msg.find('H2k') == 0:
        print("\n~~~~ Received key ~~~~")
        h2k = processKey(msg)
        print("\nHandler2 key = %s", h2k)
        mode = 1
        return h2k, mode

    if msg.find('H1k') == 0:
        #print("\n~~~~ Received key ~~~~")
        h1k = processKey(msg)
        #print("\nHandler1 key = %s", h1k)
        mode = 1
        return h1k, mode
        # append the h1k value to the key outside this function since this doesn't
        # handle the delivery of mesgs

    if msg.find('data') == 0:
        print("\n~~~~ Received Data ~~~~~")
        data = processData(msg)
        mode = 0
        return data, mode

    return -1


def processData(data):
    return data


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
