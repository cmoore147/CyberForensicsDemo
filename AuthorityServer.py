
from RSA import  generate_keypair,encrypt,decrypt


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
        print("\n~~~~ Received key ~~~~")
        h1k = processKey(msg)
        print("\nHandler1 key = %s", h1k)
        mode = 1
        return h1k, mode

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
    public_key_e = int(msg[1])
    public_key_n = int(msg[2])
    pk = (public_key_e, public_key_n)
    return pk
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
