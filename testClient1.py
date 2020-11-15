from socket import socket, AF_INET, SOCK_DGRAM, gethostname
#from RSA import generate_keypair, encrypt,decrypt
from data import evidence
import sys
from Handler import *
from Crypto.PublicKey import RSA

splash = "\n"
menu = "|=======Menu========|\n" \
       "| 0) Handle Data    |\n" \
       "| 1) Send keys+Exit |\n" \
       "|===================|\n"

'''
# Handles the msg that the handler will recieve
# - messages are either from server or client
# - input must be decoded into a string
# - returns either key or data
'''
def checkMsg(msg):
    msgArray = msg.split()

    if msg[0]  == "[Server]":
        print("\n ~~~~~ Msg from %s ~~~~",msg[0])
        print("\n",msg)
        serverPbKey = msg[2]

        return serverPbKey, 0

    if msg[0].find("Hander") == 0: # msg from a handler
        print("\n ~~~~~ Msg from %s ~~~~~",msg[0])
        print("\n",msg)

        return data, 1

    else:
        print("\nError with handler name")
        return -1


'''
Returns an array of encryped chars  that make up the AES key
'''
def encryptAESkey(aesKey,pbk):

    #for i in key:
    etext = encrypt(pbK,aesKey)
    #key_encoded.append(etext)

    return etext

'''
# handled the commands from the user
'''
def inputController(handler,data,ServerPubKey,pvk):
    print(menu)
    command = int(input(">> "))
    print("\n")

    if command == 0:  # handle data

        if data.find("Unhandled") == 0:
            print('~~~~~~~Data~~~~~~~')
            data = processPlainText(data)
            encryptedData = handler.__encryptAndHashReceivedData__(data,handler.secretKey)
            print("Encrypted Data: %s" % encryptedData)
            encryptedData += "0"
            newSeqNum = handler.__removeSequenceNumber__(encryptedData)
            print("SeqNum: %s" % newSeqNum)
            newData = handler.__appendSequenceNumber__(newSeqNum, encryptedData)
            message = ('[%s] Data: %s' % ( handler.Name,newData))
            print("Message to Send: %s\n" % message)
            #theSocket.sendto(message, (SERVER_IP, PORT_NUMBER))
            return 0

        else: #data has been handled before
            excryptedData = handler.__encryptAndHashReceivedData__(data,handler.secretKey)
            newSeqNum = handler.__removeSequenceNumber__(encryptTheData)
            newData = handler.__appendSequenceNumber__(newSeqNum, encryptTheData)
            message = ('[%s] Data: %s' % (handler.Name, newData))
            print("\n", message)
            #theSocket.sendto(message, (SERVER_IP, PORT_NUMBER))
            return 0

    '''
    # Encrypts AES with server pub key
    '''
    if command == 1:  # send key to authoritative Server and exit
        print("\n  ~~~~~~ My Secret Key ~~~~~~~  \n key: %s" % handler.secretKey)
        print("\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
        #ekey = encryptAESkey(handler.secretKey,ServerPubKey)

        message = ('[%s] AES_Key: ' % (handler.Name))
        print(int(handler.secretKey))
        newkey = encrypt(ServerPubKey,handler.secretKey)
        print(newkey)
        print(decrypt(pvk,newkey))
        enter = input("\n>> Press ENTER to send <<\n")

        if enter == '':
            #for i in ekey:
            #    msg =(message + i)
            #    #theSocket.sendto(msg.encode(), SocketData)
            #    print(msg)

            print("\n ~~~~ Exiting Handler ~~~~~")
        return -1

    print("\nInvalid input")
    return 0




if __name__ == '__main__':

    print(splash)
    '''
    ########## Socket Setup #########
    '''
    SERVER_IP = gethostname()
    PORT_NUMBER = 5000
    socketData = (SERVER_IP,PORT_NUMBER)
    SIZE = 1024
    print("Test client sending packets to IP {0}, via port {1}\n".format(SERVER_IP, PORT_NUMBER))
    mySocket = socket(AF_INET, SOCK_DGRAM)

    '''
    ########### Handler Setup ##########
    '''
    p = 1297211
    q = 1297601
    key = generateAESkey()

    pvK,pbK =
    print("pub ",pbK)
    print("priv ",pvK)
    HandlerX = Handler(key,"H1")

    '''
    ########### User Operation ##########
    
    '''
    #evidence = 0x796F2062656E2073686F74206672616E6B0D0A
    while True:
        # each client will be recieving from a socket
        # client 1 starts with data

        mode = inputController(HandlerX,evidence(),pbK,pvK)

        if mode == -1:
            sys.exit()
        # message_encoded = []
        # for i in message:
        #     Etext = str(encrypt(HandlerX.PrivateKey, i))
        #     message_encoded.append(Etext)
        #     # ----do we need to include end of transission in asci???-------
        #
        # [mySocket.sendto(code.encode(), (SERVER_IP, PORT_NUMBER)) for code in message_encoded]

