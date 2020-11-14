from socket import socket, AF_INET, SOCK_DGRAM, gethostname
from RSA import generate_keypair, encrypt
from data import evidence
import sys
from Handler import *

splash = "\n"
menu = "========Menu=========\n" \
       "= 0) Handle Data    =\n" \
       "= 1) Send keys+Exit =\n" \
       "=====================\n"

'''
Returns an array of encryped chars  that make up the AES key
'''
def encryptAESkey(aesKey):
    key = str(aesKey)
    key_encoded = []
    for i in key:
        etext = str(encrypt(p,i))
        key_encoded.append(etext)

    return key_encoded

def inputController(handler,data,SocketData,theSocket):
    print(menu)
    command = input(">> ")
    command.join('\n')

    if command == 0:  # handle data

        if data[0:10] == "Unhandled":
            data = processPlainText(data)
            excryptedData = handler.__encryptAndHashReceivedData__(data)
            excryptedData += "0"
            newSeqNum = handler.__removeSequenceNumber__(encryptTheData)
            newData = handler.__appendSequenceNumber__(newSeqNum, encryptTheData)
            theSocket.sendto(newData, (SERVER_IP, PORT_NUMBER))
            return 0

        else: #data has been handled before
            excryptedData = handler.__encryptAndHashReceivedData__(data)
            newSeqNum = handler.__removeSequenceNumber__(encryptTheData)
            newData = handler.__appendSequenceNumber__(newSeqNum, encryptTheData)
            theSocket.sendto(newData, (SERVER_IP, PORT_NUMBER))
            return 0

    '''
    # Encrypts AES with server pub key
    '''
    if command == 1:  # send key to authoritative Server and exit
        ekey = encryptAESkey(handler.secretKey)
        message = ('%s_AES %s' % (handler.Name, ekey[[0]]))
        theSocket.sendto(message.encode(), SocketData)

        if input("\nPress enter to send:\n>>"): # WAIT FOR SERVER TO HANDLE 1ST MSG
            for i in ekey[1:]:
                theSocket.sendto(i.encode(), SocketData)


        print("\n ~~~~ Exiting Handler ~~~~~")
        return -1




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
    #pvK,pbK = generate_keypair(p,q)
    HandlerX = Handler(key,"H1")

    '''
    ########### User Operation ##########
    '''
    while True:
        mode = inputController(HandlerX,evidence(),socketData)

        if mode == -1:
            sys.exit()
        # message_encoded = []
        # for i in message:
        #     Etext = str(encrypt(HandlerX.PrivateKey, i))
        #     message_encoded.append(Etext)
        #     # ----do we need to include end of transission in asci???-------
        #
        # [mySocket.sendto(code.encode(), (SERVER_IP, PORT_NUMBER)) for code in message_encoded]

