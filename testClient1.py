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
def inputHandler(handler,data,SocketData):
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
            return newData
        else:
            excryptedData = handler.__encryptAndHashReceivedData__(data)
            newSeqNum = handler.__removeSequenceNumber__(encryptTheData)
            newData = handler.__appendSequenceNumber__(newSeqNum, encryptTheData)
            return newData


    if command == 1:  # send keys and exit

        message = ('%s_Asym %d' % (handler.Name, HandlerX.PublicKey))
        message2 = ('%s_AES %s' % (handler.Name, HandlerX.secretKey))

        mySocket.sendto(message.encode(), SocketData)
        mySocket.sendto(message2.encode(), SocketData)

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
    pvK,pbK = generate_keypair(p,q)
    HandlerX = Handler(key,pvK,pbK,"H1")

    '''
    ############ User Operation ##########
    '''
    while True:
        mode = inputHandler(HandlerX,evidence(),socketData)

        if mode != -1:
            data = mode
            mySocket.sendto(data,(SERVER_IP,PORT_NUMBER))
        # message_encoded = []
        # for i in message:
        #     Etext = str(encrypt(HandlerX.PrivateKey, i))
        #     message_encoded.append(Etext)
        #     # ----do we need to include end of transission in asci???-------
        #
        # [mySocket.sendto(code.encode(), (SERVER_IP, PORT_NUMBER)) for code in message_encoded]

