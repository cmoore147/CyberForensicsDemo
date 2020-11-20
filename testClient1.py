from socket import socket, AF_INET, SOCK_DGRAM, gethostname
from RSA import generate_keypair, encryptRSA,decryptRSA
from data import evidence
import sys
from Handler import *
from SocketFunctions import listen, send
from AuthorityServer import decryptHandlerKey
#from Crypto.PublicKey import RSA

splash = "\n"
menu = "|=======Menu========|\n" \
       "| 0) Handle Data    |\n" \
       "| 1) Send keys+Exit |\n" \
       "| 2) listen for msg |\n" \
       "|===================|\n"

portlist = "\n|======Ports======|\n"\
           "| Handler2) 3000  |\n"\
           "| Handler3) 4000  |\n"\
           "| Server)   5000  |\n"\
           "|=================|"
portArray = [5000,4000,3000]

'''
# Handles the msg that the handler will recieve
# - messages are either from server or handler
# - returns int corresponding to msg type
'''
def checkMsg(msg,handler):
    msgArray = msg.split()
    #msgformat: "[Sender] type: Payload"
    if msgArray[1]  == 'PublicKey:':
        print("\n ~~~~~ Msg from %s ~~~~" % msgArray[0])
        print(msg)
        serverPbKey = msgArray[2].split(',')
        print(serverPbKey)
        e = int(serverPbKey[0])
        assert isinstance(e,int)
        n = int(serverPbKey[1])
        assert isinstance(n, int)
        handler.ServerPubkey = (e,n)
        return 0

    elif msgArray[1]=='Data:': # msg from a handler
        print("\n ~~~~~ Msg from %s ~~~~~" % msgArray[0])
        print("\n",msg)
        handler.Evidence = msgArray[2] #string
        return 1

    else:
        print("\nError with Msg format")
        return -1


'''
Returns an array of encryped chars  that make up the AES key
'''
def encryptAESkey(aesKey,ServerPubkey):
    EncryptedKeyString = ''
    #EncrypedKeyArray = []
    for i in aesKey: # ases key is a string
        assert isinstance(i,str) ,"Aes char is not a string"
        temp = encryptRSA(ServerPubkey,i)
        #print("tempEncryptio=",temp)
        EncryptedKeyString += str(temp) #encryption return int
        #EncryptedArray.append(temp)
        EncryptedKeyString+=','
    return EncryptedKeyString

'''
# handled the commands from the user
'''
def inputController(handler):
    print(menu)
    command = int(input(">> "))
    print("\n")

    if command == 0:  # handle data

        if handler.Evidence.find("Unhandled") == 0:
            print('~~~~~~~Data~~~~~~~')
            data = processPlainText(handler.Evidence)
            print("HexEncoding of Plaintext",data)
            #cast key to string
            encryptedData = handler.__encryptAndHashReceivedData__(data,handler.secretKey)
            print("Encrypted Data: %s" % encryptedData)
            encryptedData += "0"
            newSeqNum = handler.__removeSequenceNumber__(encryptedData)
            handler.seqNum = newSeqNum
            print("SeqNum: %s" % newSeqNum)
            newData = handler.__appendSequenceNumber__(newSeqNum, encryptedData)
            message = ('[%s] Data: %s' % ( handler.Name,newData))
            print("Message to Send: %s\n" % message)
            return message, 0

        else: #data has been handled before
            temp10 = str(handler.Evidence)[2:]
            data = processPlainText(temp10)
            print("type of evidence", type(handler.Evidence))
            print("HexEncoding of Plaintext",handler.Evidence)
            print("HexEncoding of Plaintext", data)
            newSeqNum = handler.__removeSequenceNumber__(handler.Evidence)
            print("SeqNum: %s" % newSeqNum)
            handler.seqNum = newSeqNum

            temp = int((handler.Evidence), 16)
            print("change in type of Evidence hex=",hex(temp))

            encryptedData = handler.__encryptAndHashReceivedData__(data,
                                                                   handler.secretKey)
            print("Encrypted Data: %s" % encryptedData)
            #newData = handler.__appendSequenceNumber__(newSeqNum,encryptedData)
            newData = encryptedData + newSeqNum
            message = ('[%s] Data: %s' % (handler.Name, newData))
            print("Message to Send: %s\n" % message)
            #theSocket.sendto(message, (SERVER_IP, PORT_NUMBER))
            return message,0

    '''
    # Encrypts AES with server pub key
    '''
    if command == 1:  # send key to authoritative Server and exit
        print("\n  ~~~~~~ My Secret Key ~~~~~~~  \n key: %s" % handler.secretKey)
        print("\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
        AesKey = str(hex(handler.secretKey))
        EncryptedKeyString = encryptAESkey(AesKey,handler.ServerPubkey)
        print(EncryptedKeyString)
        message = ('[%s] AES_Key: %s' % (handler.Name, EncryptedKeyString))
        return message, 1

    if command == 2:
        while 1:
            print(portlist)
            print(">> Choose a port <<")
            port = int(input(">>"))
            return port,2

    print("[Error] Invalid command")
    return -1,-1




if __name__ == '__main__':

    print(splash)
    '''
    ########### Handler Setup ##########
    '''
    p = 1297211 # for testing
    q = 1297601 # for testing
    key = generateAESkey()
    ServerPubKey,pvk = generate_keypair(p,q) # for testing
    handlerName = str(input("Whats ur name?"))
    #print("handlerkey",str(hex(key)))
    HandlerX = Handler(key,handlerName,0,"",0)
    HandlerX.Evidence = evidence()
    serverPort = 5000
    '''
    ########### User Operation ##########
    '''
    while True:
        mode = inputController(HandlerX)

        """
        ######## process data and send ########
        """
        if mode[1] == 0:
            print(portlist)
            port = int(input("\n>> Chose a Port <<\n"))
            if port != '':
                msg = mode[0]
                print("Sending Message")
                try:
                    send(port,msg)
                except:
                    print("Error writting to socket")

                #print("Msg attempting to send", msg)
        '''
        ######### Encrypt Private key and Send to Server ########
        '''
        if mode[1] == 1:
            enter = input("\n>> Press Enter to Send <<\n")
            msg = mode[0]
            print("Message: ", msg)
            if enter == '':
                #msg = (message + EncrypedKeyString)
                msg += ' SeqNum: ' + str(HandlerX.seqNum)
                try:
                    send(serverPort,msg)
                except:
                    print("Error writting to socket")

        """
        # Handler is listening on port for message
        """
        if mode[1] == 2:
            print("")
            # print(portlist)
            # port = input("\n>> Choose a port<<\n")
            port = mode[0]
            msg = listen(port)
            msgType = checkMsg(msg,HandlerX)
            if msgType == 0:
                print("~~~~ Received Server Key ~~~~~")
            if msgType == 1:
                print("~~~~ Received Evidence ~~~~~~~")


