from RSA import  generate_keypair,encryptRSA,decryptRSA
import hashFunction
from SocketFunctions import listen,send
from aes import AES
import binascii
import textwrap
import sys

menu = "\n|====Command Window=====|\n" \
       "| 0) Send Keys          |\n" \
       "| 1) Process Evidence   |\n" \
       "| 2) Listen for Msg     |\n" \
       "|=======================|\n"
portArray = [3000,4000,5000]

'''
# Checks the msgs that server recieves
# - if it recieves data act on different return value
'''
def checkMsg(msg,Server):
    MesgArray = msg.split()
    ########### message structure: ############
    # '[Sender] Type: payload Type2: payload' #

    if MesgArray[1] == 'AES_Key:':
        print("\n~~~~ Received key ~~~~")
        handlerKey = decryptHandlerKey(MesgArray[2],Server)
        storeKey(handlerKey, MesgArray[0], Server, MesgArray[4])
        return 1

    if MesgArray[1] == "Data:":
        print("\n~~~~ Received Evidence ~~~~~")
        print(msg)
        Server.Evidence = MesgArray[2]
        return 0

    print("Error in Message Type")
    return -1

def inputController(Server):
    print(menu)
    command = input('[%s]>> ' % Server.Name)
    command.join('\n')

    if command == '0':
        print("\n~~~~~~ Sending Public Key ~~~~~~~")

        return 0

    if command == '1':
        print("\n~~~~~~~ Extracting Data ~~~~~~~~~")
        seqNum = 1 #temp

        while seqNum > 0:
            EvidenceElements = processData(Server.Evidence)
            print("~[Evidence Elements]~\n"
                  "Data: %s\n"
                  "Hash: %s\n"
                  "SeqNum: %d\n" % (hex(EvidenceElements[0]),
                                    hex(EvidenceElements[1]),
                                    EvidenceElements[2])
                  )

            seqNum = EvidenceElements[2]
            if not checkHash(EvidenceElements[0],EvidenceElements[1]):
                return 3
            handlerKey = Server.HandlerKeys[seqNum]
            if DecryptData(EvidenceElements[0],handlerKey,Server) == -1:
                return 3
            seqNum = seqNum -1
            handlerName = Server.HandlerKeys.fromKeys(handlerKey)
            i = input("#### Chain Verified ####\n [ENTER]" % )
        return 1

    if command == '2':
        print("\n ~~~~~~~ Listening for Message ~~~~~~")
        return 2

    else:
        print("[ERROR] Invalid command")
        return -1

def DecryptData(cipherText,HandlerAESKey,Server):
    AESfunct = AES(HandlerAESKey)

    stringOfCipherText = str(hex(cipherText))
    stringOfCipherText = stringOfCipherText[2:]
    listOfBlocks = textwrap.wrap(stringOfCipherText,32)

    decryptedString = "0x"
    i =0
    for x in listOfBlocks:
        #print("Decrypting Block %d = "%i,x)
        xHex = int(x,16)
        decryptedData = AES.decrypt(AESfunct, xHex)
        tempStr = str(hex(decryptedData))
        tempStr = tempStr[2:]
        decryptedString += tempStr
        i+=1

    temp = binascii.unhexlify(((str('%00x' % int(decryptedString, 16)))))
    tempDecoded = str(temp,'utf-8')[:]
    Server.Evidence = tempDecoded
    return 0

def decryptHandlerKey(eKey,Server):
    ekeyArray = eKey.split(',')
    key = ''
    print("Server Pubkey: ",Server.PrivateKey)
    print(ekeyArray)
    for char in ekeyArray[:len(ekeyArray)-1]:
        assert isinstance(char,str) , "char in ecrypted array in not a string"
        temp = decryptRSA(Server.PrivateKey, int(char))
        key += str(temp)

    return key

def processData(data):
    seqNum = int(data[len(data)-1])
    givenHash = int(data[len(data)-41:len(data)-1],16)
    data = int(data[:len(data)-41],16)
    return data,givenHash,seqNum

def checkHash(hexData,givenHashHex):
    checkH = hashFunction.digest_hash(hexData)
    checkHashHex = int.from_bytes(checkH, "big")
    print("\n~~~~ Examine Hash ~~~~")
    print('Check Hash_hex: %s\n'
          'Given Hash_hex: %s' % (hex(checkHashHex),hex(givenHashHex)))

    if checkHashHex == givenHashHex:
        print(">>HASH VALID<<")
        return True
    else:
        print(">>Hash Invalid<<")
        return False


'''
# Manages creation of HandlerKeys data structure #
- intialized handler keys 
'''
def storeKey(aesKey,handlerName,Server,handlerSeqNum):
    #print("[",handlerName,"]","aesKey=",aesKey)
    Server.HandlerKeys[handlerName] = int(aesKey,16)
    Server.HandlerKeys[int(handlerSeqNum)] = int(aesKey,16)
    print("Updated Handler Key Library: ",Server.HandlerKeys)



def packageKey(serverKey):
    return str(ServerX.PublicKey[0]) + ',' + str(ServerX.PublicKey[1])

class Server():
    def __init__(self,PublicKey,PrivateKey,Evidence,HandlerKeys,Name):
        self.PublicKey = PublicKey
        self.PrivateKey = PrivateKey
        self.Evidence = Evidence
        self.HandlerKeys = HandlerKeys
        self.Name = Name

if __name__ == '__main__':
    """
    ############# Server Setup ################
    """
    q = 61
    p = 31
    pubKey, privKey = generate_keypair(p, q)
    print('Private: %s' % (privKey,))
    print('Public: %s' % (pubKey,))
    serverPort = 5000
    ServerX = Server(pubKey,privKey, 0, {},"Authoritative_Server")  # temp values for keys 0 and 0 and evidence

    """
    ############# User Operation ###############
    """
    while True:
        mode = inputController(ServerX)
        if mode == 0: ######### SendingKey ##########
            for x in portArray:
                keyString = packageKey(ServerX.PublicKey)
                msg = '[Server] PublicKey: %s' % keyString
                try:
                    send(x,msg,ServerX.Name)
                except:
                    print("[Error] Sending Keys to Port %s" % x)

        if mode == 1:########## Processing evidence #########
            print("###### Data is Verified #######")
            print('PlainText Evidence: ',ServerX.Evidence)
            c = input("To Exit [PRESS ENTER]")
            sys.exit()
        if mode == 3:
            c = input("Reset and try again? [PRESS ENTER]")
            if c == '':
                evidence = ""
                pass
            else:
                sys.exit()
            # extracting data

        if mode == 2: ########## Listening for Msg ##########
            msg = listen(5000,ServerX.Name)
            msgType = checkMsg(msg,ServerX)

            if msgType == 1:
                print("~~~ Updated HandlerKey Library ~~~")
            if msgType == 0:
                print("~~~~~ Recieved Evidence ~~~~~")
                #enter = input(">> Press Enter to Stop listening <<")
