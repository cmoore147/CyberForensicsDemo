from RSA import  generate_keypair,encryptRSA,decryptRSA
import hashFunction
from SocketFunctions import listen,send

menu = "\n|=======Menu==========|\n" \
       "| 0) Send Keys        |\n" \
       "| 1) Process Evidence |\n" \
       "| 2) Listen for Data  |\n" \
       "|=====================|\n"
portArray = [3000,4000,5000]

'''
# Checks the msgs that server recieves
# - if it recieves data act on different return value
'''
def checkMsg(msg,Server):

    MesgArray = msg.split()
    #message structure: " [Sender] Type: payload Type2: payload"
    #print('Incoming Msg:"%s"' % msg)
    if MesgArray[1] == 'AES_Key:':
        print("\n~~~~ Received key ~~~~")
        handlerKey = decryptHandlerKey(MesgArray[2],Server)
        storeKey(handlerKey, MesgArray[0], Server, MesgArray[4])
        #print('\n%s AES_key = %s' % (MesgArray[0], handlerKey))
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
    command = input(">> ")
    command.join('\n')

    if command == '0':
        print("\n~~~~~~ My Keys ~~~~~~~")

        return 0

    if command == '1':
        print("\n~~~~~~~ Extracting Data ~~~~~~~~~")
        seqNum = 1 #temp
        while seqNum > 0:
            EvidenceElements = processData(Server.Evidence)
            seqNum = EvidenceElements[2]
            if not checkHash(EvidenceElements[0],EvidenceElements[1]):
                #handlerX invalidated evidence
                return 1
            handlerkey = determindHander()
            if DecryptData(EvidenceElements[0],handler,Server) == -1:
                return -1
        return 0

    if command == '2':
        print("\n ~~~~~~~ Listening for Message ~~~~~~")
        return 2

    else:
        print("[ERROR] Invalid command")
        return -1

def DecryptData(cipherText,HandlerAESKey,Server):
    AESfunct = AES(HandlerAESKey)
    decrypted = AES.decrypt(AESfunct, ciphertext)
    Server.Evidence = decrypted
    return 0

def decryptHandlerKey(eKey,Server):
    ekeyArray = eKey.split(',')
    key = ''
    print("Server Key: ",Server.PrivateKey)
    print(ekeyArray)
    for char in ekeyArray[:len(ekeyArray)-1]:
        assert char == str , "char in ecrypted array in not a string"
        print("char =",int(char))
        temp = decryptRSA(Server.PrivateKey, int(char))
        #assert temp == str
        print("type of temp=",type(temp))
        key.join(str(temp))
        #print("Decrypted_Char= ",str(temp))
    #print("key = ",key)
    return key

def processData(data):
    seqNum = data[len(data)-1]
    givenHash = data[len(data)-40:len(data)-1] # check how long hash is
    data = data[:len(data)-4] #check how long data is
    return data,givenHash,seqNum

def checkHash(data,hash):
    checkH = hashFunction.digest_hash(data)
    checkH = str(hex(int.from_bytes(hashValue,"big")))
    hash = hex(str())
    print('CheckHash: %s\n'
          'Given Hash: %s' % (checkH,hash))

    if checkH == data:
        print(">>Hash valid<<")
        return True
    else:
        print(">>Hash Invalid<<")
        return False


'''
# Manages creation of HandlerKeys data structure #
- intialized handler keys 
- appends incoming decrepyted chars to partially formed keys
'''
def storeKey(aesKeyChar,handlerName,Server,handlerSeqNum):
    Server.HandlerKeys[handlerName] = aesKeyChar
    Server.HandlerKeys[handlerSeqNum] = handlerName
    #print("Server Key library: ",Server.HandlerKeys)


def packageKey(serverKey):
    return str(ServerX.PublicKey[0]) + ',' + str(ServerX.PublicKey[1])

class Server():
    def __init__(self,PublicKey,PrivateKey,Evidence,HandlerKeys):
        self.PublicKey = PublicKey
        self.PrivateKey = PrivateKey
        self.Evidence = Evidence
        self.HandlerKeys = HandlerKeys

if __name__ == '__main__':
    #key = 0x2b7e151628aed2a6abf7158809cf4f3c
    data = 0x1111113243f6a8885a308d313198a2e03707343243f6a8885a308d313198a2e
    """
    ############# Server Setup ################
    """
    q = 7
    p = 31
    pubKey, privKey = generate_keypair(p, q)
    print('Private: %s' % (privKey,))
    print('Public: %s' % (pubKey,))
    serverPort = 5000
    ServerX = Server(pubKey,privKey, data, {})  # temp values for keys 0 and 0 and evidence

    while True:
        mode = inputController(ServerX)
        if mode == 0: ######### SendingKey ##########
            for x in portArray:
                keyString = packageKey(ServerX.PublicKey)
                msg = '[Server] PublicKey: %s' % keyString
                try:
                    send(x,msg)
                except:
                    print("[Error] Sending Keys to Port %s" % x)

        if mode == 1:
            # inputController Calls data processing functions
            # when program reaches here system is over
            # actually return value could be if data is valid
            c = input("Reset and try again? [PRESS ENTER]")
            if c =='':
                evidence = ""
                pass
            else:
                sys.exit()
            # extracting data

        if mode == 2:
            #--------------------
            msg = listen(5000)
            #----------------------
            #msg = "[Handler1] AES_Key 34050201030 SeqNum: 1"
            #msg = "[handler1] Data "+ str(data)
            msgType = checkMsg(msg,ServerX)

            if msgType == 1:
                print("~~~ Updated HandlerKey Library ~~~")
            if msgType == 0:
                print("~~~~~ Recieved Evidence ~~~~~")
                enter = input(">> Press Enter to Stop listening <<")
