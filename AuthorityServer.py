
from RSA import  generate_keypair,encryptRSA,decryptRSA


#def generateKeys(p,q,ServerInfo,theSocket):

#    publicKey, privateKey = generate_keypair(p,q)

#    message = ('[Server] Key: %s' % (publicKey))
#    theSocket.sendto(message)
menu = "\n|=======Menu==========|\n" \
       "| 0) Send Keys        |\n" \
       "| 1) Process Evidence |\n" \
       "| 2) Listen for Data  |\n" \
       "|=====================|\n"

'''
# Checks the msgs that server recieves
# - if it recieves data act on different return value
'''
def checkMsg(msg,Server):

    MesgArray = msg.split()
    #message structure: " [Sender] Type : payload "
    #print('Incoming Msg:"%s"' % msg)
    if MesgArray[1] == 'AES_Key':
        print("\n~~~~ Received key ~~~~")

        keyChar = decryptRSA(Server.PrivateKey, int(MesgArray[2]))
        formKey(keyChar, MesgArray[0], HandlerKeyArray)
        print('\n%s AES_key = %s' % (MesgArray[0], keyChar))
        return 1

    if MesgArray[1] == "Data":
        print("\n~~~~ Received Evidence ~~~~~")
        print(msg)
        Server.Evidence = MesgArray[2]
        return 0

    print("Error in Message Type")
    return -1

def inputController(data,p,q,Server):
    print(menu)
    command = input(">> ")
    command.join('\n')

    if command == '0':
        print("\n~~~~~~ My Keys ~~~~~~~")
        privKey, pubKey = generate_keypair(p,q)
        print('Private: %s'% (privKey,))
        print('Public: %s'% (pubKey,))
        Server.PrivateKey = privKey
        Server.PublicKey = pubKey
        return 0

    if command == '1':
        print("\n~~~~~~~ Extracting Data ~~~~~~~~~")
        while seqNum > 0:
            EvidenceElements = processData(Server.Evidence)
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


def processData(data):
    seqNum = data[len(data)-1]
    givenHash = data[len(data)-4:len(data)-1] # check how long hash is
    data = data[:len(data)-4] #check how long data is
    return data,givenHash,seqNum

def checkHash(data,hash):
    checkH = data
    print('CheckHash: %s\n'
          'Given Hash: %s' %checkH,hash)

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
def formKey(aesKeyChar,handlerName,Server):
    if handlerName in Server.KeyArray:
        #append next char to the key
        Server.KeyArray[handlerName] += aesKeyChar
    else:
        # base case when there is no partial key in the dictionary
        KeyArray[handlerName] = aesKeyChar
    print("Server Key library: ",KeyArray)

class Server():
    def __init__(self,PublicKey,PrivateKey,Evidence,HandlerKeys):
        self.PublicKey = PublicKey
        self.PrivateKey = PrivateKey
        self.Evidence = Evidence
        self.HandlerKeys = HandlerKeys

if __name__ == '__main__':
    key = 0x2b7e151628aed2a6abf7158809cf4f3c
    data = 0x1111113243f6a8885a308d313198a2e03707343243f6a8885a308d313198a2e
    #extract msg components
    #   - handler who sent it
    #   - hash value
    #   - seq number
    #getData(plaintext)
    #calculate hash
    #   - get hash from msg
    #   - compare with check
    #
    # Decrypt data with handler Key
    # newMsg = decrypted data
    #
    #extract msg components etc...
    p = 7
    q = 11


    #key = handlerName
    #paylod = Key
    ServerX = Server(0,0,"",{}) #temp values for keys 0 and 0 and evidence
    while True:

        mode = inputController(data,p,q,ServerX)

        if mode == 0:
            # sending key
            try:
                socketSendingFunction(ServerX.PublicKey,lsitport)
                #sending function will write to each handlers Ports
                #Function input:
                    #-msg
                    #-port list
                # returns after sent each message and socket is closed
            except:
                print("Error sending Keys")

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

        if mode[1] == 2:
            #--------------------
            # listening for msg
            # listening on socket function right here
            # msg = socketList()
            # listening function is in continuous loop
            # inputs:
                #- ports
                #-flag (1 to close socket, 0 leave open)
            #----------------------
            #msg = "[Handler1] AES_Key 34050201030"
            msg = "[handler1] Data "+ str(data)
            msgType = checkMsg(msg,ServerX)

            if msgType == 1:
                print("Forming Key....")
                pass
            if msgType == 0:
                print("~~~~~ Recieved Evidence ~~~~~")
                enter = input(">> Press Enter to Stop listening <<")
                flag = 1
