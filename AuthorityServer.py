
from RSA import  generate_keypair,encryptRSA,decryptRSA


#def generateKeys(p,q,ServerInfo,theSocket):

#    publicKey, privateKey = generate_keypair(p,q)

#    message = ('[Server] Key: %s' % (publicKey))
#    theSocket.sendto(message)
menu = "|=======Menu==========|\n" \
       "| 0) Send Keys        |\n" \
       "| 1) Process Evidence |\n" \
       "| 2) Listen for Data  |" \
       "|=====================|\n"

'''
# Checks the msgs that server recieves
# - if it recieves data act on different return value
'''
def checkMsg(msg2,Server):

    MesgArray = msg.split()
    #message structure: " [Sender] Type : payload "
    print("messageArray",MesgArray)
    if MesgArray[1] == 'AES_Key':
        print("\n~~~~ Received key ~~~~")

        key = decryptRSA(Server.PrivateKey, int(MesgArray[2]))
        formKey(keyChar, MesgArray[0], HandlerKeyArray)
        print('\n%s AES_key = %s' % (MesgArray[0], key))
        return key, 1

    if MesgArray[1] == "Data":
        print("\n~~~~ Received Evidence ~~~~~")
        print(msg)
        data = MesgArray[2]
        #data = getData(MesgArray[2]) # returns data in int or str?
        return data, 0

    print("Error in Message Type")
    return -1

def inputController(data,p,q,Server):
    print(menu)
    command = input(">> ")
    command.join('\n')

    if command == '0':
        print("\n~~~~~~ My Keys ~~~~~~~")
        privKey, pubKey = generate_keypair(p,q)
        print('\nPrivate: %s'% (privKey,))
        print('\nPublic: %s '% (pubKey,))
        Server.PrivateKey = privKey
        Server.PublicKey = pubKey
        return 0,0

    if command == '1':
        print("\n~~~~~~~ Extracting Data ~~~~~~~~~")
        processData(data)

        return 0,1

    if command == '2':
        print("\n ~~~~~~~ Listening for Message ~~~~~~")
        temp = ""
        return temp, 2


def getData(msg):
    msgArray = msg.split()
    return msgArray[2]


def processKey(key):
    msg = key.split()  # splits by the spaces and places it into an array
    key_e = int(msg[1]) # encrypted char
    key_decrypt = decrypt(pk,int(key_e)) #decrypted char
    return key_decrypt

def decryptAESkey(Server,EncryptedArray):
    decryptedKey = ''
    for t in EncryptedKeyArray:
        temp = decrypt(Server.PrivateKey, t)
        decryptedKey += temp
        # print("temp",temp)

    print("Decrypted: " + decryptedKey)

def formKey(aesKeyChar,handlerName,KeyArray):
    if handlerName in KeyArray:
        KeyArray[handlerName] += aesKeyChar
    else:
        KeyArray[handlerName] = aesKeyChar
    print(KeyArray)

class Server():
    def __init__(self,PublicKey,PrivateKey,Evidence):
        self.PublicKey = PublicKey
        self.PrivateKey = PrivateKey
        self.Evidence = Evidence

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
    HandlerKeyArray = {}
    HandlerKeyArray
    #key = handlerName
    #paylod = Key
    ServerX = Server(0,0,"") #temp values for keys 0 and 0 and evidenc
    while True:

        mode = inputController(data,p,q,ServerX)

        if mode == 0:
            # sending key
            pubkey = ServerX.PublicKey
            # socketSendingFunction(key)

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
            # listening for msg

            msg = "[Handler1] AES_Key 34050201030"
            msgType = checkMsg(msg,ServerX)

            if msgType[1] == 1:
                handlerName = msgType[1]
                keyChar = msgType[0]
                formKey(keyChar,handlerName,HandlerKeyArray)
                # received key


            if msgType[1] == 0:
                print("~~~~~ Recieved Evidence ~~~~~")
                evidence = msgType[0]