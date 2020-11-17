'''
This is the evidence
'''
import binascii
#from RSA import generate_keypair,encrypt,decrypt
from Handler import generateAESkey
def evidence():
    return "Unhandled:_Yo_frank_shot_ben"


if __name__ == '__main__':
    '''
    p = 1297211
    q = 1297601
    p,v = generate_keypair(p,q)
    key = str(p[0] + p[1])
    print(p)
    AESkey = generateAESkey()
    #print(AESkey)
    #print("\n aes %s" % AESkey)
    # data =binascii.hexlify(key.encode())
    #hex(data)
    #print('0x'+data.decode())

    message_encoded = []
    AESkey = str(AESkey)
    for i in AESkey:
        etext = str(encrypt(p,i))
        message_encoded.append(etext)
    print(message_encoded)

    # send first message with header so server know its a key
    # after it knows this it will handled the rest accordingly
    '''
    temp = {}
    temp['aple'] = 6
    print(temp)
