'''
This is the evidence
'''
import binascii
from RSA import generate_keypair,encryptRSA,decryptRSA
from Handler import generateAESkey
def evidence():
    return "Unhandled:_Yo_frank_shot_ben"


if __name__ == '__main__':
    data = 0xAAAABBB
    p=61
    q = 31
    pb,pv = generate_keypair(p,q)
    print(pb,pv)
    x = str(hex(data))
    #xa = x.encode()
    #x1 = xa.decode()
    for i in x:
        temp = ord(i)
        echar = encryptRSA(pb,i)
        print("echar=",echar)
        #print("AsciiVal=",temp)
        dchar = decryptRSA(pv,echar)
        print("dchar = ",dchar)
        #print("letter",chr(dchar))
