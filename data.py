'''
This is the evidence
'''
import binascii
from RSA import generate_keypair,encryptRSA,decryptRSA
from Handler import generateAESkey
def evidence():
    return "Shands"


if __name__ == '__main__':
    data = 0xAAAABBB
    p=7
    q = 31
    pb,pv = generate_keypair(p,q)
    print(pb,pv)
    print("data",data)
    x = str(hex(data))
    print(x)
    y = int(x,16)
    print(y)
    #xa = x.encode()
    #x1 = xa.decode()
    for i in x:
        temp = ord(i)
        echar = encryptRSA(pb,str(i))
        print("echar=",echar)
        #print("AsciiVal=",temp)
        dchar = decryptRSA(pv,echar)
        print("dchar = ",dchar)
        #print("letter",chr(dchar))
