'''
This is the evidence
'''
import binascii

def evidence():
    return "Unhandled:_Yo_frank_shot_ben"
if __name__ == '__main__':
    data =binascii.hexlify(evidence().encode())
    #hex(data)
    print('0x'+data.decode())