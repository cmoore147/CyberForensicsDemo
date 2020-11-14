from socket import socket, gethostname, AF_INET, SOCK_DGRAM

from RSA import decrypt

PORT_NUMBER = 5000
SIZE = 1024

hostName = gethostname()
# hostName = gethostbyname( 'DESKTOP-A30LB1P' )

mySocket = socket(AF_INET, SOCK_DGRAM)
mySocket.bind((hostName, PORT_NUMBER))

print("Test server listening on port {0}\n".format(PORT_NUMBER))
client_public_key = ''
while True:
    (data, addr) = mySocket.recvfrom(SIZE)
    data = data.decode()
    if data.find('public_key') != -1:  # client has sent their public key\
        ###################################your code goes here#####################################
        # retrieve public key and private key from the received message (message is a string!)
        msg = data.split()  # splits by the spaces and places it into an array
        public_key_e = int(msg[1])
        public_key_n = int(msg[2])
        pk = (public_key_e, public_key_n)
        print('public key is : %d, %d' % (public_key_e, public_key_n))
    else:
        cipher = int(data)
        # cipher = long(float(data))
        data_decoded = decrypt(pk, cipher)
        print(str(cipher) + ':' + data_decoded)
        ###################################your code goes here#####################################
        # data_decoded is the decoded character based on the received cipher, calculate it using functions in RSA.py
sys.ext()
# What could I be doing wrong?
