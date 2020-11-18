import sys
from socket import socket, AF_INET, SOCK_DGRAM, gethostname
from RSA import generate_keypair,encryptRSA,decryptRSA


def send(PORT_NUMBER, data):
    #Client side
    SERVER_IP = gethostname()

    SIZE = 1024
    print ("Test client sending packets to IP {0}, via port {1}\n".format(SERVER_IP, PORT_NUMBER))

    mySocket = socket( AF_INET, SOCK_DGRAM ) #Connection  Setup

    mySocket.sendto(data.encode(),(SERVER_IP,PORT_NUMBER))
    return




def listen(PORT_NUMBER):
    #Server side socket
    hostName = gethostname()
    SIZE = 1024


    mySocket = socket( AF_INET, SOCK_DGRAM ) #Creates socket
    mySocket.bind( (hostName, PORT_NUMBER) ) #Binds socket

    print ("Test server listening on port {0}\n".format(PORT_NUMBER)) #States which port server is listening on
    #client_public_key=''

    (data,addr) = mySocket.recvfrom(SIZE)
    data = data.decode()
    return data
