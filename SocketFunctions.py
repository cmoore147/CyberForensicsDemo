import sys
from socket import socket, AF_INET, SOCK_DGRAM, gethostname
from RSA import generate_keypair,encryptRSA,decryptRSA


def send(PORT_NUMBER, data,name):
    SERVER_IP = gethostname()
    SIZE = 1024

    mySocket = socket(AF_INET, SOCK_DGRAM)  # Connection  Setup
    mySocket.sendto(data.encode(), (SERVER_IP, PORT_NUMBER))

    print ("[",Name,"]"," sending packets to IP {0}, via port {1}\n"
                        "".format(SERVER_IP, PORT_NUMBER))
    return



def listen(PORT_NUMBER,Name):
    hostName = gethostname()
    SIZE = 1024

    mySocket = socket( AF_INET, SOCK_DGRAM ) #Creates socket
    mySocket.bind( (hostName, PORT_NUMBER) ) #Binds socket

    print ("[",Name,"]"," listening on port {0}\n"
                        "".format(PORT_NUMBER)) #States which port server is listening on

    (data,addr) = mySocket.recvfrom(SIZE)
    data = data.decode()
    return data
