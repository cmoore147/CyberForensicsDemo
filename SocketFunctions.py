#!/usr/bin/env python3

import socket

HOST = '127.0.0.1'  # (localhost)
PORT = 1023        # Port to listen on (non-privileged are > 1023)
PORTc = 65432      #Port used to send stuff on
message = 'Encrypted';



#Function to
def client(HOST, PORT, send):
    #Code for sending functionality
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as m:
        m.connect((HOST, PORT))
        m.sendall(send)
        #data2 = m.recv(1024)
        m.close()
        return
#Function for setting up server to listen on
def server(HOST, PORT):
    while True:
        #Code for Server
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((HOST, PORT))
            s.listen()
            conn, addr = s.accept()
            with conn:
                print('Connected by', addr)
                while True:
                    data = conn.recv(1024)
                    if not data:
                        break
                    #conn.sendall(b"Hi")
                    print('recieved from client', repr(data))
    return

