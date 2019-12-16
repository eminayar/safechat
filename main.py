users = {}
encryption_keys = {}
G = 10399
P = 11503
host_ip = "FILL HERE"
from threading import Lock
lock = Lock()
## [emin,192.168.1.2,newKey,G,P,A]
## [esra,192.168.1.3,pubkey,B]


def send_response( host_name, host_ip, target_ip ):
    import socket
    response_message = '[' + host_name + ',' + host_ip + ',response]'
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((target_ip,12345))
        s.sendall(str.encode(response_message))

def send_message( host_name, target_ip, message, lock ):
    import socket
    import random
    response_message = '[' + host_name + ',' + host_ip + ',message,' + message + ']'
    if target_ip not in encryption_keys:
        lock.acquire()
        a = random.randint(1,P-1)
        A = pow(G,a) % P
        key_message = '[' + host_name + ',' + host_ip + ',newKey,' + str(G) + ','+ str(P) + ','+ str(A) + ']'
        encryption_keys[target_ip] = a
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((target_ip,12345))
            s.sendall(str.encode(key_message))
    with lock:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((target_ip,12345))
            s.sendall(str.encode(response_message))

def announcement_listener( host_name, host_ip ):
    import select, socket
    import time
    import _thread
    global users

    port = 12345
    bufferSize = 1024
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(('', port))
    s.setblocking(False)
    while True:    
        result = select.select([s],[],[])
        msg = result[0][0].recv(bufferSize).decode('ascii')
        usr, ip, tp = msg.split(',')
        usr = usr.strip()[1:]
        tp = tp.strip()[:-1]
        ip = ip.strip()
        if tp.strip() == 'announce' and ip != host_ip:
            if (usr not in users) or (usr in users and time.time()-users[usr][1] > 5):
                users[usr] = (ip,time.time())
                _thread.start_new_thread( send_response, (host_name, host_ip, users[usr][0], ))

def tcp_listener( host_name, host_ip, lock ):
    import socket
    import time
    import random
    global users

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host_ip,12345))
        s.listen(10)
        while True:
            conn, addr = s.accept()
            with conn:
                while True:
                    data = conn.recv(1024).decode('ascii').strip()[1:-1].split(',')
                    if not data:
                        break
                    print(data)
                    if len(data) < 3:
                        print("unsupported message type")
                    elif data[2].strip() == 'newKey':
                        g = int(data[3].strip())
                        p = int(data[4].strip())
                        A = int(data[5].strip())
                        b = random.randint(1,p-1)
                        B = pow(g,b) % p
                        encryption_keys[data[1].strip()] = pow(A,b) % P
                        pubkey_message = '[' + host_name + ',' + host_ip + ',pubkey,' + str(B) + ']'
                        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                            s.connect((target_ip,12345))
                            s.sendall(str.encode(response_message))
                    elif data[2].strip() == 'pubkey':
                        a = encryption_keys[data[1].strip()]
                        B = int(data[3].strip())
                        encryption_keys[data[1].strip()] = pow(B,a) % P
                        lock.release()
                    elif data[2].strip() == 'response':
                        if (data[0].strip() not in users) or (data[0].strip() in users and time.time()-users[data[0].strip()][1] > 5):
                            users[data[0].strip()] = (data[1].strip(),time.time())
                    elif data[2].strip() == 'message':
                        print(data[0].strip() + ": " + data[3].strip())    

import _thread
import sys
import socket
import os
import time

os.system('clear')
username = input("Enter your username: ")

try:
    _thread.start_new_thread( announcement_listener, ( username, host_ip, ) )
    _thread.start_new_thread( tcp_listener, (username, host_ip, lock, ) )
except:
    print ("Error: unable to start thread")

announce_message = '[' + username + ',' + host_ip + ',announce]'
port = 12345
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST,1)
print("Broadcasting...")
for _ in range(3):
    sock.sendto(str.encode(announce_message),('<broadcast>',port))

sock.close()

while True:
    command = input("Enter command(exit, list, message): \n")
    if command == 'exit':
        break
    if command == 'list':
        print( list(users.keys()) )
    elif 'message' in command:
        cmd = command.split(" ")
        _thread.start_new_thread( send_message , ( username, users[cmd[1].strip()][0], "".join(cmd[2:]), lock, ) )

