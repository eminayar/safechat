users = {}
encryption_keys = {}
G = 10399
P = 11503
host_ip = "192.168.1.104"
from threading import Lock
lock = Lock()
tcp_lock = Lock()
## [emin,192.168.1.2,newKey,G,P,A]
## [esra,192.168.1.3,pubkey,B]


def send_response( host_name, host_ip, target_ip ):
    import socket
    response_message = '[' + host_name + ',' + host_ip + ',response]'
    print(response_message, target_ip)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((target_ip,12345))
        s.sendall(str.encode(response_message))

def send_message( host_name, target_ip, message, lock ):
    import socket
    import pyDes
    import random
    if target_ip not in encryption_keys:
        lock.acquire()
        a = random.randint(1,P-1)
        A = pow(G,a) % P
        key_message = '[' + host_name + ',' + host_ip + ',newKey,' + str(G) + ','+ str(P) + ','+ str(A) + ']'
        print(key_message)
        encryption_keys[target_ip] = a
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((target_ip,12345))
            s.sendall(str.encode(key_message))
    with lock:
        wowkey = str(encryption_keys[target_ip])
        response_message = '[' + host_name + ',' + host_ip + ',message,' + message + ']'
        encrypted_message = pyDes.triple_des(wowkey.ljust(24)).encrypt(message, padmode=2)
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

def tcp_listener( host_name, host_ip, lock, tcp_lock ):
    import socket
    import time
    import random
    import pyDes
    global users

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('',12345))
        s.listen(5)
        tcp_lock.release()
        print("accepting connections")
        while True:
            conn, addr = s.accept()
            with conn:
                while True:
                    raw_data = conn.recv(1024)
                    if not raw_data:
                        break
                    comma = 0
                    header = ""
                    data = ""
                    for i in range(1,len(raw_data)):
                        if raw_data[i:i+1].decode('ascii') == ',':
                            comma += 1
                        if comma == 3:
                            header = raw_data[1:i].decode('ascii').strip().split(',')
                            data = raw_data[i+1:-1]
                            break
                    if not header:
                        header = raw_data[1:-1].decode('ascii').split(',')
                    if len(header) < 3:
                        print("unsupported message type")
                    elif header[2].strip() == 'newKey':
                        data = data.decode('ascii').strip().split(',')
                        g = int(data[0].strip())
                        p = int(data[1].strip())
                        A = int(data[2].strip())
                        b = random.randint(1,p-1)
                        B = pow(g,b) % p
                        encryption_keys[header[1].strip()] = pow(A,b) % P
                        pubkey_message = '[' + host_name + ',' + host_ip + ',pubkey,' + str(B) + ']'
                        print(pubkey_message)
                        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                            s.connect((header[1].strip(),12345))
                            s.sendall(str.encode(pubkey_message))
                    elif header[2].strip() == 'pubkey':
                        data = data.decode('ascii').strip()
                        a = encryption_keys[header[1].strip()]
                        B = int(data)
                        encryption_keys[header[1].strip()] = pow(B,a) % P
                        lock.release()
                    elif header[2].strip() == 'response':
                        if (header[0].strip() not in users) or (header[0].strip() in users and time.time()-users[header[0].strip()][1] > 5):
                            users[header[0].strip()] = (header[1].strip(),time.time())
                    elif header[2].strip() == 'message':
                        wowkey = str(encryption_keys[header[1].strip()])
                        decrypted = pyDes.triple_des(wowkey.ljust(24)).decrypt(data, padmode=2)
                        print(header[0].strip() + ": " + data)
                        print(header[0].strip() + ": " + decrypted)

import _thread
import sys
import socket
import os
import time

os.system('clear')
username = input("Enter your username: ")

try:
    _thread.start_new_thread( announcement_listener, ( username, host_ip, ) )
    tcp_lock.acquire()
    _thread.start_new_thread( tcp_listener, (username, host_ip, lock, tcp_lock,  ) )
except:
    print ("Error: unable to start thread")

announce_message = '[' + username + ',' + host_ip + ',announce]'
print(announce_message)
port = 12345
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST,1)
tcp_lock.acquire()
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

