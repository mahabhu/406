# Import socket module 
import socket 
import importlib
_1905069_ecdh = importlib.import_module("1905069_ecdh")
_1905069_aes = importlib.import_module("1905069_aes")
import random 
import time      

def exchangeKeyClient(s,AES_LEN):
    start_time = time.time()
    msg = s.recv(1024).decode()
    [p,Ea,Eb,Ax,Ay,Px,Py] = msg.split(",")

    p = int(p)
    Ea = int(Ea)
    Eb = int(Eb)
    Ax = int(Ax)
    Ay = int(Ay)
    Px = int(Px)
    Py = int(Py)
    E = _1905069_ecdh.EllipticCurve(p,Ea,Eb)
    A = _1905069_ecdh.Point(Ax,Ay)
    P = _1905069_ecdh.Point(Px,Py)

    b = random.randint(2,p-2)
    B = E.mul(P,b)
    B_time = time.time()-start_time;
    start_time = time.time()
    msg = str(B.x) + "," + str(B.y)
    s.send(msg.encode())
    R = E.mul(A,b)
    key = _1905069_ecdh.intToString(R.x,AES_LEN)
    # iv  = _1905069_ecdh.intToString(R.y,AES_LEN)
    key_time = time.time()-start_time
    # print("A  : ", A)
    # print("B  : ", B)
    # print("key: ", key)
    # print("iv : ", iv)
    return key,B_time,key_time
 
# Create a socket object 
s = socket.socket()         
 
# Define the port on which you want to connect 
port = 12345     
AES_LEN = 256   
 
# connect to the server on local computer 
s.connect(('127.0.0.1', port)) 
 
# receive data from the server and decoding to get the string.
key,B_time,key_time = exchangeKeyClient(s,AES_LEN)
print("B_time: ", B_time)
print("key_time: ", key_time)
filePath = "E:\\Academics\\4-1\\406_security_sessional\\offline_1\\1905069\\to\\sorry.txt"
cipherText,decipherText,result = _1905069_aes.receiveFile(s,AES_LEN,key,filePath)
text = "Mashroor Hasan Bhuiyan"
cipherText = _1905069_aes.sendEncrypted(s,AES_LEN,text,_1905069_aes.getInitializationVector(AES_LEN),key)

# print("Key:")
# print("In ASCII: ",key)
# print("In HEX: ",''.join(_1905069_aes.asciiStringToHexVector(key)))
# print("")

# print("Initialization Vector:")
# print("In ASCII: ",iv)
# print("In HEX: ",''.join(_1905069_aes.asciiStringToHexVector(iv)))
# print("")

# print("Cipher Text:")
# print("In ASCII: ",cipherText)
# print("In HEX: ",''.join(_1905069_aes.asciiStringToHexVector(cipherText)))
# print("")

# print("Decipher Text:")
# print("In ASCII: ",decipherText)
# print("In HEX: ",''.join(_1905069_aes.asciiStringToHexVector(decipherText)))
# print("")

# print("Ciphered Text:")
# print("In HEX: ",''.join(hexStringVector))
# print("In ASCII: ",_1905069_aes.hexToASCII(''.join(hexStringVector)))
# print("")

# print("Deciphered Text:")
# print("In HEX: ",''.join(_1905069_aes.hexVectorToHexString(decipherHexVector)))
# print("In ASCII: ",''.join(_1905069_aes.hexVectorToAsciiVector(decipherHexVector)))
# print("")


# b = dh.get_ab(AES_LEN)
# B = dh.get_AB(p,g,b)

# close the connection 
s.close() 