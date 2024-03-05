# first of all import the socket library 
import socket 
import importlib
_1905069_ecdh = importlib.import_module("1905069_ecdh")
_1905069_aes = importlib.import_module("1905069_aes")
import random   
import time       


def exchangeKeyServer(c,AES_LEN):
    start_time = time.time()
    p = _1905069_ecdh.getPrime(AES_LEN).int_val()
    P = _1905069_ecdh.getPoint(AES_LEN)
    E = _1905069_ecdh.getElipticCurve(AES_LEN,p,P)

    a = random.randint(2,p-2)
    A = E.mul(P,a)
    A_time = time.time()-start_time;
    start_time = time.time()
    msg = str(E.p) + "," + str(E.a) + "," + str(E.b) + "," + str(A.x) + "," + str(A.y) + "," + str(P.x) + "," + str(P.y)
    c.send(msg.encode())
    msg = c.recv(1024).decode()

    [Bx,By] = msg.split(",")
    Bx = int(Bx)
    By = int(By)
    B = _1905069_ecdh.Point(Bx,By)
    R = E.mul(B,a)
    key = _1905069_ecdh.intToString(R.x,AES_LEN)
    # iv  = _1905069_ecdh.intToString(R.y,AES_LEN)
    key_time = time.time()-start_time
    # print("A  : ", A)
    # print("B  : ", B)
    # print("key: ", key)
    # print("iv : ", iv)
    return key,A_time,key_time
 
# next create a socket object 
s = socket.socket()         
print ("Socket successfully created")
 
# reserve a port on your computer in our 
# case it is 12345 but it can be anything 
port = 12345 
AES_LEN = 256

# Next bind to the port 
# we have not typed any ip in the ip field 
# instead we have inputted an empty string 
# this makes the server listen to requests 
# coming from other computers on the network 
s.bind(('', port))         
print ("socket binded to %s" %(port)) 
 
# put the socket into listening mode 
s.listen(5)     
print ("socket is listening")            
 
# a forever loop until we interrupt it or 
# an error occurs 
while True:
    # Establish connection with client. 
    c, addr = s.accept() 
    
    key,A_time,key_time = exchangeKeyServer(c,AES_LEN)
    print("A_time: ", A_time)
    print("key_time: ", key_time)

    filePath = 'E:\\Academics\\4-1\\406_security_sessional\\offline_1\\1905069\\from\\hello_from.txt'

    # text = "Agge Kdde Aa Bhulekhe Kayi Wari Kayi Wari Canada")

    cipherText = _1905069_aes.sendFile(c,AES_LEN,_1905069_aes.getInitializationVector(AES_LEN),key,filePath)

    cipherText,decipherText = _1905069_aes.receiveEncrypted(c,AES_LEN,key)

    # print("Key:")
    # print("In ASCII: ",key)
    # print("In HEX: ",''.join(_1905069_aes.asciiStringToHexVector(key)))
    # print("")

    # print("Plain Text:")
    # print("In ASCII: ",text)
    # print("In HEX: ",''.join(_1905069_aes.asciiStringToHexVector(text)))
    # print("")
    
    # print("Initialization Vector:")
    # print("In ASCII: ",iv)
    # print("In HEX: ",''.join(_1905069_aes.asciiStringToHexVector(iv)))
    # print("")

    
    # print("Cipher Text:")
    # print("In ASCII: ",cipherText)
    # print("In HEX: ",''.join(_1905069_aes.asciiStringToHexVector(cipherText)))
    # print("")

    # print("Ciphered Text:")
    # print("In HEX: ",''.join(hexStringVector))
    # print("In ASCII: ",_1905069_aes.hexToASCII(''.join(hexStringVector)))
    # print("")

    # [encrypted_hex,encrypted_text,time] = aes.ENCRYPT_AES(AES_LEN,text,key_bin)
    # print("encrypted_hex = ",encrypted_hex)
    # c.send(encrypted_text.encode())

    # Close the connection with the client 
    c.close()

    # Breaking once connection closed
    break